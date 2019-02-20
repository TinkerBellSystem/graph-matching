# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function
from pycparser import c_parser, c_ast, parse_file
from motif.rtm import create_motif_node, create_alternation_node, create_group_node
from motif.provtype import provenance_vertex_type


def list_functions(ast, dictionary):
	"""List all functions within an AST.

	Arguments:
	ast 	   -- AST from a parsed file
	dictionary -- dict to save the functions

	"""
	for ext in ast.ext:
		if type(ext).__name__ == 'FuncDef':
			# A FuncDef consists of a declaration, a list of parameter
			# declarations (for K&R style function definitions), and a body.
			# function_decl, like any other declaration, is a Decl.
			# Its type child is a FuncDecl, which has a return type and arguments stored in a ParamList node
			function_decl = ext.decl
			function_body = ext.body
			# From declaration, we can also get the function name.
			function_name = function_decl.name
			# From declaration, we extract parameters.
			param_names = list()
			if type(function_decl.type.args).__name__ == 'NoneType':
				# Function declaration does not have parameters, do nothing
				pass
			elif type(function_decl.type.args).__name__ == 'ParamList':
				function_params = function_decl.type.args.params
				for param in function_params:
					param_names.append(param.name)
			else:
				#######################################################
				# We will consider other conditions if we ever see them
				#######################################################
				print('\x1b[6;30;41m[x]\x1b[0m [list_functions]: The type {} is not implemented'.format(type(function_decl.type.args).__name__))
				raise NotImplementedError('type not implemented properly')

			dictionary[function_name] = (param_names, function_body)


def eval_function_call(function_call, function_dict, motif_node_dict):
	"""Evaluate a function call.

	Bottom level function calls:
	1. alloc_provenance()

	:param function_call: This is the function call to be evaluated.
	:param function_dict: This is the dictionary that stores all seen function calls.
	:param motif_node_dict: This is the motif node map.
	:return: Either skip the function call or call eval_function_body to evaluate its body.
	"""
	if function_call.name.name in function_dict:
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating function: {}'.format(function_call.name.name))
		return eval_function_body(function_dict[function_call.name.name][1], function_dict, motif_node_dict)
	elif function_call.name.name == "alloc_provenance":


	else:
		print('\x1b[6;30;43m[!]\x1b[0m [eval_function_call] Skipping function: {}'.format(function_call.name.name))
		return None, None


def eval_function_body(function_body, function_dict, motif_node_dict):
	"""Evaluate a Compound function body.

	Arguments:
	function_body 	-- function body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map

	Returns:
	a motif_node and an RTMTree, both of which can be None
	"""
	# The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
	# The following goes through the declarations and statements in the function body
	motif_node = None
	tree = None

	for item in function_body.block_items:
		if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
			motif_node, tree_node = eval_function_call(item, function_dict, motif_node_dict)
			if tree_node != None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
			tree_node = eval_assignment(item, function_dict, motif_node_dict)
			if tree_node != None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
			tree_node = eval_declaration(item, function_dict, motif_node_dict)
			if tree_node != None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'If':   # Case 4: if/else
			tree_node = eval_if_else(item, function_dict, motif_node_dict)
			if tree_node != None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Return':   # Case 5: return with function call
			motif_node, tree_node = eval_return(item, function_dict, motif_node_dict)
			if tree_node != None:
				tree = create_group_node(tree, tree_node)
		else:
			print('\x1b[6;30;41m[x]\x1b[0m [eval_function_body] The type {} is not implemented'.format(type(item).__name__))
			raise NotImplementedError('type not implemented properly')
	
	return motif_node, tree


def eval_assignment(assignment, function_dict, motif_node_dict):
	"""Evaluate a single assignment that creates new TreeNodes.

	Arguments:
	assignment 		-- assignment body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map

	Returns:
	an RTMTree, which can be None
	"""
	if type(assignment.rvalue).__name__ == 'FuncCall':
		motif_node, tree_node = eval_function_call(assignment.rvalue, function_dict, motif_node_dict)
		# consider "var = XXX;" and "*var = XXX" and "&var = XXX" situations
		if (type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in motif_node_dict) or \
			(type(assignment.lvalue).__name__ == 'UnaryOp' and assignment.lvalue.expr.name in motif_node_dict):
			if motif_node is None:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_assignment] Motif node {} is in the dictionary, so motif_node should not be None.'.format(assignment.lvalue.name))
				raise RuntimeError('motif node should not return None type')
			else:
				motif_node_dict[assignment.lvalue.name].append(motif_node)
		return tree_node
	# In a case where a provenance node was declared but then assigned or reassigned. For example:
	#   struct provenance *tprov;
	#   ...
	#   tprov = t->provenance;
	# tprov must then be in the motif_node_dict.
	elif type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in motif_node_dict:
		# we can only infer its type from the name of the variable
		motif_node = create_motif_node(provenance_vertex_type(assignment.lvalue.name))
		motif_node_dict[assignment.lvalue.name].append(motif_node)
		return None
	# similar case as the previous one, except that we have: *tprov = ...
	# we can only infer its type from the name of the variable
	elif type(assignment.lvalue).__name__ == 'UnaryOp' and type(assignment.lvalue.expr).__name__ == 'ID' and assignment.lvalue.expr.name in motif_node_dict:
		motif_node = create_motif_node(provenance_vertex_type(assignment.lvalue.expr.name))
		motif_node_dict[assignment.lvalue.expr.name].append(motif_node)
		return None
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		#######################################################
		print('\x1b[6;30;41m[x]\x1b[0m [eval_assignment]: an unforseen case not considered')
		raise NotImplementedError('a case not implemented')


def eval_declaration(declaration, function_dict, motif_node_dict):
	"""Evaluate a single declaration that generates new TreeNodes.

	Arguments:
	declaration 	-- declaration body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map

	Returns:
	an RTMTree, which can be None
	"""
	# We are only concerned with declaration type "struct provenance" or "struct provenance *"
	if (type(declaration.type).__name__ == 'PtrDecl' and type(declaration.type.type).__name__ == 'TypeDecl' and type(declaration.type.type.type).__name__ == 'Struct' and declaration.type.type.type.name == 'provenance') or \
		(type(declaration.type).__name__ == 'TypeDecl' and type(declaration.type.type).__name__ == 'Struct' and declaration.type.type.name == 'provenance'):
		# if it is immediately assigned by a function call
		if type(declaration.init).__name__ == 'FuncCall':
			motif_node, tree_node = eval_function_call(declaration.init, function_dict, motif_node_dict)
			if motif_node is None:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} must be associated with a MotifNode.'.format(declaration.name))
				raise RuntimeError('motif node should not return None type')
			else:
				# it should be the first time we see the name in the dictionary
				if declaration.name in motif_node_dict:
					print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} should not already be in the dictionary.'.format(declaration.name))
					raise RuntimeError('motif node should not have existed already')
				else:
					motif_node_dict[declaration.name] = [motif_node]
			return tree_node
		# if it is set to NULL first
		elif type(declaration.init).__name__ == 'ID':
			if declaration.init.name == 'NULL':
				# it should be the first time we see the name in the dictionary
				if declaration.name in motif_node_dict:
					print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is set to NULL and should not already be in the dictionary.'.format(declaration.name))
					raise RuntimeError('motif node is set to NULL and should not have existed already')
				else:
					motif_node_dict[declaration.name] = []
			else:
				#######################################################
				# We will consider other conditions if we ever see them
				#######################################################
				print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is set to an unknown condition that is not considered yet.'.format(declaration.name))
				raise RuntimeError('motif node is set to NULL and should not have existed already')
			return None
		# if it is not set at all, then it must be set later
		elif type(declaration.init).__name__ == 'NoneType':
			if declaration.name in motif_node_dict:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is not set and should not already be in the dictionary.'.format(declaration.name))
				raise RuntimeError('motif node is not set and should not have existed already')
			else:
				############################################
				# We would encounter an exception here!
				# TODO: Refactoring CamFlow Code is required 
				############################################
				#################################################################
				# The following hack should not exist in TinkerBell Motif Engine.
				#################################################################
				# if declaration.name == 'pckprov':
					# motif_node_dict[declaration.name] = [create_motif_node(provenance_vertex_type(declaration.name))]
				# else:
				#################################################################
				motif_node_dict[declaration.name] = []
			return None
		# it must be set through other methods, so we can only infer the type from its name
		else:
			if declaration.name in motif_node_dict:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration]: {} is not set in an unknown way but should not already be in the dictionary.'.format(declaration.name))
				raise RuntimeError('motif node is not set in an unknown way but should not have existed already')
			else:
				motif_node_dict[declaration.name] = [create_motif_node(provenance_vertex_type(declaration.name))]
			return None     
	else:
		return None


def eval_if_condition(condition):
	"""Evaluate `if` condition.
	Returns True if the `if` condition requires alternation consideration.
	Otherwise, return False.

	Arguments:
	condition -- if/elif condition to be evaluated

	Return:
	boolean value
	"""
	if type(condition).__name__ == 'BinaryOp':
		if type(condition.left).__name__ == 'ID':
			# case: if (mask & XXX) {...} in "provenance_inode_permission"; mask can only be determined at runtime
			if condition.left.name == 'mask':
				return True
			# case: if (shmflg & SHM_RDONLY) {...} in "provenance_shm_shmat"; shmflg can be only be determined at runtime
			if condition.left.name == 'shmflg':
				return True
		elif type(condition.left).__name__ == 'BinaryOp':
			if type(condition.left.left).__name__ == 'ID':
				# case: if ((perms & (DIR__WRITE)) != 0) in "provenance_file_permission"; perms can only be determined at runtime
				if condition.left.left.name == 'perms':
					return True
				# case: if ((prot & (PROT_WRITE)) != 0) in "provenance_mmap_file"; prot can only be determined at runtime
				elif condition.left.left.name == 'prot':
					return True
			elif type(condition.left.left).__name__ == 'BinaryOp':
				if type(condition.left.left.left).__name__ == 'ID':
					# case: if ((flags & MAP_TYPE) == MAP_SHARED...) in "provenance_mmap_file"; flags can only be determined at runtime
					if condition.left.left.left.name == 'flags':
						return True
			elif type(condition.left.right).__name__ == 'ID':
				# case: if (sock->sk->sk_family == PF_UNIX &&...) in "provenance_socket_recvmsg", "provenance_socket_recvmsg_always", "provenance_socket_sendmsg", "provenance_socket_sendmsg_always"; sock->sk->sk_family can only be determined at runtime
				if condition.left.right.name == 'PF_UNIX':
					return True
	elif type(condition).__name__ == 'FuncCall':
		# case: if (is_inode_dir(inode)) in "provenance_file_permission"; inode type can only be determined at runtime
		if condition.name.name == 'is_inode_dir':
			return True
		# case: else if (is_inode_socket(inode)) in "provenance_file_permission"
		elif condition.name.name == 'is_inode_socket':
			return True
		# case: if ( vm_mayshare(flags) ) in "provenance_mmap_munmap"; flags can only be determined at runtime
		elif condition.name.name == 'vm_mayshare':
			return True
	elif type(condition).__name__ == 'ID':
		# case: if (iprovb) in "provenance_socket_sendmsg", "provenance_socket_sendmsg_always"
		if condition.name == 'iprovb':
			return True
		# case: if (pprov) in "provenance_socket_recvmsg", "provenance_socket_recvmsg_always"
		elif condition.name == 'pprov':
			return True
	#######################################################
	# We will consider other conditions if we ever see them
	#######################################################
	else:
		return False


def eval_if_else(item, function_dict, motif_node_dict):
	"""Evaluate (nesting) if/else blocks.
	Only if/else blocks that contain statements that create MotifNodes/TreeNodes are of interest here.
	Within those blocks, only specific if/else condition checks are of interest here.
	Most if/else are for error handling only. 

	Arguments:
	item 			-- if/else block to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map

	Returns:
	an RTMTree, which can be None
	"""
	# evaluate the `if` branch first
	true_branch = item.iftrue
	if type(true_branch).__name__ == 'FuncCall':
		motif_node, left = eval_function_call(true_branch, function_dict, motif_node_dict)             
	elif type(true_branch).__name__ == 'Assignment':
		left = eval_assignment(true_branch, function_dict, motif_node_dict)
	elif type(true_branch).__name__ == 'Decl':
		left = eval_declaration(true_branch, function_dict, motif_node_dict)
	elif type(true_branch).__name__ == 'Return':
		left = eval_return(true_branch, function_dict, motif_node_dict)
	elif type(true_branch).__name__ == 'Compound':
		left = eval_function_body(true_branch, function_dict, motif_node_dict)
	else:
		left = None
	# evaluate the `else` branch if it exists
	false_branch = item.iffalse
	if type(false_branch).__name__ == 'FuncCall':
		motif_node, right = eval_function_call(false_branch, function_dict, motif_node_dict)
	elif type(false_branch).__name__ == 'Assignment':
		right = eval_assignment(false_branch, function_dict, motif_node_dict)
	elif type(false_branch).__name__ == 'Decl':
		right = eval_declaration(false_branch, function_dict, motif_node_dict)
	elif type(false_branch).__name__ == 'Return':
		right = eval_return(false_branch, function_dict, motif_node_dict)
	elif type(false_branch).__name__ == 'Compound':
		right = eval_function_body(false_branch, function_dict, motif_node_dict)
	elif type(false_branch).__name__ == 'If':   # else if case
		right = eval_if_else(false_branch, function_dict, motif_node_dict)
	else:
		right = None

	if left or right:
		# only under certain circumstances do we actually create alternation node
		if eval_if_condition(item.cond):
			return create_alternation_node(left, right)
		else:
			print('\x1b[6;30;41m[x]\x1b[0m [eval_if_else]: Condition [{}] is not considered'.format(item.cond))
			raise RuntimeError('an unexpected if/elif condition')
			# if only one branch is not None, we need not create a group node
			##################################################################
			# What are the cases where we ignore if/else alternation, and why?
			##################################################################
			# if left is None:
			# 	return right
			# if right is None:
			# 	return left
			# return create_group_node(left, right)
			##################################################################
	else:
		return None


def eval_return(statement, function_dict, motif_node_dict):
	"""Evaluate a single return statement that directly generates new TreeNodes/MotifNode.

	Arguments:
	statement 		-- return statementto be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map

	Returns:
	a motif_node and an RTMTree, either of which can be None
	"""
	if type(statement.expr).__name__ == 'FuncCall':
		return eval_function_call(statement.expr, function_dict, motif_node_dict)
	elif type(statement.expr).__name__ == 'ID':
		if statement.expr.name in motif_node_dict:
			return motif_node_dict[statement.expr.name], None
		else:
			return None, None
	else:
		return None, None
