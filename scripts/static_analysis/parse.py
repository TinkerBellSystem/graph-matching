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
from motif.rtm import MotifNode, MotifEdge, create_motif_node, create_alternation_node, create_group_node, create_leaf_node, create_asterisk_node, create_question_mark_node
from motif.provtype import provenance_relation, provenance_vertex_type, match_relation

r_map = provenance_relation('camflow/type.c')


def ast_snippet(ast_snippet):
	"""AST snippet from pycparser without formatting. Used for printing.

	:param ast_snippet: the ast snippet
	:return: ast snippet without formatting (i.e., whitespace)
	"""
	return repr(ast_snippet).replace('\n', ' ').replace(' ', '')


def extract_function_argument_names(function_call):
	"""Extract argument name in subroutine function calls in lower-level functions.
	We so far consider three cases if arguments exist:
	For example,
	function_call(arg1, &arg2, func(arg3));
	case 1: arg1 -> arg1
	case 2: &arg2 -> arg2
	case 3: func(arg3) -> arg3
	"""
	arg_names = []
	# Function call does not use any arguments
	if type(function_call.args).__name__ == 'NoneType':
		return arg_names
	elif type(function_call.args).__name__ == 'ExprList':
		for arg in function_call.args.exprs:
			if type(arg).__name__ == 'ID':
				arg_names.append(arg.name)
			elif type(arg).__name__ == 'UnaryOp':
				arg_names.append(arg.expr.name)
			elif type(arg).__name__ == 'FuncCall':
				arg_names.append(arg.args.exprs[0].name)  # assuming only first argument in FuncCall for simplicity
			elif type(arg).__name__ == 'Constant':
				arg_names.append(arg.value)
			elif type(arg).__name__ == 'StructRef':
				arg_names.append(arg.name.name)
			else:
				print('\33[101m' + '\x1b[6;30;41m[x]\x1b[0m [extract_function_argument_names]  ' + type(
					arg).__name__ + ' is not yet considered.')
				raise NotImplementedError('type not implemented properly')
		return arg_names
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		#######################################################
		print('\33[101m' + '\x1b[6;30;41m[x]\x1b[0m [extract_function_argument_names]  ' + type(
			function_call.args).__name__ + ' is not yet considered.')
		raise NotImplementedError('type not implemented properly')


def create_name_dict(caller_arguments, callee_parameters, parent_name_dict):
	"""
	Add a list of callee's parameter names as keys that need to be mapped to caller's argument names, which are values.
	Each caller argument corresponds to the callee parameter of the same position in the list.
	:param caller_arguments: a list of arguments caller uses when calling callee function
	:param callee_parameters: a list of parameters in callee function definition
	:param parent_name_dict: dictionary it inherits from
	:return: the name dict
	"""
	if len(caller_arguments) != len(callee_parameters):
		print('\33[101m' + '\x1b[6;30;41m[x]\x1b[0m [add_name_to_dict] Invalid caller and callee lists.')
		raise RuntimeError('caller argument list should have the same length as callee parameter list')
	name_dict = dict()
	print('\x1b[6;30;42m[+]\x1b[0m [create_name_dict] Creating name dictionary: ', end='')
	for i in range(len(callee_parameters)):
		true_caller_argument = get_true_name(caller_arguments[i], parent_name_dict)
		name_dict[callee_parameters[i]] = true_caller_argument
		print('{}->{} '.format(callee_parameters[i], true_caller_argument), end='')
	print('\n', end='')
	return name_dict


def get_true_name(name, name_dict):
	"""
	Return true name based on name_dict.
	:param name: the name whose true name we are looking for
	:param name_dict: dict to have the key and value names to return true name
	:return: its true name
	"""
	while name_dict.get(name, None) is not None:
		name = name_dict.get(name, None)
	return name


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
				print('\x1b[6;30;41m[x]\x1b[0m [list_functions] The type {} is not implemented'.format(
					type(function_decl.type.args).__name__))
				raise NotImplementedError('type not implemented properly')

			dictionary[function_name] = (param_names, function_body)


def eval_function_call(caller_function_name, function_call, function_dict, motif_node_dict, name_dict):
	"""Evaluate a function call.

	Bottom level function calls:
	1. alloc_provenance()

	:param caller_function_name: This is the name of the caller function that calls this function call
	:param function_call: This is the function call to be evaluated.
	:param function_dict: This is the dictionary that stores all seen function calls.
	:param motif_node_dict: This is the motif node map.
	:param name_dict: This is the name map of the calling function.
	:return: Either skip the function call, return a motif_node and an RTMTree, both of which can be None, or call eval_function_body to evaluate its body.
	"""
	if function_call.name.name == "alloc_provenance":
		args = extract_function_argument_names(function_call)
		node_type = args[0]
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating alloc_provenance()')
		return create_motif_node(provenance_vertex_type(node_type)), None
	elif function_call.name.name == 'alloc_long_provenance':
		args = extract_function_argument_names(function_call)
		node_type = args[0]
		# TODO: Fix record_node_name() function in provenance_record.h or try to recognize long_prov_elt in TinkerBell
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating alloc_long_provenance()')
		return create_motif_node(provenance_vertex_type(node_type)), None
	elif function_call.name.name == '__write_relation':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating __write_relation()')
		args = extract_function_argument_names(function_call)
		relation_type = match_relation(r_map, get_true_name(caller_function_name + '.' + args[0], name_dict).split('.')[1])
		src_node = motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)][-1]
		dst_node = motif_node_dict[get_true_name(caller_function_name + '.' + args[2], name_dict)][-1]
		edge = MotifEdge(src_node, dst_node, relation_type)
		return None, create_leaf_node(edge)
	elif function_call.name.name == '__update_version':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating __update_version()')
		args = extract_function_argument_names(function_call)
		original_node = motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)][-1]
		if original_node.mn_has_outgoing is False:
			return original_node, None
		if args[0] == 'RL_VERSION_TASK' or args[0] == 'RL_VERSION' or args[0] == 'RL_NAMED' or args[0] == 'RL_NAMED_PROCESS':
			return original_node, None
		else:
			new_motif_node = MotifNode(original_node.mn_ty)
			new_motif_node.mn_has_name_recorded = original_node.mn_has_name_recorded
			new_motif_node.mn_kernel_version = original_node.mn_kernel_version
			new_motif_node.mn_is_initialized = original_node.mn_is_initialized
			if original_node.mn_ty == 'task':
				edge = MotifEdge(original_node, new_motif_node, match_relation(r_map, 'RL_VERSION_TASK'))
			else:
				edge = MotifEdge(original_node, new_motif_node, match_relation(r_map, 'RL_VERSION'))
			motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)].append(new_motif_node)
			return new_motif_node, create_leaf_node(edge)
	elif function_call.name.name == 'set_has_outgoing':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating set_has_outgoing()')
		args = extract_function_argument_names(function_call)
		node = motif_node_dict[get_true_name(caller_function_name + '.' + args[0], name_dict)][-1]
		node.mn_has_outgoing = True
		return None, None
	elif function_call.name.name == 'set_kernel_recorded':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating set_kernel_recorded()')
		args = extract_function_argument_names(function_call)
		node = motif_node_dict[get_true_name(caller_function_name + '.' + args[0], name_dict)][-1]
		# TODO: 'record_kernel_link.prov_machine' hard-coded
		kernel_node = motif_node_dict['record_kernel_link.prov_machine'][-1]
		node.mn_kernel_version = kernel_node.mn_kernel_version
		return None, None
	elif function_call.name.name == 'record_terminate':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating record_terminate()')
		args = extract_function_argument_names(function_call)
		node = motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)][-1]
		new_motif_node = MotifNode(node.mn_ty)
		new_motif_node.mn_has_name_recorded = node.mn_has_name_recorded
		new_motif_node.mn_kernel_version = node.mn_kernel_version
		new_motif_node.mn_is_initialized = node.mn_is_initialized
		motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)].append(new_motif_node)
		motif_edge = MotifEdge(node, new_motif_node, match_relation(r_map, args[0]))
		return None, create_leaf_node(motif_edge)
	elif function_call.name.name == 'set_initialized':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating set_initialized()')
		args = extract_function_argument_names(function_call)
		node = motif_node_dict[get_true_name(caller_function_name + '.' + args[0], name_dict)][-1]
		node.mn_is_initialized = True
		return None, None
	elif function_call.name.name == 'node_identifier':
		# assuming we are always updating the version of the node
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating node_identifier() but do nothing')
		return None, None
	elif function_call.name.name == 'update_inode_type':
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating update_inode_type()')
		args = extract_function_argument_names(function_call)
		node = motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)][-1]

		new_motif_node = MotifNode(node.mn_ty)
		new_motif_node.mn_has_name_recorded = node.mn_has_name_recorded
		new_motif_node.mn_kernel_version = node.mn_kernel_version
		new_motif_node.mn_is_initialized = node.mn_is_initialized

		motif_edge = MotifEdge(node, new_motif_node, match_relation(r_map, 'RL_VERSION'))
		motif_node_dict[get_true_name(caller_function_name + '.' + args[1], name_dict)].append(new_motif_node)
		return new_motif_node, create_question_mark_node(create_leaf_node(motif_edge))
	elif function_call.name.name in function_dict:
		callee_function = function_dict[function_call.name.name]
		args = extract_function_argument_names(function_call)
		caller_args = [caller_function_name + '.' + arg for arg in args]
		params = callee_function[0]
		callee_params = [function_call.name.name + '.' + param for param in params]
		name_dict = create_name_dict(caller_args, callee_params, name_dict)
		print('\x1b[6;30;42m[+]\x1b[0m [eval_function_call] Evaluating function: {}'.format(function_call.name.name))
		return eval_function_body(function_call.name.name, callee_function[1], function_dict, motif_node_dict, name_dict)
	else:
		print('\x1b[6;30;43m[!]\x1b[0m [eval_function_call] Skipping function: {}'.format(function_call.name.name))
		return None, None


def eval_function_body(function_name, function_body, function_dict, motif_node_dict, name_dict):
	"""Evaluate a Compound function body.

	Arguments:
	function_name	-- the name of this function whose body we are inspecting
	function_body 	-- function body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Returns:
	a motif_node and an RTMTree, both of which can be None
	"""
	# The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
	# The following goes through the declarations and statements in the function body
	motif_node = None
	tree = None

	for item in function_body.block_items:
		if type(item).__name__ == 'FuncCall':  # Case 1: provenance-graph-related function call
			motif_node, tree_node = eval_function_call(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Assignment':  # Case 2: rc = provenance-graph-related function call
			tree_node = eval_assignment(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Decl':  # Case 3: declaration with initialization
			tree_node = eval_declaration(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'If':  # Case 4: if/else
			tree_node = eval_if_else(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'Return':  # Case 5: return with function call
			motif_node, tree_node = eval_return(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'While':  # Case 6: while block
			tree_node = eval_while(function_name, item, function_dict, motif_node_dict, name_dict)
			if tree_node is not None:
				tree = create_group_node(tree, tree_node)
		elif type(item).__name__ == 'UnaryOp':		# Case 7: node_identifier(prov_elt(prov)).version++;
			if type(item.expr).__name__ == 'StructRef':
				if type(item.expr.name).__name__ == 'FuncCall' and item.expr.field.name == 'version':
					motif_node, tree_node = eval_function_call(function_name, item.expr.name, function_dict, motif_node_dict, name_dict)
				else:
					print('\x1b[6;30;41m[x]\x1b[0m [eval_function_body] The type {} is not implemented, or the field name is not version'.format(
						type(item.expr.name).__name__))
					raise NotImplementedError('type not implemented properly or with the wrong field name')
			else:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_function_body] The type {} is not implemented'.format(
					type(item.expr).__name__))
				raise NotImplementedError('type not implemented properly')
		elif type(item).__name__ == 'Goto':	  # Case 8: goto
			print('\x1b[6;30;43m[!]\x1b[0m [eval_function_body] Skipping goto statement')
		elif type(item).__name__ == 'Label':  # Case 9: label associated with goto
			print('\x1b[6;30;43m[!]\x1b[0m [eval_function_body] Skipping goto label')
		else:
			print('\x1b[6;30;41m[x]\x1b[0m [eval_function_body] The type {} is not implemented'.format(
				type(item).__name__))
			raise NotImplementedError('type not implemented properly')

	return motif_node, tree


def eval_assignment(function_name, assignment, function_dict, motif_node_dict, name_dict):
	"""Evaluate a single assignment that creates new TreeNodes.

	Arguments:
	function_name 	-- the name of the function whose assignment statement we are inspecting
	assignment 		-- assignment body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Returns:
	an RTMTree, which can be None
	"""
	if type(assignment.rvalue).__name__ == 'FuncCall':
		motif_node, tree_node = eval_function_call(function_name, assignment.rvalue, function_dict, motif_node_dict, name_dict)
		# consider "var = XXX;"
		if type(assignment.lvalue).__name__ == 'ID' and get_true_name(function_name + '.' + assignment.lvalue.name, name_dict) in motif_node_dict:
			if motif_node is None:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_assignment] Motif node {} is in the dictionary, so motif_node should not be None.'.format(function_name + '.' + assignment.lvalue.name))
				raise RuntimeError('motif node should not return None type')
			else:
				motif_node_dict[get_true_name(function_name + '.' + assignment.lvalue.name, name_dict)].append(motif_node)
		# consider "*var = XXX" and "&var = XXX"
		elif type(assignment.lvalue).__name__ == 'UnaryOp' and get_true_name(function_name + '.' + assignment.lvalue.expr.name, name_dict) in motif_node_dict:
			if motif_node is None:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_assignment] Motif node {} is in the dictionary, so motif_node should not be None.'.format(function_name + '.' + assignment.lvalue.expr.name))
				raise RuntimeError('motif node should not return None type')
			else:
				motif_node_dict[get_true_name(function_name + '.' + assignment.lvalue.expr.name, name_dict)].append(motif_node)
		return tree_node
	# In a case where a provenance node was declared but then assigned or reassigned. For example:
	#   struct provenance *tprov;
	#   ...
	#   tprov = t->provenance;
	# tprov must then be in the motif_node_dict.
	elif type(assignment.lvalue).__name__ == 'ID':
		if get_true_name(function_name + '.' + assignment.lvalue.name, name_dict) in motif_node_dict:
			# we can only infer its type from the name of the variable
			motif_node = create_motif_node(provenance_vertex_type(assignment.lvalue.name))
			motif_node_dict[get_true_name(function_name + '.' + assignment.lvalue.name, name_dict)].append(motif_node)
		else:
			print('\x1b[6;30;43m[!]\x1b[0m [eval_assignment] Skipping assignment due to unrecognized lvalue: {}'.format(
				ast_snippet(assignment.lvalue)))
		return None
	# similar case as the previous one, except that we have: *tprov = ...
	# we can only infer its type from the name of the variable
	elif type(assignment.lvalue).__name__ == 'UnaryOp' and type(assignment.lvalue.expr).__name__ == 'ID':
		if get_true_name(function_name + '.' + assignment.lvalue.expr.name, name_dict) in motif_node_dict:
			motif_node = create_motif_node(provenance_vertex_type(assignment.lvalue.expr.name))
			motif_node_dict[get_true_name(function_name + '.' + assignment.lvalue.expr.name, name_dict)].append(motif_node)
		else:
			print('\x1b[6;30;43m[!]\x1b[0m [eval_assignment] Skipping assignment due to unrecognized lvalue: {}'.format(
				ast_snippet(assignment.lvalue)))
		return None
	elif type(assignment.lvalue).__name__ == 'StructRef':
		print('\x1b[6;30;43m[!]\x1b[0m [eval_assignment] Skipping assignment: {}'.format(ast_snippet(assignment)))
		return None
	elif type(assignment.lvalue).__name__ == 'FuncCall':
		print('\x1b[6;30;43m[!]\x1b[0m [eval_assignment] Skipping assignment: {}'.format(ast_snippet(assignment)))
		return None
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		#######################################################
		print('\x1b[6;30;41m[x]\x1b[0m [eval_assignment] An unforeseen case not considered: {}'.format(
			ast_snippet(assignment)))
		raise NotImplementedError('a case not implemented')


def eval_declaration(function_name, declaration, function_dict, motif_node_dict, name_dict):
	"""Evaluate a single declaration that generates new TreeNodes.

	Arguments:
	function_name 	-- the name of the function whose declaration statement we are inspecting
	declaration 	-- declaration body to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Returns:
	an RTMTree, which can be None
	"""
	# We are only concerned with declaration type "struct provenance" or "struct provenance *"
	if (type(declaration.type).__name__ == 'PtrDecl' and type(declaration.type.type).__name__ == 'TypeDecl' and type(
			declaration.type.type.type).__name__ == 'Struct' and declaration.type.type.type.name == 'provenance') or \
			(type(declaration.type).__name__ == 'TypeDecl' and type(
				declaration.type.type).__name__ == 'Struct' and declaration.type.type.name == 'provenance') or \
			(type(declaration.type).__name__ == 'PtrDecl' and type(
				declaration.type.type).__name__ == 'TypeDecl' and type(
				declaration.type.type.type).__name__ == 'Union' and declaration.type.type.type.name == 'long_prov_elt'):
		# if it is immediately assigned by a function call
		if type(declaration.init).__name__ == 'FuncCall':
			motif_node, tree_node = eval_function_call(function_name, declaration.init, function_dict, motif_node_dict, name_dict)
			if motif_node is None:
				print('\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} must be associated with a MotifNode.'.format(
					declaration.name))
				raise RuntimeError('motif node should not return None type')
			else:
				# it should be the first time we see the name in the dictionary
				if get_true_name(function_name + '.' + declaration.name, name_dict) in motif_node_dict:
					print(
						'\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} should not already be in the dictionary.'.format(
							declaration.name))
					raise RuntimeError('motif node should not have existed already')
				else:
					motif_node_dict[get_true_name(function_name + '.' + declaration.name, name_dict)] = [motif_node]
			return tree_node
		# if it is set to NULL first
		elif type(declaration.init).__name__ == 'ID':
			if declaration.init.name == 'NULL':
				# it should be the first time we see the name in the dictionary
				if get_true_name(function_name + '.' + declaration.name, name_dict) in motif_node_dict:
					print(
						'\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is set to NULL and should not already be in the dictionary.'.format(
							declaration.name))
					raise RuntimeError('motif node is set to NULL and should not have existed already')
				else:
					motif_node_dict[get_true_name(function_name + '.' + declaration.name, name_dict)] = []
			else:
				#######################################################
				# We will consider other conditions if we ever see them
				#######################################################
				print(
					'\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is set to an unknown condition that is not considered yet.'.format(
						declaration.name))
				raise RuntimeError('unknown declaration primitive')
			return None
		# if it is not set at all, then it must be set later
		elif type(declaration.init).__name__ == 'NoneType':
			if get_true_name(function_name + '.' + declaration.name, name_dict) in motif_node_dict:
				print(
					'\x1b[6;30;41m[x]\x1b[0m [eval_declaration] {} is not set and should not already be in the dictionary.'.format(
						declaration.name))
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
				motif_node_dict[get_true_name(function_name + '.' + declaration.name, name_dict)] = []
			return None
		# it must be set through other methods, so we can only infer the type from its name
		else:
			if get_true_name(function_name + '.' + declaration.name, name_dict) in motif_node_dict:
				print(
					'\x1b[6;30;41m[x]\x1b[0m [eval_declaration]: {} is not set in an unknown way but should not already be in the dictionary.'.format(
						declaration.name))
				raise RuntimeError('motif node is not set in an unknown way but should not have existed already')
			else:
				motif_node_dict[get_true_name(function_name + '.' + declaration.name, name_dict)] = [create_motif_node(provenance_vertex_type(declaration.name))]
				print('\x1b[6;30;43m[!]\x1b[0m [eval_declaration] Inferring motif node from its name {}'.format(declaration.name))
			return None
	else:
		print('\x1b[6;30;43m[!]\x1b[0m [eval_declaration] Skipping declaration: {}'.format(ast_snippet(declaration)))
		return None


def eval_if_condition(function_name, item, function_dict, motif_node_dict, name_dict):
	"""Evaluate `if` condition.
	Returns True if the `if` condition requires alternation consideration.
	Otherwise, return False.

	Arguments:
	function_name 	-- the name of the function whose if/else statement we are inspecting
	item 			-- if/else block to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Return:
	boolean value
	"""
	condition = item.cond
	if type(condition).__name__ == 'BinaryOp':
		if type(condition.left).__name__ == 'ID':
			# case: if (mask & XXX) {...} in "provenance_inode_permission"; mask can only be determined at runtime
			if condition.left.name == 'mask':
				return True
			# case: if (shmflg & SHM_RDONLY) {...} in "provenance_shm_shmat"; shmflg can be only be determined at runtime
			if condition.left.name == 'shmflg':
				return True
		elif type(condition.left).__name__ == 'FuncCall':
			# case: if (provenance_is_kernel_recorded(node) || !provenance_is_recorded(node)) in "provenance_rcord.h"
			# TODO: We can actually determine if kernel is recorded, but how do we parse it?
			if condition.left.name.name == 'provenance_is_kernel_recorded':
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


def eval_if_else(function_name, item, function_dict, motif_node_dict, name_dict):
	"""Evaluate (nesting) if/else blocks.
	Only if/else blocks that contain statements that create MotifNodes/TreeNodes are of interest here.
	Within those blocks, only specific if/else condition checks are of interest here.
	Most if/else are for error handling only. 

	Arguments:
	function_name 	-- the name of the function whose if/else statement we are inspecting
	item 			-- if/else block to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Returns:
	an RTMTree, which can be None
	"""
	# evaluate the `if` branch first
	true_branch = item.iftrue
	if type(true_branch).__name__ == 'FuncCall':
		motif_node, left = eval_function_call(function_name, true_branch, function_dict, motif_node_dict, name_dict)
	elif type(true_branch).__name__ == 'Assignment':
		left = eval_assignment(function_name, true_branch, function_dict, motif_node_dict, name_dict)
	elif type(true_branch).__name__ == 'Decl':
		left = eval_declaration(function_name, true_branch, function_dict, motif_node_dict, name_dict)
	elif type(true_branch).__name__ == 'Return':
		motif_node, left = eval_return(function_name, true_branch, function_dict, motif_node_dict, name_dict)
	elif type(true_branch).__name__ == 'Compound':
		motif_node, left = eval_function_body(function_name, true_branch, function_dict, motif_node_dict, name_dict)
	elif type(true_branch).__name__ == 'While':
		print('\x1b[6;30;41m[x]\x1b[0m [eval_if_else]: While is not implemented properly.')
		raise NotImplementedError("while not implemented properly")
	else:
		left = None
	# evaluate the `else` branch if it exists
	false_branch = item.iffalse
	if type(false_branch).__name__ == 'FuncCall':
		motif_node, right = eval_function_call(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'Assignment':
		right = eval_assignment(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'Decl':
		right = eval_declaration(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'Return':
		motif_node, right = eval_return(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'Compound':
		motif_node, right = eval_function_body(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'If':  # else if case
		right = eval_if_else(function_name, false_branch, function_dict, motif_node_dict, name_dict)
	elif type(false_branch).__name__ == 'While':
		print('\x1b[6;30;41m[x]\x1b[0m [eval_if_else]: While is not implemented properly.')
		raise NotImplementedError("while not implemented properly")
	else:
		right = None

	if left or right:
		# only under certain circumstances do we actually create alternation node
		if eval_if_condition(function_name, item, function_dict, motif_node_dict, name_dict):
			return create_alternation_node(left, right)
		else:
			print(
				'\x1b[6;30;43m[!]\x1b[0m [eval_if_else] Condition: {} is not considered, so no alternation node is produced'.format(ast_snippet(item.cond)))
			if left is not None and right is None:
				return left
			elif left is None and right is not None:
				return right
			else:
				return create_group_node(left, right)
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
		print('\x1b[6;30;43m[!]\x1b[0m [eval_if_else] Skipping if/else block that results in None')
		return None


def eval_return(function_name, statement, function_dict, motif_node_dict, name_dict):
	"""Evaluate a single return statement that directly generates new TreeNodes/MotifNode.

	Arguments:

	function_name 	-- the name of the function whose return statement we are inspecting
	statement 		-- return statement to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict		-- name map

	Returns:
	a motif_node and an RTMTree, either of which can be None
	"""
	if type(statement.expr).__name__ == 'FuncCall':
		return eval_function_call(function_name, statement.expr, function_dict, motif_node_dict, name_dict)
	elif type(statement.expr).__name__ == 'ID':
		if get_true_name(function_name + '.' + statement.expr.name, name_dict) in motif_node_dict:
			return motif_node_dict[get_true_name(function_name + '.' + statement.expr.name, name_dict)][-1], None
		else:
			print('\x1b[6;30;43m[!]\x1b[0m [eval_return] Skipping return due to unrecognized lvalue: {}'.format(
				ast_snippet(statement.expr.name)))
			return None, None
	else:
		print('\x1b[6;30;43m[!]\x1b[0m [eval_return] Skipping return: {}'.format(
			ast_snippet(statement.expr)))
		return None, None


def eval_while(function_name, item, function_dict, motif_node_dict, name_dict):
	"""Evaluate While blocks.

	Arguments:
	function_name 	-- the name of the function whose if/else statement we are inspecting
	item 			-- while block to be evaluated
	function_dict	-- dictionary that saves all function bodies
	motif_node_dict -- motif node map
	name_dict 		-- name map

	Returns:
	an RTMTree, which can be None
	"""
	statement = item.stmt
	if type(statement).__name__ == 'Compound':
		motif_node, tree_node = eval_function_body(function_name, item.stmt, function_dict, motif_node_dict, name_dict)
		if tree_node is not None:
			return create_asterisk_node(tree_node)
		else:
			return None
	else:
		print('\x1b[6;30;41m[x]\x1b[0m [eval_if_else]: The type {} is not implemented'.format(type(statement).__name__))
		raise NotImplementedError('type not implemented properly')
