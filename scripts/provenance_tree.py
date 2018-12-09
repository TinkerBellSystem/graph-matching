# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import re
from rtm_tree import *
from helper import *
from pycparser import c_parser, c_ast, parse_file

# Functions that deal with provenance
#####################################################################################################
def relation_to_str(str):
	"""
	Returns a corresponding relation string given the relation name.
	The information is stored in "type.c".
	"""
	with open('./camflow/type.c', 'r') as f:
		for line in f:
			matched = re.match(r"\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*\"(\w+)\"\s*;\s*\/\/\s*([\w\s]+)", line.strip())	# Match the lines in the "type.c" file that contains types.
			if matched is not None:	# Find the right lines
				relation = 'RL_' + matched.group(1)
				if relation == str:
					return matched.group(2)
		# No matching
		print('\33[5;30;103m' + '[warning][relation_to_str]: Unknown type: '+ str + '\033[0m')
	f.close()

def provenance_to_type(str):
	"""
	Convert provenance name to provenance type in string.
	"""
	if str == 'cprov' or str=='nprov' or str == 'old_prov' or str == 'pprov' or str == 'ENT_PROC':
		return 'process_memory'
	elif str == 'tprov' or str == 'ntprov' or str == 'ACT_TASK':
		return 'task'
	elif str == 'iprov' or str == 'iprova' or str == 'iprovb' or str == 'niprov' or str == 'inprov' or str == 'outprov' or str == 'oprov' or str == 'ENT_INODE_UNKNOWN':
		return 'inode'
	elif str == 'mprov' or str == 'ENT_MSG':
		return 'msg'
	elif str == 'sprov' or str == 'ENT_SHM':
		return 'shm'
	elif str == 'dprov':
		return 'directory'
	elif str == 'iattrprov' or str == 'ENT_IATTR':
		return 'iattr'
	elif str == 'bprov' or str == 'ENT_INODE_MMAP':
		return 'mmaped_file'
	elif str == 'pckprov':
		return 'packet'
	elif str == 'ENT_ARG':
		return 'arg'
	elif str == 'ENT_ENV':
		return 'env'
	else:
		print('\33[5;30;103m' + '[warning][provenance_to_type]: Unknown provenance type: '+ str + '\033[0m')
#####################################################################################################

# Functions that deal with RTM Tree
#####################################################################################################
def create_leaf_node(motif_edge):
	"""
	The function that generates this leaf node at the lowest level is "__write_relation".
	
	'FuncCall', 'Assignment', and 'Decl' type with "__write_relation" can result in a leaf node.
	"""
	return RTMTreeNode(motif_edge)

def create_asterisk_node(left):
	"""
	This function creates a unary "*" internal node.
	@left should be a leaf node or an internal node.

	shared memory read/write can result in this node.
	""" 
	asterisk_node = RTMTreeNode('*')
	asterisk_node.left = left
	return asterisk_node

def create_question_mark_node(left):
	"""
	This function creates a unary "?" internal node.
	@left should be a leaf node or an internal node.

	version updates can result in this question mark relation.
	""" 
	question_mark_node = RTMTreeNode('?')
	question_mark_node.left = left
	return question_mark_node

def create_group_node(left, right):
	"""
	This function creates a binary "." internal node.
	@left and @right should be leaf nodes or internal nodes.

	Compound block can result in this group relation.
	Note that "None" could also be an alternative in this case for either @left and @right, but not both.
	"""
	group_node = RTMTreeNode('.')
	group_node.left = left
	group_node.right = right
	return group_node

def create_alternation_node(left, right):
	"""
	This function creates a binary "|" internal node.
	@left and @right should be leaf nodes or internal nodes.

	"if/elif/else" block can result in this alternation relation.
	Note that "None" could also be an alternative in this case for either @left and @right, but not both.
	"""
	alternation_node = RTMTreeNode('|')
	alternation_node.left = left
	alternation_node.right = right
	return alternation_node
#####################################################################################################

# Functions that deal with Motifs
#####################################################################################################
def create_motif_node(node_type):
	"""
	If a motif node is never explicitly defined by e.g., alloc_provenance() or get_cred_provenance() function calls,
	we will create a new motif node on the fly.
	"""
	return MotifNode(provenance_to_type(node_type))
#####################################################################################################

# Functions that parse and analyze lower-level functions that are called by hook functions
#####################################################################################################
def match_arg(arg, parameters):
	"""
	Each @arg in subroutine functions such as 'record_relation()' is matched to the position
	of @parameters in its caller function (the lower-level function that we analyze) such as 'uses()'.
	"""
	if arg not in parameters:
		return None
	else:
		return parameters.index(arg)

def caller_parameter_names(function_decl):
	"""
	Extract parameter names from caller function delaration 
	(i.e., the low-level function we analyze such as 'uses()'')
	"""
	param_names = []
	# Function declaration does not have parameters
	if type(function_decl.type.args).__name__ == 'NoneType':
		return param_names
	elif type(function_decl.type.args).__name__ == 'ParamList':
		function_parameters = function_decl.type.args.params
		for param in function_parameters:
			param_names.append(param.name)
		return param_names
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		# POSSIBLE CODE HERE.
		#######################################################
		print('\33[101m' + '[error][caller_parameter_names]:  ' + type(function_decl.type.args).__name__ + ' is not yet considered.\033[0m')
		exit(1)

def extract_function_argument_names(function_call):
	"""
	Extract argument name in subroutine function calls in lower-level functions.
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
				arg_names.append(arg.args.exprs[0].name)	# assuming only first argument in FuncCall for simplicity
		return arg_names
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		# POSSIBLE CODE HERE.
		#######################################################
		print('\33[101m' + '[error][extract_function_argument_names]:  ' + type(function_call.args).__name__ + ' is not yet considered.\033[0m')
		exit(1)

def eval_function_call(func_call, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate a single function call within the lower-level functions called by hook functions.
	All evaluated function calls should return None, a new MotifNode and/or a new RTM Tree Node.
	"""
	print("\x1b[6;30;42m" + 'Evaluating ' + func_call.name.name + ' function...' + '\x1b[0m')
	if func_call.name.name == 'record_relation':
		arg_names = extract_function_argument_names(func_call)
		# Only the first three arguments are of interest
		edge_type_index = match_arg(arg_names[0], caller_parameters)
		if edge_type_index == None:	# edge type is hard-coded in `record_relation` subroutine.
			edge_type = relation_to_str(str(arg_names[0]))
		else:
			edge_type = caller_arguments[edge_type_index]

		from_node_index = match_arg(arg_names[1], caller_parameters)
		from_node = caller_arguments[from_node_index]
		from_key = getKeyByValue(motif_node_dict, from_node)
		if from_key:
			# try again to get the lastest version
			from_node = getLastValueFromKey(motif_node_dict, from_key)

		to_node_index = match_arg(arg_names[2], caller_parameters)
		to_node = caller_arguments[to_node_index]
		to_key = getKeyByValue(motif_node_dict, to_node)
		if to_key:
			to_node = getLastValueFromKey(motif_node_dict, to_key)
		return record_relation(edge_type, from_node, to_node, None, None, motif_node_dict)
	elif func_call.name.name == 'current_update_shst':
		arg_names = extract_function_argument_names(func_call)
		cprov_index = match_arg(arg_names[0], caller_parameters)
		cprov_node = caller_arguments[cprov_index]
		cprov_key = getKeyByValue(motif_node_dict, cprov_node)
		if cprov_key:
			cprov_node = getLastValueFromKey(motif_node_dict, cprov_key)
		if arg_names[1] == 'true':
			return current_update_shst(cprov_node, True, motif_node_dict)
		else:
			return current_update_shst(cprov_node, False, motif_node_dict)
	else:
		return None, None

def eval_assignment(assignment, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate a single assignment that directly generates new MotifNodes or TreeNodes.
	"""
	if type(assignment.rvalue).__name__ == 'FuncCall':
		motif_node, tree_node = eval_function_call(assignment.rvalue, caller_parameters, caller_arguments, motif_node_dict, local_dict)
		# it is possible that a function being evaluated returns a non-None MotifNode that need not to be assigned to the LHS variable.
		# But if the LHS variable is in @local_dict, then the RHS function must return a non-None MotifNode.
		# consider "var = XXX;" and "*var = XXX" and "&var = XXX" situations
		if (type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in local_dict) or (type(assignment.lvalue).__name__ == 'UnaryOp' and assignment.lvalue.expr.name in local_dict):
			if not motif_node:
				print('\33[101m' + '[error][eval_assignment/provenance]:  ' + assignment.lvalue.name + ' is in the local dictionary. MotifNode should not be None.\033[0m')
				exit(1)
			else:
				local_dict[assignment.lvalue.name].append(motif_node)
		return tree_node
	# In a case where a provenance node was declared but then assigned or reassigned. For example:
	#   struct provenance *tprov;
	#   ...
	#   tprov = t->provenance;
	# tprov must then be in the motif_node_dict.
	elif type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in local_dict:
		# we can only infer its type from the name of the variable
		motif_node = create_motif_node(assignment.lvalue.name)
		local_dict[assignment.lvalue.name].append(motif_node)
		return None
	elif type(assignment.lvalue).__name__ == 'UnaryOp' and type(assignment.lvalue.expr).__name__ == 'ID' and assignment.lvalue.expr.name in local_dict:
		# similar case as the previous one, except that we have: *tprov = ...
		# we can only infer its type from the name of the variable
		motif_node = create_motif_node(assignment.lvalue.expr.name)
		local_dict[assignment.lvalue.expr.name].append(motif_node)
		return None
	else:
		#######################################################
		# We will consider other conditions if we ever see them
		# POSSIBLE CODE HERE.
		#######################################################
		return None

def eval_declaration(declaration, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate a single declaration that directly generates new MotifNodes or TreeNodes.
	"""
	# We are only concerned with declaration type "struct provenance" or "struct provenance *"
	if type(declaration.type).__name__ == 'PtrDecl' and type(declaration.type.type).__name__ == 'TypeDecl' and type(declaration.type.type.type).__name__ == 'Struct' and declaration.type.type.type.name == 'provenance':
		if type(declaration.init).__name__ == 'FuncCall':
			motif_node, tree_node = eval_function_call(declaration.init, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if not motif_node:
				print('\33[101m' + '[error][eval_declaration/provenance]:  ' + declaration.name + ' must be associated with a MotifNode.\033[0m')
				exit(1)
			else:
				# it should be the first time we see the name in the dictionary
				if declaration.name in local_dict:
					print('\33[101m' + '[error][eval_declaration/provenance]:  ' + declaration.name + ' should not already be in the local dictionary.\033[0m')                    
					exit(1)
				else:
					local_dict[declaration.name] = [motif_node]
			return tree_node
		# it must be set through other methods, 'inode' is the only case for now.
		else:
			if declaration.name in local_dict:
				print('\33[101m' + '[error][eval_declaration/provenance]:  ' + declaration.name + ' is not set in an unknown way but should not already be in the local dictionary.\033[0m')                    
				exit(1)
			else:
				local_dict[declaration.name] = [MotifNode('inode')]
			return None
	else:
		return None

def eval_return(statement, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate a single return statement that directly generates new TreeNodes and/or MotifNode.
	"""
	if type(statement.expr).__name__ == 'FuncCall':
		return eval_function_call(statement.expr, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(statement.expr).__name__ == 'ID':
		if statement.expr.name in local_dict:
			return local_dict[statement.expr.name], None
		else:
			return None, None
	else:
		return None, None

def eval_if_condition(condition):
	"""
	Evaluate `if` condition.
	Returns True if the `if` condition requires alternation consideration.
	Otherwise, return False.
	"""
	return False

def eval_if_else(item, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate (nesting) if/else blocks.
	Only if/else blocks that contain statements that create TreeNodes are of interest here.
	Within those blocks, only specific if/else condition checks are of interest here.
	Most if/else are for error handling only. 

	We assume that if/else block do not create new MotifNode.
	"""
	true_branch = item.iftrue
	if type(true_branch).__name__ == 'FuncCall':
		motif_node, left = eval_function_call(true_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)     
	elif type(true_branch).__name__ == 'Assignment':
		left = eval_assignment(true_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(true_branch).__name__ == 'Decl':
		left = eval_declaration(true_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(true_branch).__name__ == 'Return':
		motif_node, left = eval_return(true_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
		if motif_node:
			print('\33[101m' + '[error][eval_if_else/provenance]: if statement true branch should not generate a new MotifNode at return.\033[0m')                    
			exit(1)
	elif type(true_branch).__name__ == 'Compound':
		motif_node, left = eval_function_body(true_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
		if motif_node:
			print('\33[101m' + '[error][eval_if_else/provenance]: if statement true branch should not generate a new MotifNode at Compound.\033[0m')                    
			exit(1)
	else:
		left = None
    
	false_branch = item.iffalse
	if type(false_branch).__name__ == 'FuncCall':
		motif_node, right = eval_function_call(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(false_branch).__name__ == 'Assignment':
		right = eval_assignment(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(false_branch).__name__ == 'Decl':
		right = eval_declaration(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	elif type(false_branch).__name__ == 'Return':
		motif_node, right = eval_return(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
		if motif_node:
			print('\33[101m' + '[error][eval_if_else/provenance]: if statement false branch should not generate a new MotifNode at return.\033[0m')                    
			exit(1)
	elif type(false_branch).__name__ == 'Compound':
		motif_node, right = eval_function_body(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
		if motif_node:
			print('\33[101m' + '[error][eval_if_else/provenance]: if statement false branch should not generate a new MotifNode at Compound.\033[0m')                    
			exit(1)
	elif type(false_branch).__name__ == 'If':   # else if case
		right = eval_if_else(false_branch, caller_parameters, caller_arguments, motif_node_dict, local_dict)
	else:
		right = None

	if left or right:
		# only under certain circumstances do we actually create alternation node
		if eval_if_condition(item.cond):
			return create_alternation_node(left, right)
		else:
			# if only one branch is not None, we need not create a group node
			if not left:
				return right
			if not right:
				return left
			return create_group_node(left, right)
	else:
		return None

def eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict):
	"""
	Evaluate a Compound function body.
	All evaluated function bodies should return a tuple: (New Motif Node, New RTM Tree Node), either or both of which can be None
	"""
	# The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
	# The following goes through the declarations and statements in the function body
	motif = None
	tree = None
	for item in function_body.block_items:
		if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
			new_motif_node, new_tree_node = eval_function_call(item, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if new_tree_node != None:
				tree = create_group_node(tree, new_tree_node)
		elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
			new_tree_node = eval_assignment(item, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if new_tree_node != None:
				tree = create_group_node(tree, new_tree_node)
		elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
			new_tree_node = eval_declaration(item, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if new_tree_node != None:
				tree = create_group_node(tree, new_tree_node)
		elif type(item).__name__ == 'If':   # Case 4: if
			new_tree_node = eval_if_else(item, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if new_tree_node != None:
				tree = create_group_node(tree, new_tree_node)
		elif type(item).__name__ == 'Return':	# Case 5: return with function call
			new_motif_node, new_tree_node = eval_return(item, caller_parameters, caller_arguments, motif_node_dict, local_dict)
			if new_tree_node != None:
				tree = create_group_node(tree, new_tree_node)
			motif = new_motif_node
	return motif, tree
#####################################################################################################

# Some building block functions
# These functions (except possibly helper functions starts with __) returns a tuple (MotifNode, RTM Tree Node), 
# either or both of which can be None.
# because some functions actually return a new MotifNode object.
# These function does not run static analysis using AST.
#####################################################################################################
### cred.h
def task_cred_xxx(task, xxx):
	"""
	Simply return a new MotifNode of type 'task'
	"""
	return MotifNode('task'), None

### provenance.h
def alloc_provenance(node_type, gfp):
	"""
	A new MotifNode is created given the @node_type when 'alloc_provenance' (provenance.h) is called.

	Return:
	The second element in the returned tuple is None since no RTM tree node is generated in this function.

	Function signature: static __always_inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
	@node_type --> ntype

	@gfp is ignored in our analysis.
	"""
	if gfp:
		print('\33[101m' + '[error][alloc_provenance]:  parameter "gfp" is not ignored.\033[0m')
		exit(1)
	return create_motif_node(node_type), None

### provenance_filter.h
def __filter_update_node(edge_type):
	"""
	For certain types of edge, calling update version makes no sense
	So we identify them so that we do not call "update_version" function.
	"""
	if edge_type == 'RL_VERSION_TASK' or edge_type == 'RL_VERSION' or edge_type == 'RL_NAMED' or edge_type == 'RL_NAMED_PROCESS':
		return True
	else:
		return False

### provenance_record.h
def __update_version(edge_type, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "__update_version" (provenance_record.h) is called.
	A new MotifNode is created, which is the updated version of the @motif_node.
	A version edge between the new MotifNode and @motif_node is created.

	We must update the @motif_node_dict with the corresponding entry name (the key of @motif_node).
	This is appended to the value of the dictionary.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. prov_policy.should_compress_node

	Function signature: static __always_inline int __update_version(const uint64_t type, prov_entry_t *prov)
	@edge_type --> type
	@motif_node --> prov
	"""
	# if updating version is not needed, simply return the original node
	if __filter_update_node(edge_type):
		return motif_node, None

	new_motif_node = MotifNode(motif_node.mn_ty)
	new_motif_node.mn_has_name_recorded = motif_node.mn_has_name_recorded
	new_motif_node.mn_kernel_version = motif_node.mn_kernel_version
	new_motif_node.mn_is_initialized = motif_node.mn_is_initialized
	if motif_node.mn_ty == 'task':
		motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION_TASK'))
	else:
		motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION'))
	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	return new_motif_node, create_leaf_node(motif_edge)

def record_relation(edge_type, from_node, to_node, file, flags, motif_node_dict):
	"""
	RTM tree nodes for when "record_relation" (provenance_record.h) is called.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. prov_policy.should_compress_edge

	Function signature: static __always_inline int record_relation(const uint64_t type, prov_entry_t *from, prov_entry_t *to, const struct file *file, const uint64_t flags)
	@edge_type --> type
	@from_node --> from
	@to_node --> to

	@file and @flags are ignored in our analysis.
	"""
	new_to_node, rtm_tree_update_node = __update_version(edge_type, to_node, motif_node_dict)
	new_motif_edge = MotifEdge(from_node, new_to_node, edge_type)
	rtm_tree_leaf_node = create_leaf_node(new_motif_edge)

	# from_node now has outgoing edges
	from_node.mn_has_outgoing = True

	return new_to_node, create_group_node(rtm_tree_update_node, rtm_tree_leaf_node)

def record_terminate(edge_type, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_terminate" (provenance_record.h) is called.
	A new MotifNode is created, which is the final version of the @motif_node.
	A version edge between the new MotifNode and @motif_node is created.
	The new MotifNode retires immediately due to termination,
	For completeness, we still add the new node to the Motif Node Dictionary.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. provenance_is_recorded(prov_elt(prov))
	2. prov_policy.prov_all
	3. filter_node(prov_entry(prov))

	Return:
	The first element in the returned tuple is None since no Motif node needs to be returned in this function.
	(record_terminate() in CamFlow does not return a provenance node object.)

	Function signature: static __always_inline int record_terminate(uint64_t type, struct provenance *prov)
	@edge_type --> type
	@motif_node --> prov
	"""
	new_motif_node = MotifNode(motif_node.mn_ty)
	new_motif_node.mn_has_name_recorded = motif_node.mn_has_name_recorded
	new_motif_node.mn_kernel_version = motif_node.mn_kernel_version
	new_motif_node.mn_is_initialized = motif_node.mn_is_initialized

	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	else:
		print('\33[101m' + '[error][record_terminate]: Motif Node: '+ str(motif_node.mn_id) + ' of the type ' + str(motif_node.mn_ty) + ' do not have a key in Motif Node Dictionary. \033[0m')
	motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str(edge_type))
	return None, create_leaf_node(motif_edge)

def record_node_name(motif_node, name, force, motif_node_dict):
	"""
	RTM tree nodes for when "record_node_name" (provenance_record.h) is called.
	A new MotifNode is created for the path name.
	The new MotifNode is a short-lived, so it is not needed to be remembered in @motif_node_dict.

	The following check is ignored:
	1. provenance_is_recorded(prov_elt(node))

	We check if @motif_node's name has been recorded before because of the check in CamFlow:
	1. provenance_is_name_recorded(prov_elt(node))
	We record the node name if 
	1. @motif_node's name has not been recorded, or
	2. Force is True

	Function signature: static inline int record_node_name(struct provenance *node,
															const char *name,
															bool force) 
	@motif_node --> node
	@force --> force

	@name is ignored in our analysis.
	"""
	# if recording node name is not needed, simply return @motif_node, None
	if motif_node.mn_has_name_recorded and not force:
		return motif_node, None

	new_motif_node = MotifNode('path')
	if motif_node.mn_ty == 'task':
		updated_motif_node, rtm_tree_node = record_relation(relation_to_str('RL_NAMED_PROCESS'), new_motif_node, motif_node, None, None, motif_node_dict)
	else:
		updated_motif_node, rtm_tree_node = record_relation(relation_to_str('RL_NAMED'), new_motif_node, motif_node, None, None, motif_node_dict)
	# motif_node's name is now recorded
	motif_node.mn_has_name_recorded = True
	return updated_motif_node, rtm_tree_node

def record_kernel_link(motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_kernel_link" (provenance_record.h) is called.
	
	The following checks are ignored because we can easily decide CamFlow settings:
	1. provenance_is_recorded(prov_elt(node))

	Function signature: static inline int record_kernel_link(struct provenance *node)
	@motif_node --> node
	"""
	# TODO: Kernel Node is a global variable.
	if 'kernel' not in motif_node_dict:
		motif_node_dict['kernel'] = [MotifNode('machine')]

	if motif_node.mn_kernel_version < len(motif_node_dict['kernel']):
		# update the node's kernel version
		motif_node.mn_kernel_version = len(motif_node_dict['kernel'])
		return record_relation(relation_to_str('RL_RAN_ON'), getLastValueFromKey(motif_node_dict, 'kernel'), motif_node, None, None, motif_node_dict)

def influences_kernel(edge_type, entity_node, activity_node, file, motif_node_dict):
	"""
	RTM tree nodes for when 'influences_kernel' (provenance_record.h) is called.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. apply_target(prov)
	2. provenance_is_opaque(prov)

	Function signature: static __always_inline int influences_kernel(const uint64_t type,
																		struct provenance *entity,
																		struct provenance *activity,
																		const struct file *file)
	@edge_type -> type
	@entity_node -> entity
	@activity_node -> activity

	@file is ignored in our analysis.
	"""
	# TODO: Kernel Node is a global variable.
	if 'kernel' not in motif_node_dict:
		motif_node_dict['kernel'] = [MotifNode('machine')]
	
	updated_activity_node, rtm_tree_load_node = record_relation(relation_to_str('RL_LOAD_FILE'), entity_node, activity_node, None, None,motif_node_dict)
	updated_activity_node, rtm_tree_type_node = record_relation(relation_to_str(edge_type), activity_node, getLastValueFromKey(motif_node_dict, 'kernel'), None, None, motif_node_dict)

	return updated_activity_node, create_group_node(rtm_tree_load_node, rtm_tree_type_node)

### provenance_inode.h
def update_inode_type(mode, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "update_inode_type" (provenance_inode.h) is called.
	
	The following check is ignored:
	1. provenance_is_recorded(prov_elt(prov))

	mode value can only be known as runtime. Therefore, we must use a question mark node.

	Function signature: static inline void update_inode_type(uint16_t mode, struct provenance *prov)
	@motif_node --> prov

	@mode is ignored in our analysis.
	"""
	new_motif_node = MotifNode(motif_node.mn_ty)
	new_motif_node.mn_has_name_recorded = motif_node.mn_has_name_recorded
	new_motif_node.mn_kernel_version = motif_node.mn_kernel_version
	new_motif_node.mn_is_initialized = motif_node.mn_is_initialized

	motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION'))
	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	else:
		print('\33[5;30;103m' + '[warning][update_inode_type]: Motif Node: '+ str(motif_node.mn_id) + ' of the type ' + str(motif_node.mn_ty) + ' do not have a key in Motif Node Dictionary. \033[0m')
	return new_motif_node, create_question_mark_node(create_leaf_node(motif_edge))

def record_inode_name_from_dentry(dentry, motif_node, force, motif_node_dict):
	"""
	RTM tree nodes for when "record_inode_name_from_dentry" (provenance_inode.h) is called.
	
	The following check is ignored:
	1. provenance_is_recorded(prov_elt(prov))

	We check if @motif_node's name has been recorded before because of the check in CamFlow:
	1. provenance_is_name_recorded(prov_elt(prov))

	Function signature: static inline int record_inode_name_from_dentry(struct dentry *dentry,
													struct provenance *prov,
													bool force) 
	@motif_node --> prov
	@force --> force

	@dentry is ignored in our analysis.
	"""
	if motif_node.mn_has_name_recorded:
		return motif_node, None
	else:
		return record_node_name(motif_node, None, force, motif_node_dict)

def record_inode_name(inode, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_inode_name" (provenance_inode.h) is called.
	
	The following check is ignored:
	1. provenance_is_recorded(prov_elt(prov))

	We check if @motif_node's name has been recorded before because of the check in CamFlow:
	1. provenance_is_name_recorded(prov_elt(prov))

	Function signature: static inline int record_inode_name(struct inode *inode, struct provenance *prov) 
	@motif_node --> prov

	@inode is ignored in our analysis.
	"""
	if motif_node.mn_has_name_recorded:
		return motif_node, None
	else:
		return record_inode_name_from_dentry(None, motif_node, False, motif_node_dict)

def refresh_inode_provenance(inode, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "refresh_inode_provenance" (provenance_inode.h) is called.
	
	The following check is ignored:
	1. provenance_is_opaque(prov_elt(prov))

	Function signature: static __always_inline void refresh_inode_provenance(struct inode *inode, struct provenance *prov)
	@motif_node --> prov

	@inode is ignored in our analysis.
	"""
	updated_motif_node, rtm_tree_record_node = record_inode_name(None, motif_node, motif_node_dict)
	new_motif_node, rtm_tree_update_node = update_inode_type(None, updated_motif_node, motif_node_dict)
	return new_motif_node, create_group_node(rtm_tree_record_node, rtm_tree_update_node)

def branch_mmap(iprov, cprov):
	"""
	A new MotifNode is created, which is also returned and used by hook functions.

	The following check is ignored:
	1. provenance_is_tracked(prov_elt(iprov/cprov))
	2. prov_policy.prov_all

	Function signature: static inline struct provenance *branch_mmap(struct provenance *iprov, struct provenance *cprov)
	@iprov and @cprov are ignored.	
	"""
	new_motif_node = create_motif_node('ENT_INODE_MMAP')
	return new_motif_node, None

def inode_init_provenance(inode, opt_dentry, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "inode_init_provenance" (provenance_inode.h) is called.
	
	We check if @motif_node's has been initialized before because of the check in CamFlow:
	1. provenance_is_initialized(prov_elt(prov))

	Function signature: static inline int inode_init_provenance(struct inode *inode,
																struct dentry *opt_dentry,
																struct provenance *prov)
	@motif_node --> prov

	@inode and @opt_dentry are ignored in our analysis.
	"""
	if motif_node.mn_is_initialized:
		return motif_node, None
	else:
		motif_node.mn_is_initialized = True
		return update_inode_type(None, motif_node, motif_node_dict)

def get_inode_provenance(inode, may_sleep, motif_node_dict):
	"""
	RTM tree nodes for when "get_inode_provenance" (provenance_inode.h) is called.
	A new MotifNode of type 'inode' is created, which is also returned and used by hook functions.

	We check if @motif_node's has been initialized before because of the check in CamFlow:
	1. provenance_is_initialized(prov_elt(prov))
	We also check @may_sleep

	Function signature: static __always_inline struct provenance *get_inode_provenance(struct inode *inode, bool may_sleep)

	@inode is ignored in our analysis.
	"""
	motif_node = MotifNode('inode')
	rtm_tree_init_node = None
	rtm_tree_refresh_node = None
	if not motif_node.mn_is_initialized and may_sleep:
		new_motif_node, new_rtm_tree_init_node = inode_init_provenance(None, None, motif_node, motif_node_dict)
		motif_node = new_motif_node
		rtm_tree_init_node = new_rtm_tree_init_node
	if may_sleep:
		new_motif_node, new_rtm_tree_refresh_node = refresh_inode_provenance(None, motif_node, motif_node_dict)
		motif_node = new_motif_node
		rtm_tree_refresh_node = new_rtm_tree_refresh_node
	if not rtm_tree_init_node and rtm_tree_refresh_node:
		return motif_node, rtm_tree_refresh_node
	elif rtm_tree_init_node and not rtm_tree_refresh_node:
		return motif_node, rtm_tree_init_node
	elif rtm_tree_init_node and rtm_tree_refresh_node:
		return motif_node, create_group_node(rtm_tree_init_node, rtm_tree_refresh_node)
	else:
		return motif_node, None 

def get_dentry_provenance(dentry, may_sleep, motif_node_dict):
	"""
	RTM tree nodes for when "get_dentry_provenance" (provenance_inode.h) is called.

	Function signature: static __always_inline struct provenance *get_dentry_provenance(struct dentry *dentry, bool may_sleep)

	@dentry is ignored in our analysis.
	"""
	return get_inode_provenance(None, may_sleep, motif_node_dict)

def get_file_provenance(file, may_sleep, motif_node_dict):
	"""
	RTM tree nodes for when "get_file_provenance" (provenance_inode.h) is called.

	Function signature: static __always_inline struct provenance *get_file_provenance(struct file *file, bool may_sleep)

	@file is ignored in our analysis.
	"""
	return get_inode_provenance(None, may_sleep, motif_node_dict)

def record_write_xattr(edge_type, iprov_node, tprov_node, cprov_node, name, value, size, flags, motif_node_dict):
	"""
	RTM tree nodes for when "record_write_xattr" (provenance_inode.h) is called.
	A new MotifNode is created for 'xattr' type.

	The following check is ignored:
	1. provenance_is_tracked(prov_elt(iprov/tprov/cprov))
	2. prov_policy.prov_all
	3. should_record_relation

	Function signature: int record_write_xattr(uint64_t type,
												struct provenance *iprov,
												struct provenance *tprov,
												struct provenance *cprov,
												const char *name,
												const void *value,
												size_t size,
												const uint64_t flags)
	@edge_type --> type
	@iprov_node --> iprov
	@tprov_node --> tprov
	@cprov_node --> cprov

	@name, @value, @size, @flags are ignored.
	"""
	ty = relation_to_str(edge_type)

	new_motif_node = MotifNode('xattr')
	_, rtm_tree_proc_read_node = record_relation(relation_to_str('RL_PROC_READ'), cprov_node, tprov_node, None, None, motif_node_dict)
	_, rtm_tree_type_node = record_relation(ty, tprov_node, new_motif_node, None, None, motif_node_dict)
	rtm_tree_group_node = create_group_node(rtm_tree_proc_read_node, rtm_tree_type_node)
	
	if edge_type == 'RL_SETXATTR':
		_, rtm_tree_set_node = record_relation(relation_to_str('RL_SETXATTR_INODE'), new_motif_node, iprov_node, None, None, motif_node_dict)
		return None, create_group_node(rtm_tree_group_node, rtm_tree_set_node)
	else:
		_, rtm_tree_rmv_node = record_relation(relation_to_str('RL_RMVXATTR_INODE'), new_motif_node, iprov_node, None, None, motif_node_dict)
		return None, create_group_node(rtm_tree_group_node, rtm_tree_rmv_node)

def record_read_xattr(cprov_node, tprov_node, iprov_node, name, motif_node_dict):
	"""
	RTM tree nodes for when "record_read_xattr" (provenance_inode.h) is called.
	A new MotifNode is created for 'xattr' type.

	The following check is ignored:
	1. provenance_is_tracked(prov_elt(iprov/tprov/cprov))
	2. prov_policy.prov_all
	3. should_record_relation

	Function signature: int record_read_xattr(struct provenance *cprov,
												struct provenance *tprov,
												struct provenance *iprov,
												const char *name)
	@cprov_node --> cprov
	@tprov_node --> tprov
	@iprov_node --> iprov

	@name is ignore.
	"""
	new_motif_node = MotifNode('xattr')
	_, rtm_tree_get_inode_node = record_relation(relation_to_str('RL_GETXATTR_INODE'), iprov_node, new_motif_node, None, None, motif_node_dict)
	_, rtm_tree_get_node = record_relation(relation_to_str('RL_GETXATTR'), new_motif_node, tprov_node, None, None, motif_node_dict)
	rtm_tree_group_node = create_group_node(rtm_tree_get_inode_node, rtm_tree_get_node)
	
	_, rtm_tree_proc_write_node = record_relation(relation_to_str('RL_PROC_WRITE'), tprov_node, cprov_node, None, None, motif_node_dict)
	return None, create_group_node(rtm_tree_group_node, rtm_tree_proc_write_node)

### provenance_task.h
def current_update_shst(motif_node, read, motif_node_dict):
	"""
	RTM tree nodes for when "current_update_shst" (provenance_task.h) is called.

	"flags" value is only known at time, so we include a question mark node while checking:
	1. vm_read_exec_mayshare(flags)
	2. vm_write_mayshare(flags)
	
	Function signature: static __always_inline int current_update_shst(struct provenance *cprov, bool read)
	@motif_node --> cprov
	@read --> read
	"""
	mmprov_motif_node, rtm_tree_mmprov_node = get_file_provenance(None, False, motif_node_dict)
	# We did not include "rtm_tree_mmprov_node" because we know it is None
	if rtm_tree_mmprov_node:
		print('\33[101m' + '[error][current_update_shst]: get_file_provenance should not return a non-None RTM TreeNode. \033[0m')
		exit(1)
	if read:
		_, rtm_tree_read_node = record_relation(relation_to_str('RL_SH_READ'), mmprov_motif_node, motif_node, None, None, motif_node_dict)
		return None, create_asterisk_node(create_question_mark_node(rtm_tree_read_node))
	else:
		_, rtm_tree_write_node = record_relation(relation_to_str('RL_SH_WRITE'), motif_node, mmprov_motif_node, None, None, motif_node_dict)
		return None, create_asterisk_node(create_question_mark_node(rtm_tree_write_node))

def record_task_name(task, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_task_name" (provenance_task.h) is called.

	The following check is ignored:
	1. provenance_is_recorded(prov_elt(prov))
	2. provenance_is_opaque(prov_elt(fprov))

	"exe_file" value is only known at time, so we include a question mark node while checking:
	1. if (exe_file)

	Function signature: static inline int record_task_name(struct task_struct *task,
															struct provenance *prov)
	@motif_node --> prov
	
	@task is ignored.
	"""
	if motif_node.mn_has_name_recorded:
		return None, None
	else:
		fprov_motif_node, rtm_tree_fprov_node = get_file_provenance(None, False, motif_node_dict)
		if rtm_tree_fprov_node:
			print('\33[101m' + '[error][record_task_name]: get_file_provenance should not return a non-None RTM TreeNode. \033[0m')
			exit(1)
		_, rtm_tree_name_node = record_node_name(motif_node, None, False, motif_node_dict)
		if not rtm_tree_name_node:
			return None, create_question_mark_node(rtm_tree_name_node)
		else:
			return None, None

def get_task_provenance():
	"""
	A new MotifNode is created of type 'task' when 'get_task_provenance' (provenance_task.h) is called.

	Return:
	The second element in the returned tuple is None since no RTM tree node is generated in this function.

	Function signature: static inline struct provenance *get_task_provenance( void )
	"""
	return MotifNode('task'), None

def get_cred_provenance(motif_node_dict):
	"""
	RTM tree nodes for when 'get_cred_provenance' (provenance_task.h) is called.
	This function returns a new MotifNode of type 'process_memory'.

	The following check is ignored:
	1. provenance_is_opaque(prov_elt(prov))

	Function signature: static inline struct provenance *get_cred_provenance(void)
	"""
	new_process_memory_motif_node = MotifNode('process_memory')

	_, rtm_tree_task_name_node = record_task_name(None, new_process_memory_motif_node, motif_node_dict)
	_, rtm_tree_kernel_link_node = record_kernel_link(new_process_memory_motif_node, motif_node_dict)

	if rtm_tree_task_name_node and rtm_tree_kernel_link_node:
		return new_process_memory_motif_node, create_group_node(rtm_tree_task_name_node, rtm_tree_kernel_link_node)
	elif not rtm_tree_task_name_node and rtm_tree_kernel_link_node:
		return new_process_memory_motif_node, rtm_tree_kernel_link_node
	elif rtm_tree_task_name_node and not rtm_tree_kernel_link_node:
		return new_process_memory_motif_node, rtm_tree_task_name_node
	else:
		return new_process_memory_motif_node, None

### provenance_net.h
def get_sk_provenance(sk, motif_node_dict):
	"""
	RTM tree nodes for when 'get_sk_provenance' (provenance_net.h) is called.
	This function returns a new MotifNode of type 'inode'.

	Function signature: static inline struct provenance *get_sk_provenance(struct sock *sk)
	@sk is ignored.
	"""
	return MotifNode('inode'), None

def get_socket_provenance(sock, motif_node_dict):
	"""
	RTM tree nodes for when 'get_socket_provenance' (provenance_net.h) is called.
	This function simply calls get_sk_provenance, which returns a new MotifNode of type 'inode'.

	Function signature: static inline struct provenance *get_socket_provenance(struct socket *sock)
	@sock is ignored.
	"""
	return get_sk_provenance(None, motif_node_dict)

def get_socket_inode_provenance(sock, motif_node_dict):
	"""
	RTM tree nodes for when 'get_socket_inode_provenance' (provenance_net.h) is called.
	This function returns a new MotifNode of type 'inode'.

	Function signature: static inline struct provenance *get_socket_inode_provenance(struct socket *sock)
	@sock is ignored.
	"""
	return get_inode_provenance(None, False, motif_node_dict)

def record_address(address, addrlen, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when 'record_address' (provenance_net.h) is called.
	A new MotifNode is created for 'address' type.

	The following check is ignored:
	1. provenance_is_recorded(prov_elt(prov))

	Function signature: static __always_inline int provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
	@motif_node --> prov

	@address, @addrlen are ignored.
	"""
	if motif_node.mn_has_name_recorded:
		return None, None
	else:
		new_motif_node = MotifNode('address')
		_, rtm_tree_named_node = record_relation(relation_to_str('RL_NAMED'), new_motif_node, motif_node, None, None, motif_node_dict)
		motif_node.mn_has_name_recorded = True
	return None, rtm_tree_named_node

def get_sk_inode_provenance(sk, motif_node_dict):
	"""
	RTM tree nodes for when 'get_sk_inode_provenance' (provenance_net.h) is called.
	This function returns a new MotifNode of type 'inode'.

	Function signature: static inline struct provenance *get_sk_inode_provenance(struct sock *sk)
	@sk is ignored.
	"""
	return get_socket_inode_provenance(None, motif_node_dict)

def record_packet_content(skb, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when 'record_packet_content' (provenance_net.h) is called.
	A new MotifNode is created for packet.
	
	Function signature: static __always_inline void provenance_packet_content(struct sk_buff *skb,
																				struct provenance *pckprov)
	@motif_node --> pckprov

	@skb is ignored.
	"""
	new_motif_node = MotifNode('packet_content')
	return record_relation(relation_to_str('RL_PCK_CNT'), new_motif_node, motif_node, None, None, motif_node_dict)

def record_arg(motif_node, vtype, etype, arg, len, motif_node_dict):
	"""
	RTM tree node(s) for when 'record_arg' (provenance_task.h) is called.
	A new MotifNode is created based on @vtype.

	Function signature: static __always_inline int prov_record_arg(struct provenance *prov,
																	uint64_t vtype,
																	uint64_t etype,
																	const char *arg,
																	size_t len)
	@motif_node --> prov
	@vtype --> vtype
	@etype --> etype

	@arg and @len are ignored.
	"""
	new_motif_node = create_motif_node(vtype)
	return record_relation(relation_to_str(etype), new_motif_node, motif_node, None, None, motif_node_dict)

def record_args(motif_node, bprm, motif_node_dict):
	"""
	RTM tree node(s) for when 'record_args' (provenance_task.h) is called.

	The following check is ignored:
	1. provenance_is_tracked(prov_elt(prov))
	2. prov_policy.prov_all

	Function signature: prov_record_args(struct provenance *prov,
										struct linux_binprm *bprm)
	@motif_node --> prov

	@bprm is ignored.
	"""
	_, rtm_tree_arg_node = record_arg(motif_node, 'ENT_ARG', 'RL_ARG', None, None, motif_node_dict)
	rtm_tree_arg_asterisk_node = create_asterisk_node(rtm_tree_arg_node)
	_, rtm_tree_env_node = record_arg(motif_node, 'ENT_ENV', 'RL_ENV', None, None, motif_node_dict)
	rtm_tree_env_asterisk_node = create_asterisk_node(rtm_tree_env_node)

	return None, create_group_node(rtm_tree_arg_asterisk_node, rtm_tree_env_asterisk_node)	
#####################################################################################################

# Functions that run static analysis using AST to generate a tuple (MotifNode, RTM Tree Node)
#####################################################################################################
def parser(file_name, function_name):
	"""
	Parse function @function_name in file @file_name to AST tree.
	Returns function declaration and function body to be analyzed.
	"""
	ast = parse_file(file_name)
	for ext in ast.ext:
		if type(ext).__name__ == 'FuncDef':
			function_decl = ext.decl
			func_name = function_decl.name
			if func_name == function_name:
				return function_decl, ext.body
	print('\33[101m' + '[error][parser]: Function: '+ function_name + ' does not exist in ' + file_name + ' .\033[0m')
	exit(1)

### provenance_record.h
def uses(edge_type, entity_node, activity_node, activity_mem_node, file, flags, motif_node_dict):
	"""
	Parse and analyze "uses" function in "provenance_record.h".
	"""
	function_decl, function_body = parser('./camflow/provenance_record_pp.h', 'uses')

	ty = relation_to_str(edge_type)
	caller_parameters = caller_parameter_names(function_decl)
	caller_arguments = [ty, entity_node, activity_node, activity_mem_node, file, flags]
	local_dict = {}
	return eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict)

def uses_two(edge_type, entity_node, activity_node, file, flags, motif_node_dict):
	"""
	Parse and analyze "uses_two" function in "provenance_record.h".
	"""
	function_decl, function_body = parser('./camflow/provenance_record_pp.h', 'uses_two')
	
	ty = relation_to_str(edge_type)
	caller_parameters = caller_parameter_names(function_decl)
	caller_arguments = [ty, entity_node, activity_node, file, flags]
	local_dict = {}
	return eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict)

def generates(edge_type, activity_mem_node, activity_node, entity_node, file, flags, motif_node_dict):
	"""
	Parse and analyze "generates" function in "provenance_record.h".
	"""
	function_decl, function_body = parser('./camflow/provenance_record_pp.h', 'generates')
	
	ty = relation_to_str(edge_type)
	caller_parameters = caller_parameter_names(function_decl)
	caller_arguments = [ty, activity_mem_node, activity_node, entity_node, file, flags]
	local_dict = {}
	return eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict)

def derives(edge_type, from_node, to_node, file, flags, motif_node_dict):
	"""
	Parse and analyze "derives" function in "provenance_record.h".
	"""
	function_decl, function_body = parser('./camflow/provenance_record_pp.h', 'derives')
	
	ty = relation_to_str(edge_type)
	caller_parameters = caller_parameter_names(function_decl)
	caller_arguments = [ty, from_node, to_node, file, flags]
	local_dict = {}
	return eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict)

def informs(edge_type, from_node, to_node, file, flags, motif_node_dict):
	"""
	Parse and analyze "informs" function in "provenance_record.h".
	"""
	function_decl, function_body = parser('./camflow/provenance_record_pp.h', 'informs')
	
	ty = relation_to_str(edge_type)
	caller_parameters = caller_parameter_names(function_decl)
	caller_arguments = [ty, from_node, to_node, file, flags]
	local_dict = {}
	return eval_function_body(function_body, caller_parameters, caller_arguments, motif_node_dict, local_dict)
#####################################################################################################
