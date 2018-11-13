# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

import re
from rtm import *

def relation_to_str(str):
	"""
	Returns a corresponding relation string given the relation name.
	The information is stored in "type.c".
	"""
	with open('../camflow/type.c', 'r') as f:
		for line in f:
			matched = re.match(r"\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*\"(\w+)\"\s*;\s*\/\/\s*([\w\s]+)", line.strip())	# Match the lines in the "type.c" file that contains types.
			if matched is not None:	# Find the right lines
				relation = 'RL_' + matched.group(1)
				if relation == str:
					return matched.group(2)
		print('\33[103m' + '[error]: Unknown type: '+ str + '\033[0m')

def prov_to_type(str):
	"""
	Convert provenance name to provenance type in string.
	"""
	if str == 'cprov' or str=='nprov' or str == 'old_prov' or str == 'pprov':
		return 'process_memory'
	elif str == 'tprov' or str == 'ntprov':
		return 'task'
	elif str == 'iprov' or str == 'iprova' or str == 'iprovb' or str == 'niprov' or str == 'inprov' or str == 'outprov' or str == 'oprov':
		return 'inode'
	elif str == 'mprov':
		return 'msg'
	elif str == 'sprov':
		return 'shm'
	elif str == 'dprov':
		return 'directory'
	elif str == 'iattrprov':
		return 'iattr'
	elif str == 'bprov':
		return 'mmaped_file'
	elif str == 'pckprov':
		return 'packet'
	else:
		print('\33[104m' + '[error]: Unknown provenance type: '+ str + '\033[0m')

def create_edge(src_node_type, dst_node_type, edge_type):
	"""
	Create a typed (@edge_type), timestamped(@ts) MotifEdge.
	An edge is defined by two MotifNodes.
	"""
	src_node = MotifNode(src_node_type)
	dst_node = MotifNode(dst_node_type)
	return MotifEdge(src_node, dst_node, edge_type)

def create_singular_relation(src_node_type, dst_node_type, edge_type):
	"""
	The function that generates this relation at the lowest level is "__write_relation".
	This is a singular relation.
	
	'FuncCall', 'Assignment', and 'Decl' type with "__write_relation" can result in this singular relation.
	"""
	left = create_edge(src_node_type, dst_node_type, edge_type)
	return Relation(left, None, None)

def create_asterisk_relation(left):
	"""
	This function creates a unary "*" relation.

	shared memory read/write can result in this asterisk relation.
	""" 
	return Relation(left, None, '*')


def create_group_relation(left, right):
	"""
	This function creates a binary "(...)" relation.

	Compound block can result in this group relation.
	"""
	return Relation(left, right, '()')

def create_alternation_relation(left, right):
	"""
	This function creates a binary "|" relation.

	"if/elif/else" block can result in this alternation relation.
	Note that "None" could also be an alternative in this case (i.e., no relation).
	"""
	return Relation(left, right, "|")

# Some building block relation functions
########################################
def update_version_relation(node_type):
	"""
	Edges for when "__update_version" is called.
	# TODO: This function is processed MANUALLY due to its requirement in "if" conditions.
	"""
	if node_type == 'task':
		return create_singular_relation('task', 'task', relation_to_str('RL_VERSION_TASK'))
	else:
		return create_singular_relation(node_type, node_type, relation_to_str('RL_VERSION'))

def record_relation(src_node_type, dst_node_type, edge_type):
	"""
	Edges for when "record_relation" is called.
	# TODO: automate this process.
	"""
	return create_group_relation(update_version_relation(dst_node_type), create_singular_relation(src_node_type, dst_node_type, edge_type))

def record_terminate(node_type, edge_type):
	"""
	Edges for when "record_terminate" is called.
	# TODO: automate this process.
	"""
	return create_singular_relation(node_type, node_type, edge_type)

def record_write_xattr(edge_type):
	"""
	Edges for when "record_write_xattr" is called.
	# TODO: automate this process.
	"""
	relation = relation_to_str(edge_type)
	proc_read_relation = record_relation('process_memory', 'task', relation_to_str('RL_PROC_READ'))
	edge_type_relation = record_relation('task', 'xattr', relation)
	group = create_group_relation(proc_read_relation, edge_type_relation)
	if relation == 'setxattr':
		return create_group_relation(group, record_relation('xattr', 'inode', relation_to_str('RL_SETXATTR_INODE')))
	else:
		return create_group_relation(group, record_relation('xattr', 'inode', relation_to_str('RL_RMVXATTR_INODE')))

def record_read_xattr():
	"""
	Edges for when "record_read_xattr" is called.
	# TODO: automate this process.
	"""
	getxattr_inode_relation = record_relation('inode', 'xattr', relation_to_str('RL_GETXATTR_INODE'))
	getxattr_relation = record_relation('xattr', 'task', relation_to_str('RL_GETXATTR'))
	proc_write_relation = record_relation('task', 'process_memory', relation_to_str('RL_PROC_WRITE'))
	return create_group_relation(create_group_relation(getxattr_inode_relation, getxattr_relation), proc_write_relation)

def current_update_shst(is_read):
	"""
	Edges for when "current_update_shst" is called.
	@is_read: if False, then it is "write"
	# TODO: automate this process.
	"""
	if is_read:
		return create_asterisk_relation(record_relation('inode', 'process_memory', relation_to_str('RL_SH_READ')))
	else:
		return create_asterisk_relation(record_relation('process_memory', 'inode', relation_to_str('RL_SH_WRITE')))
########################################

# Building block functions to parse higher-level functions such as 'uses', 'generates', etc.
###########################################################################################
def match_arguments(arg, arguments):
	"""
	Each @arg in low-level functions such as 'record_relation' is matched to the position
	of @arguments in its caller function such as 'uses'.
	"""
	if arg not in arguments:
		return None
	else:
		return arguments.index(arg)

def caller_argument_names(function_decl):
	"""
	Extract argument names from caller function delaration.
	"""
	arg_names = []
	function_arguments = function_decl.type.args.params
	for arg in function_arguments:
		arg_names.append(arg.name)
	return arg_names

def extract_function_arg_names(func_call):
	"""
	Extract arguments in function calls.
	We have three cases:
	For example,
	funccall(arg1, &arg2, func(arg3));
	case 1: arg1 -> arg1
	case 2: &arg2 -> arg2
	case 3: func(arg3) -> arg3
	"""
	arg_names = []
	for arg in func_call.args.exprs:
		if type(arg).__name__ == 'ID':
			arg_names.append(arg.name)
		elif type(arg).__name__ == 'UnaryOp':
			arg_names.append(arg.expr.name)
		elif type(arg).__name__ == 'FuncCall':
			arg_names.append(arg.args.exprs[0].name)	# assuming only first argument in FuncCall
	return arg_names

def eval_func_call(func_call, caller_arguments, params):
	"""
	Evaluate a single function call that directly generates relations.
	"""
	if func_call.name.name == 'record_relation':
		arg_names = extract_function_arg_names(func_call)
		# Only the first three arguments are of interest
		edge_type_index = match_arguments(arg_names[0], caller_arguments)
		if edge_type_index == None:	# edge type is hard-coded in `record_relation function`.
			edge_type = relation_to_str(str(arg_names[0]))
		else:
			edge_type = params[edge_type_index]
		src_node_type_index = match_arguments(arg_names[1], caller_arguments)
		src_node_type = params[src_node_type_index]
		dst_node_type_index = match_arguments(arg_names[2], caller_arguments)
		dst_node_type = params[dst_node_type_index]
		return record_relation(src_node_type, dst_node_type, edge_type)
	elif func_call.name.name == 'current_update_shst':
		arg_names = extract_function_arg_names(func_call)
		# Only the second argument is of interest
		if arg_names[1] == 'true':
			return current_update_shst(True)
		else:
			return current_update_shst(False)
	else:
		return None

def eval_assignment(assignment, caller_arguments, params):
	"""
	Evaluate a single assignment that directly generates a relation.
	"""
	if type(assignment.rvalue).__name__ == 'FuncCall':
		return eval_func_call(assignment.rvalue, caller_arguments, params)
	else:
		return None

def eval_declaration(declaration, caller_arguments, params):
	"""
	Evaluate a single declaration that directly generates a relation.
	"""
	if type(declaration.init).__name__ == 'FuncCall':
		return eval_func_call(declaration.init, caller_arguments, params)
	else:
		return None

def eval_return(statement, caller_arguments, params):
	"""
	Evaluate a single return statement that directly generates a relation.
	"""
	if type(statement.expr).__name__ == 'FuncCall':
		return eval_func_call(statement.expr, caller_arguments, params)
	else:
		return None

def eval_if_else(item, caller_arguments, params):
	"""
	Evaluate (nesting) if/else blocks.
	"""
	true_branch = item.iftrue

	if type(true_branch).__name__ == 'FuncCall':
		left = eval_func_call(true_branch, caller_arguments, params)
	elif type(true_branch).__name__ == 'Assignment':
		left = eval_assignment(true_branch, caller_arguments, params)
	elif type(true_branch).__name__ == 'Decl':
		left = eval_declaration(true_branch, caller_arguments, params)
	elif type(true_branch).__name__ == 'Return':
		left = eval_return(true_branch, caller_arguments, params)
	elif type(true_branch).__name__ == 'Compound':
		left = eval_function_body(true_branch, caller_arguments, params)
	else:
		left = None
    
	false_branch = item.iffalse
	if type(false_branch).__name__ == 'FuncCall':
		right = eval_func_call(false_branch, caller_arguments, params)
	elif type(false_branch).__name__ == 'Assignment':
		right = eval_assignment(false_branch, caller_arguments, params)
	elif type(false_branch).__name__ == 'Decl':
		right = eval_declaration(false_branch, caller_arguments, params)
	elif type(false_branch).__name__ == 'Return':
		right = eval_return(false_branch, caller_arguments, params)
	elif type(false_branch).__name__ == 'Compound':
		right = eval_function_body(false_branch, caller_arguments, params)
	elif type(false_branch).__name__ == 'If':   # else if case
		right = eval_if_else(false_branch, caller_arguments, params)
	else:
		right = None

	if left != None or right != None:
		return create_alternation_relation(left, right)
	else:
		return None

def eval_function_body(function_body, caller_arguments, params):
	"""
	Evaluate a Compound function body.
	"""
	# The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
	# The following goes through the declarations and statements in the function body
	relation = None
	for item in function_body.block_items:
		if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
			right = eval_func_call(item, caller_arguments, params)
			if right == None and relation == None:
				relation = None
			else:
				relation = create_group_relation(relation, right)
		elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
			right = eval_assignment(item, caller_arguments, params)
			if right == None and relation == None:
				relation = None
			else:
				relation = create_group_relation(relation, right)
		elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
			right = eval_declaration(item, caller_arguments, params)
			if right == None and relation == None:
				relation = None
			else:
				relation = create_group_relation(relation, right)
		elif type(item).__name__ == 'If':   # Case 4: if
			right = eval_if_else(item, caller_arguments, params)
			if right == None and relation == None:
				relation = None
			else:
				relation = create_group_relation(relation, right)
		elif type(item).__name__ == 'Return':	# Case 5: return with function call
			right = eval_return(item, caller_arguments, params)
			if right == None and relation == None:
				relation = None
			else:
				relation = create_group_relation(relation, right)
	return relation
###########################################################################################
def relation_with_four_args(function, rel, arg1, arg2, arg3):
	"""
	For relations: uses, generates
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	c = prov_to_type(arg3)

	function_decl = function.decl
	caller_arguments = caller_argument_names(function_decl)
	params = [relation, a, b, c]

	function_body = function.body
	return eval_function_body(function_body, caller_arguments, params)

def relation_with_three_args(function, rel, arg1, arg2):
	"""
	For relations: derives, informs, uses_two
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)

	function_decl = function.decl
	caller_arguments = caller_argument_names(function_decl)
	params = [relation, a, b]

	function_body = function.body
	return eval_function_body(function_body, caller_arguments, params)

def get_cred_provenance_to_relation():
	"""
	Edge for 'get_cred_provenance'.
	# TODO: automate this process.
	"""
	return create_edge('path', 'process_memory', relation_to_str('RL_NAMED_PROCESS'))

def inode_provenance_to_relation():
	"""
	Edge for 'inode_provenance', 'dentry_provenance', 'file_provenance', 'refresh_inode_provenance'.
	# TODO: automate this process.
	"""
	return create_edge('path', 'inode', relation_to_str('RL_NAMED'))

def provenance_record_address_to_relation():
	"""
	Edges for 'provenance_record_address'.
	# TODO: automate this process.
	"""
	return create_edge('address', 'inode', relation_to_str('RL_NAMED'))

def record_write_xattr_to_relation(rel):
	"""
	Edges for xattribute (record_write_xattr) relations.
	"""
	return record_write_xattr(rel)

def record_terminate_to_relation(rel, arg1):
	"""
	Edges for terminate (record_terminate) relation.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	return record_terminate(a, relation)

def record_read_xattr_to_relation():
	"""
	Edges for read xattribute relation.
	"""
	return record_read_xattr()

def provenance_packet_content_to_relation():
	"""
	Edges for package relation.
	# TODO: automate this process.
	"""
	return record_relation('packet_content', 'packet', relation_to_str('RL_PCK_CNT'))

def prov_record_args_to_relation():
	"""
	Edges for argument relations.
	# TODO: automate this process.
	"""
	record_arg_relation = record_relation('argv', 'process_memory', relation_to_str('RL_ARG'))
	record_env_relation = record_relation('envp', 'process_memory', relation_to_str('RL_ENV'))
	return create_group_relation(create_asterisk_relation(record_arg_relation), create_asterisk_relation(record_env_relation))
