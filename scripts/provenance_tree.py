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

# Functions that deal provenance
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
		print('\33[103m' + '[error][relation_to_str]: Unknown type: '+ str + '\033[0m')
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
	elif str == 'bprov':
		return 'mmaped_file'
	elif str == 'pckprov':
		return 'packet'
	else:
		print('\33[104m' + '[error][provenance_to_type]: Unknown provenance type: '+ str + '\033[0m')
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


# Some building block functions that generates RTM motif nodes and edges (NOT THE SAME AS TREE NODES)
# These functions returns a tuple (MotifNode, RTM Tree Node)
# because some functions actually return a new MotifNode object.
#####################################################################################################
### provenance.h
def alloc_provenance(node_type):
	"""
	A new MotifNode is created given the @node_type when 'alloc_provenance' (provenance.h) is called.

	Return:
	The second element in the returned tuple is None since no RTM tree node is generated in this function.

	Function signature: static __always_inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
	@node_type --> ntype

	"gfp" is ignored in our analysis.
	"""
	return MotifNode(provenance_to_type(node_type)), None

# The lowest level of function that generates RTM motif edges is "__write_relation"
### provenance_filter.h
def __filter_update_node(edge_type):
	"""
	For certain types of edge, calling update version makes no sense
	So we identify them so that we do not call "update_version" function.
	"""
	if edge_type == 'RL_VERSION_TASK' or edge_type == "RL_VERSION" or edge_type == 'RL_NAMED' or edge_type == 'RL_NAMED_PROCESS':
		return True
	else:
		return False

### provenance_record.h
def update_version(edge_type, motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "__update_version" (provenance_record.h) is called.
	A new MotifNode is created, which is the updated version of the @motif_node.
	A version edge between the new MotifNode and @motif_node is created.

	We must update the @motif_node_dict with the corresponding entry name (the key of @motif_node).
	This is appended to the value of the dictionary.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. prov_policy.should_compress_node
	2. filter_update_node(type)

	Function signature: static __always_inline int __update_version(const uint64_t type, prov_entry_t *prov)
	@edge_type --> type
	@motif_node --> prov
	"""
	if __filter_update_node(edge_type):
		return None

	if motif_node.mn_ty == 'task':
		new_motif_node = MotifNode(motif_node.mn_ty)
		motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION_TASK'))
	else:
		new_motif_node = MotifNode(motif_node.mn_ty)
		motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION'))
	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	else:
		print('\33[103m' + '[error][update_version]: Motif Node: '+ str(motif_node.mn_id) + ' of the type ' + str(motif_node.mn_ty) + ' do not have a key in Motif Node Dictionary. \033[0m')
	return create_leaf_node(motif_edge)

def record_relation(edge_type, from_node, to_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_relation" (provenance_record.h) is called.

	The following checks are ignored because we can easily decide CamFlow settings:
	1. prov_policy.should_compress_edge

	Function signature: static __always_inline int record_relation(const uint64_t type, prov_entry_t *from, prov_entry_t *to, const struct file *file, const uint64_t flags)
	@edge_type --> type
	@from_node --> from
	@to_node --> to

	"file" and "flags" are ignored in our analysis.
	"""
	rtm_tree_update_node = update_version(edge_type, to_node, motif_node_dict)

	dict_key = getKeyByValue(motif_node_dict, to_node)
	if dict_key:
		new_motif_edge = MotifEdge(from_node, getLastValueFromKey(motif_node_dict, dict_key), edge_type)
	else:	
		new_motif_edge = MotifEdge(from_node, to_node, edge_type)
	rtm_tree_leaf_node = create_leaf_node(new_motif_edge)

	# from_node now has outgoing edges
	from_node.mn_has_outgoing = True

	return create_group_node(rtm_tree_update_node, rtm_tree_leaf_node)

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

	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	else:
		print('\33[103m' + '[error][record_terminate]: Motif Node: '+ str(motif_node.mn_id) + ' of the type ' + str(motif_node.mn_ty) + ' do not have a key in Motif Node Dictionary. \033[0m')
	motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str(edge_type))
	return None, create_leaf_node(motif_edge)

def record_node_name(motif_node, force, motif_node_dict):
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

	"name" is ignored in our analysis.
	"""
	if motif_node.mn_has_name_recorded and not force:
		return None, None

	new_motif_node = MotifNode('path')
	if motif_node.mn_ty == 'task':
		rtm_tree_node = record_relation(relation_to_str('RL_NAMED_PROCESS'), new_motif_node, motif_node, motif_node_dict)
	else:
		rtm_tree_node = record_relation(relation_to_str('RL_NAMED'), new_motif_node, motif_node, motif_node_dict)
	# motif_node's name is now recorded
	motif_node.mn_has_name_recorded = True
	return None, rtm_tree_node

def record_kernel_link(motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_kernel_link" (provenance_record.h) is called.
	A new MotifNode is created for the machine "prov_machine" if it does not exist.
	The new MotifNode is a kernel entry in @motif_node_dict.
	The key value pair is (kernel, [MotifNode('machine'),...]).

	The following checks are ignored because we can easily decide CamFlow settings:
	1. provenance_is_recorded(prov_elt(node))

	Function signature: static inline int record_kernel_link(struct provenance *node)
	@motif_node --> node
	"""
	# We only record kernel node if it does not exist or if its kernel version is outdated
	if 'kernel' not in motif_node_dict or motif_node.mn_kernel_version < len(motif_node_dict['kernel']):
		new_motif_node = MotifNode('machine')
		if 'kernel' not in motif_node_dict:
			motif_node_dict['kernel'] = [new_motif_node]
		else:
			motif_node_dict['kernel'].append(new_motif_node)
		# update the node's kernel version
		motif_node.mn_kernel_version = len(motif_node_dict['kernel'])
		return record_relation(relation_to_str('RL_RAN_ON'), new_motif_node, motif_node, motif_node_dict)

def uses():
	#TODO

def uses_two(edge_type, entity_node, activity_node, motif_node_dict):
	#TODO

def generates(edge_type, activity_mem_node, activity_node, entity_node, motif_node_dict):
	#TODO

def derives():
	#TODO

def informs(edge_type, from_node, to_node, motif_node_dict):
	#TODO


def influences_kernel(edge_type, entity_node, activity_node, motif_node_dict):
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

	'file' is ignored in our analysis.
	"""
	if 'kernel' not in motif_node_dict:
		new_motif_node = MotifNode('machine')
		motif_node_dict['kernel'] = [new_motif_node]
	
	rtm_tree_load_node = record_relation(relation_to_str('RL_LOAD_FILE'), entity_node, activity_node, motif_node_dict)
	rtm_tree_machine_node = record_relation(relation_to_str(edge_type), activity_node, getLastValueFromKey(motif_node_dict, 'kernel'), motif_node_dict)

	return create_group_node(rtm_tree_load_node, rtm_tree_machine_node)

##### Functions: uses, uses_two, generates, derives, and informs will be handled through AST analysis on provenance_record.h

### provenance_task.h
def current_update_shst(cprov_node, read, motif_node_dict):
	"""
	RTM tree nodes for when "current_update_shst" (provenance_task.h) is called.
	
	Two new MotifNodes and a MotifEdge between them is created for mmap file.
	
	Function signature: int current_update_shst(struct provenance *cprov, bool read)
	@cprov_node --> cprov
	@read --> read
	"""
	new_path_motif_node = MotifNode('path')
	new_inode_motif_node = MotifNode('inode')
	motif_edge = MotifEdge(new_path_motif_node, new_inode_motif_node, relation_to_str('RL_NAMED'))

	if read:
		return create_group_node(create_leaf_node(motif_edge), create_asterisk_node(record_relation(new_inode_motif_node, cprov_node, relation_to_str('RL_SH_READ'), motif_node_dict)))
	else:
		return create_group_node(create_leaf_node(motif_edge), create_asterisk_node(record_relation(cprov_node, new_inode_motif_node, relation_to_str('RL_SH_WRITE'), motif_node_dict)))

def get_cred_provenance():
	#TODO
	"""
	RTM tree nodes for when 'get_cred_provenance' (provenance_task.h) is called.
	This function returns a new MotifNode of type process_memory.

	Function signature: static inline struct provenance *get_cred_provenance(void)
	"""
	# new_process_memory_motif_node = MotifNode('process_memory')
	# task_name_rtm_node = record_task_name(new_process_memory_motif_node)
	# kernel_link_rtm_node = record_kernel_link(new_process_memory_motif_node)
	
	# new_path_motif_node = MotifNode('path')
	# new_process_memory_motif_node = MotifNode('process_memory')
	# process_motif_edge = MotifEdge(new_path_motif_node, new_process_memory_motif_node, relation_to_str('RL_NAMED_PROCESS'))
	# process_rtm_node = create_leaf_node(process_motif_edge)
	
	# new_machine_node = MotifNode('machine')
	# machine_motif_edge = MotifEdge(new_machine_node, new_process_memory_motif_node, relation_to_str('RL_RAN_ON'))
	# machine_rtm_node = create_leaf_node(machine_motif_edge)
	# return new_process_memory_motif_node, create_group_node(task_name_rtm_node, kernel_link_rtm_node)


def get_task_provenance():
	"""
	A new MotifNode is created of type 'task' when 'get_task_provenance' (provenance_task.h) is called.

	Return:
	The second element in the returned tuple is None since no RTM tree node is generated in this function.

	Function signature: static inline struct provenance *get_task_provenance( void )
	"""
	return MotifNode('task'), None


### provenance_inode.h
def update_inode_type(motif_node, motif_node_dict):
	"""
	RTM tree nodes for when "update_inode_type" (provenance_inode.h) is called.
	Update inode type (except "task" inode).
	Question mark relation because whether the inode type is updated is unknown statically, depending on runtime "mode" value. 

	Function signature: static inline void update_inode_type(uint16_t mode, struct provenance *prov)
	@motif_node -> prov 
	"""
	new_motif_node = MotifNode(motif_node.mn_ty)
	dict_key = getKeyByValue(motif_node_dict, motif_node)
	if dict_key:
		motif_node_dict[dict_key].append(new_motif_node)
	motif_edge = MotifEdge(motif_node, new_motif_node, relation_to_str('RL_VERSION'))
	return create_question_mark_node(create_leaf_node(motif_edge))


def record_write_xattr(iprov_node, tprov_node, cprov_node, edge_type, motif_node_dict):
	"""
	RTM tree nodes for when "record_write_xattr" (provenance_inode.h) is called.
	A new MotifNode is created for 'xattr' type.

	Function signature: int record_write_xattr(uint64_t type,
												struct provenance *iprov,
												struct provenance *tprov,
												struct provenance *cprov,
												const char *name,
												const void *value,
												size_t size,
												const uint64_t flags)
	@iprov_node --> iprov
	@tprov_node --> tprov
	@cprov_node --> cprov
	@edge_type --> type
	"""
	relation = relation_to_str(edge_type)
	proc_read_rtm_node = record_relation(cprov_node, tprov_node, relation_to_str('RL_PROC_READ'), motif_node_dict)

	new_motif_node = MotifNode('xattr')
	edge_type_rtm_node = record_relation(tprov_node, new_motif_node, relation, motif_node_dict)
	
	group_rtm_node = create_group_node(proc_read_rtm_node, edge_type_rtm_node)
	if relation == 'setxattr':
		return create_group_node(group_rtm_node, record_relation(new_motif_node, iprov_node, relation_to_str('RL_SETXATTR_INODE'), motif_node_dict))
	else:
		return create_group_node(group_rtm_node, record_relation(new_motif_node, iprov_node, relation_to_str('RL_RMVXATTR_INODE'), motif_node_dict))

def record_read_xattr(cprov_node, tprov_node, iprov_node, motif_node_dict):
	"""
	RTM tree nodes for when "record_read_xattr" (provenance_inode.h) is called.
	A new MotifNode is created for 'xattr' type.

	Function signature: int record_read_xattr(struct provenance *cprov,
												struct provenance *tprov,
												struct provenance *iprov,
												const char *name)
	@cprov_node --> cprov
	@tprov_node --> tprov
	@iprov_node --> iprov
	"""
	new_motif_node = MotifNode('xattr')
	getxattr_inode_rtm_node = record_relation(iprov_node, new_motif_node, relation_to_str('RL_GETXATTR_INODE'), motif_node_dict)
	getxattr_rtm_node = record_relation(new_motif_node, tprov_node, relation_to_str('RL_GETXATTR'), motif_node_dict)
	proc_write_rtm_node = record_relation(tprov_node, cprov_node, relation_to_str('RL_PROC_WRITE'), motif_node_dict)
	return create_group_node(create_group_node(getxattr_inode_rtm_node, getxattr_rtm_node), proc_write_rtm_node)
########################################

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
	Extract arguments in subroutine function calls.
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

def eval_func_call(func_call, caller_arguments, params, motif_node_dict):
	"""
	Evaluate a single function call that directly generates relations.
	"""
	if func_call.name.name == 'record_relation':
		arg_names = extract_function_arg_names(func_call)
		# Only the first three arguments are of interest
		edge_type_index = match_arguments(arg_names[0], caller_arguments)
		if edge_type_index == None:	# edge type is hard-coded in `record_relation` subroutine.
			edge_type = relation_to_str(str(arg_names[0]))
		else:
			edge_type = params[edge_type_index]
		from_node_index = match_arguments(arg_names[1], caller_arguments)
		from_node = params[from_node_index]
		from_key = getKeyByValue(motif_node_dict, from_node)
		if from_key:
			from_node = getLastValueFromKey(motif_node_dict, from_key)
		to_node_index = match_arguments(arg_names[2], caller_arguments)
		to_node = params[to_node_index]
		to_key = getKeyByValue(motif_node_dict, to_node)
		if to_key:
			to_node = getLastValueFromKey(motif_node_dict, to_key)
		return record_relation(from_node, to_node, edge_type, motif_node_dict)
	elif func_call.name.name == 'current_update_shst':
		arg_names = extract_function_arg_names(func_call)
		cprov_index = match_arguments(arg_names[0], caller_arguments)
		cprov_node = params[cprov_index]
		cprov_key = getKeyByValue(motif_node_dict, cprov_node)
		if cprov_key:
			cprov_node = getLastValueFromKey(motif_node_dict, cprov_key)
		if arg_names[1] == 'true':
			return current_update_shst(cprov_node, True, motif_node_dict)
		else:
			return current_update_shst(cprov_node, False, motif_node_dict)
	else:
		return None

def eval_assignment(assignment, caller_arguments, params, motif_node_dict):
	"""
	Evaluate a single assignment that directly generates a relation.
	"""
	if type(assignment.rvalue).__name__ == 'FuncCall':
		return eval_func_call(assignment.rvalue, caller_arguments, params, motif_node_dict)
	else:
		return None

def eval_declaration(declaration, caller_arguments, params, motif_node_dict):
	"""
	Evaluate a single declaration that directly generates a relation.
	"""
	if type(declaration.init).__name__ == 'FuncCall':
		return eval_func_call(declaration.init, caller_arguments, params, motif_node_dict)
	else:
		return None

def eval_return(statement, caller_arguments, params, motif_node_dict):
	"""
	Evaluate a single return statement that directly generates a relation.
	"""
	if type(statement.expr).__name__ == 'FuncCall':
		return eval_func_call(statement.expr, caller_arguments, params, motif_node_dict)
	else:
		return None

def eval_if_else(item, caller_arguments, params, motif_node_dict):
	"""
	Evaluate (nesting) if/else blocks.
	"""
	true_branch = item.iftrue
	if type(true_branch).__name__ == 'FuncCall':
		left = eval_func_call(true_branch, caller_arguments, params, motif_node_dict)
	elif type(true_branch).__name__ == 'Assignment':
		left = eval_assignment(true_branch, caller_arguments, params, motif_node_dict)
	elif type(true_branch).__name__ == 'Decl':
		left = eval_declaration(true_branch, caller_arguments, params, motif_node_dict)
	elif type(true_branch).__name__ == 'Return':
		left = eval_return(true_branch, caller_arguments, params, motif_node_dict)
	elif type(true_branch).__name__ == 'Compound':
		left = eval_function_body(true_branch, caller_arguments, params, motif_node_dict)
	else:
		left = None
    
	false_branch = item.iffalse
	if type(false_branch).__name__ == 'FuncCall':
		right = eval_func_call(false_branch, caller_arguments, params, motif_node_dict)
	elif type(false_branch).__name__ == 'Assignment':
		right = eval_assignment(false_branch, caller_arguments, params, motif_node_dict)
	elif type(false_branch).__name__ == 'Decl':
		right = eval_declaration(false_branch, caller_arguments, params, motif_node_dict)
	elif type(false_branch).__name__ == 'Return':
		right = eval_return(false_branch, caller_arguments, params, motif_node_dict)
	elif type(false_branch).__name__ == 'Compound':
		right = eval_function_body(false_branch, caller_arguments, params, motif_node_dict)
	elif type(false_branch).__name__ == 'If':   # else if case
		right = eval_if_else(false_branch, caller_arguments, params, motif_node_dict)
	else:
		right = None

	if left != None or right != None:
		return create_alternation_node(left, right)
	else:
		return None

def eval_function_body(function_body, caller_arguments, params, motif_node_dict):
	"""
	Evaluate a Compound function body.
	"""
	# The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
	# The following goes through the declarations and statements in the function body
	relation = None
	for item in function_body.block_items:
		if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
			right = eval_func_call(item, caller_arguments, params, motif_node_dict)
			if right == None and relation == None:
				relation = None
			elif right != None:
				relation = create_group_node(relation, right)
		elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
			right = eval_assignment(item, caller_arguments, params, motif_node_dict)
			if right == None and relation == None:
				relation = None
			elif right != None:
				relation = create_group_node(relation, right)
		elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
			right = eval_declaration(item, caller_arguments, params, motif_node_dict)
			if right == None and relation == None:
				relation = None
			elif right != None:
				relation = create_group_node(relation, right)
		elif type(item).__name__ == 'If':   # Case 4: if
			right = eval_if_else(item, caller_arguments, params, motif_node_dict)
			if right == None and relation == None:
				relation = None
			elif right != None:
				relation = create_group_node(relation, right)
		elif type(item).__name__ == 'Return':	# Case 5: return with function call
			right = eval_return(item, caller_arguments, params, motif_node_dict)
			if right == None and relation == None:
				relation = None
			elif right != None:
				relation = create_group_node(relation, right)
	return relation

def relation_with_four_args(function, rel, arg1, arg2, arg3, motif_node_dict):
	"""
	For relations: uses, generates
	@rel (edge_type): from type.c
	@arg1, @arg2, @arg3: MotifNodes from hooks.c
	"""
	relation = relation_to_str(rel)

	function_decl = function.decl
	caller_arguments = caller_argument_names(function_decl)
	params = [relation, arg1, arg2, arg3]

	function_body = function.body
	return eval_function_body(function_body, caller_arguments, params, motif_node_dict)

def relation_with_three_args(function, rel, arg1, arg2, motif_node_dict):
	"""
	For relations: derives, informs, uses_two
	@rel (edge_type): from type.c
	@arg1, @arg2: MotifNodes from hooks.c
	"""
	relation = relation_to_str(rel)
	
	function_decl = function.decl
	caller_arguments = caller_argument_names(function_decl)
	params = [relation, arg1, arg2]

	function_body = function.body
	return eval_function_body(function_body, caller_arguments, params, motif_node_dict)

def inode_provenance_to_relation():
	"""
	RTM tree leaf node for when 'inode_provenance', 'dentry_provenance', 'file_provenance', 'refresh_inode_provenance' (provenance_inode.h) are called.
	Two new MotifNodes and a MotifEdge between them is created for inode.
	This function also returns the new inode MotifNode.

	Function signature:
	static __always_inline struct provenance *inode_provenance(struct inode *inode, bool may_sleep)
	static __always_inline struct provenance *dentry_provenance(struct dentry *dentry, bool may_sleep)
	static __always_inline struct provenance *file_provenance(struct file *file, bool may_sleep)
	static inline void refresh_inode_provenance(struct inode *inode)

	Precondition:
	* In hooks that call them, we assume it is always the first time an "inode" typed node is created.
	"""
	new_path_motif_node = MotifNode('path')
	new_inode_motif_node = MotifNode('inode')
	motif_edge = MotifEdge(new_path_motif_node, new_inode_motif_node, relation_to_str('RL_NAMED'))

	return new_inode_motif_node, create_leaf_node(motif_edge)

def provenance_record_address_to_relation(prov_node, motif_node_dict):
	"""
	RTM tree nodes for when 'provenance_record_address' (provenance_net.h) is called.
	A new MotifNode is created for 'address' type.

	Function signature: static __always_inline int provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
	@prov_node --> prov
	"""
	new_address_motif_node = MotifNode('address')
	return record_relation(new_address_motif_node, prov_node, relation_to_str('RL_NAMED'), motif_node_dict)

def provenance_packet_content_to_relation(prov_node, motif_node_dict):
	"""
	RTM tree node(s) for when 'provenance_packet_content' (provenance_net.h) is called.
	A new MotifNode and a MotifEdge between them are created for packet.
	
	Function signature: static __always_inline void provenance_packet_content(struct sk_buff *skb,
																				struct provenance *pckprov)
	@prov_node --> pckprov
	"""
	new_packet_content_motif_node = MotifNode('packet_content')
	return record_relation(new_packet_content_motif_node, prov_node, relation_to_str('RL_PCK_CNT'), motif_node_dict)

def prov_record_args_to_relation(prov_node, motif_node_dict):
	"""
	RTM tree node(s) for when 'prov_record_args' (provenance_task.h) is called.
	Two new MotifNodes are created for arg and env.

	Function signature: prov_record_args(struct provenance *prov,
											struct linux_binprm *bprm)
	@prov_node --> prov
	"""
	new_argv_motif_node = MotifNode('argv')
	new_envp_motif_node = MotifNode('envp')
	rtm_argv_node = record_relation(new_argv_motif_node, prov_node, relation_to_str('RL_ARG'), motif_node_dict)
	rtm_envp_node = record_relation(new_envp_motif_node, prov_node, relation_to_str('RL_ENV'), motif_node_dict)
	return create_group_node(create_asterisk_node(rtm_argv_node), create_asterisk_node(rtm_envp_node))
#####################################################################################################
