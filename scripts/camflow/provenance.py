# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

import re

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

def version(e):
	"""
	Edges for version relations.
	"""
	if e == 'task':
		return 'task-' + relation_to_str('RL_VERSION_TASK') + '->task'
	else:
		return e + '-' + relation_to_str('RL_VERSION') + '->' + e

def uses_to_relation(rel, arg1, arg2, arg3):
	"""
	Edges for use relation.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	c = prov_to_type(arg3)
	return a + '-' + relation + '->' + b + ',' + b + '-' + relation_to_str('RL_PROC_WRITE') + '->' + c + ',' + version(b) + ',' + version(c) + ',process_memory-' + relation_to_str('RL_SH_WRITE')+'->inode' +','+ version('inode')

def generates_to_relation(rel, arg1, arg2, arg3):
	"""
	Edges for generates relations.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	c = prov_to_type(arg3)
	return a + '-' + relation_to_str('RL_PROC_READ') + '->' + b + ',' + b + '-' + relation + '->' + c + ',' + version(b) + ',' + version(c) + ',inode-'+ relation_to_str('RL_SH_READ') + '->process_memory' + ',' + version('process_memory')

def derives_to_relation(rel, arg1, arg2):
	"""
	Edges for derives relation.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	return a + '-' + relation + '->' + b + ',' + version(b)

def informs_to_relation(rel, arg1, arg2):
	"""
	Edges for informs relations.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	return a + '-' + relation + '->' + b + ',' + version(b)

def uses_two_to_relation(rel, arg1, arg2):
	"""
	Edges for uses(2) relations.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	b = prov_to_type(arg2)
	return a + '-' + relation + '->' + b + ',' + version(b)

def get_cred_provenance_to_relation():
	"""
	Edge for RL_NAMED_PROCESS.
	"""
	return 'path-' + relation_to_str('RL_NAMED_PROCESS') + '->process_memory'

def inode_provenance_to_relation():
	"""
	Edge for RL_NAMED of path.
	"""
	return 'path-' + relation_to_str('RL_NAMED') + '->inode'

def provenance_record_address_to_relation():
	"""
	Edges for RL_NAMED of address.
	"""
	return 'address-' + relation_to_str('RL_NAMED') + '->inode'

def record_write_xattr_to_relation(rel):
	"""
	Edges for xattribute (record_write_xattr) relations.
	"""
	relation = relation_to_str(rel)
	if relation == 'setxattr':
		return 'process_memory-' + relation_to_str('RL_PROC_READ') + '->task,task-' + relation + '->xattr,xattr-' + relation_to_str('RL_SETXATTR_INODE') + '->inode' + ',' + version('task') + ',' + version('inode')
	else:
		return 'process_memory-' + relation_to_str('RL_PROC_READ') + '->task,task-'+ relation + '->xattr,xattr-' + relation_to_str('RL_RMVXATTR_INODE') + '->inode' + ',' + version('task') + ',' + version('inode')

def record_terminate_to_relation(rel, arg1):
	"""
	Edges for terminate (record_terminate) relation.
	"""
	relation = relation_to_str(rel)
	a = prov_to_type(arg1)
	return a + '-' + relation + '->' + a

def record_read_xattr_to_relation():
	"""
	Edges for read xattribute relation.
	"""
	return 'inode-' + relation_to_str('RL_GETXATTR_INODE') + '->xattr,xattr-' + relation_to_str('RL_GETXATTR') + '->task,task-' + relation_to_str('RL_PROC_WRITE') + '->process_memory' + ',' + version('task') + ',' + version('process_memory')

def provenance_packet_content_to_relation():
	"""
	Edges for package relation.
	"""
	return 'packet_content-' + relation_to_str('RL_PCK_CNT') + '->packet'

def prov_record_args_to_relation():
	"""
	Edges for argument relations.
	"""
	return 'argv-' + relation_to_str('RL_ARG') + '->process_memory,envp-' + relation_to_str('RL_ENV')+'->process_memory'

