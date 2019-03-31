# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018-2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import re


def provenance_relation(type_def_file_path):
	"""Returns a mapping between CamFlow's provenance relation definitions and its relation name strings.
	For example, "RL_STR_READ" --> "read".
	This function goes through the definition code once (which is written in "type.c") to retrieve all relevant information.

	Arguments:
	type_def_file_path -- the file path that contains the relation definition code

	Returns:
	a mapping between CamFlow's provenance relation definitions and the corresponding relation name strings
	"""
	r_map = dict()
	with open(type_def_file_path, 'r') as f:
		for line in f:
			# Match the lines in the file that contains relevant relation types.
			matched = re.match(r"\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*\"(\w+)\"\s*;\s*\/\/\s*([\w\s]+)", line.strip())
			if matched is not None:	# Find the right lines
				relation = 'RL_' + matched.group(1)
				r_map[relation] = matched.group(2)
	f.close()
	return r_map


def match_relation(r_map, rl_type):
	"""Matches a CamFlow's provenance relation definition to its relation name string.

	Arguments:
	r_map 	-- a map from CamFlow's provenance relation definitions to the corresponding relation name strings
	rl_type -- a relation definition type to map from

	Returns:
	the mapped relation name string, if any. Raise exception if no such a key.
	"""
	try:
		return r_map[rl_type]
	except Exception as e:
		print('\x1b[6;30;41m[x]\x1b[0m [match_relation]: Unknown relation type {}'.format(rl_type))
		raise ValueError(repr(e))


def provenance_vertex_type(v_name):
	"""Match a provenance vertex variable name to its corresponding vertex type.
		
	Arguments:
	v_name -- the name of the vertex's variable

	#TODO:
	1. May require necessary code change for easy mapping?
	2. Can we identify specific inode type based on the name?
	"""
	if v_name == 'cprov' \
		or v_name =='nprov' \
		or v_name == 'old_prov' \
		or v_name == 'pprov' \
		or v_name == 'ENT_PROC':
		return 'process_memory'
	elif v_name == 'tprov' \
		or v_name == 'ntprov' \
		or v_name == 'ACT_TASK':
		return 'task'
	elif v_name == 'iprov' \
		or v_name == 'iprova' \
		or v_name == 'iprovb' \
		or v_name == 'niprov' \
		or v_name == 'inprov' \
		or v_name == 'outprov' \
		or v_name == 'oprov' \
		or v_name == 'ENT_INODE_UNKNOWN':
		return 'inode'
	elif v_name == 'ENT_PATH':
		return 'path'
	elif v_name == 'mprov' or v_name == 'ENT_MSG':
		return 'msg'
	elif v_name == 'sprov' or v_name == 'ENT_SHM':
		return 'shm'
	elif v_name == 'dprov':
		return 'directory'
	elif v_name == 'iattrprov' or v_name == 'ENT_IATTR':
		return 'iattr'
	elif v_name == 'bprov' or v_name == 'ENT_INODE_MMAP':
		return 'mmaped_file'
	elif v_name == 'pckprov':
		return 'packet'
	elif v_name == 'ENT_ARG':
		return 'argv'
	elif v_name == 'ENT_ENV':
		return 'env'
	elif v_name == 'ENT_XATTR':
		return 'xattr'
	elif v_name == 'ENT_ADDR':
		return 'address'
	elif v_name == 'ENT_SBLCK' or v_name == 'sbprov':
		return 'sb'
	elif v_name == 'ENT_PCKCNT':
		return 'pckcnt'
	else:
		print('\x1b[6;30;41m[x]\x1b[0m [provenance_vertex_type]: Unknown vertex type {} '.format(v_name))
		raise ValueError('unknown vertex type')
