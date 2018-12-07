# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

def getKeyByValue(node_dict, node):
	keys = list()	# Should have exactly one element. 
	items = node_dict.items()
	for item in items:
		for n in item[1]:
			if n == node:
				keys.append(item[0])
	if len(keys) > 1:
		print('\33[101m' + '[error]: The node with ID: '+ node.mn_id + ' has more than one name. \033[0m')
		exit(1)
	elif len(keys) == 0:
		return None
	else:
		return keys[0]

def getLastValueFromKey(node_dict, key):
	if key not in node_dict or len(node_dict[key]) == 0:
		print('\33[101m' + '[error]: The name: '+ key + ' has no associated nodes. \033[0m')
		exit(1)
	else:
		return node_dict[key][-1]
