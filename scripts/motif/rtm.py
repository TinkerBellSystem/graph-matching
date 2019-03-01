# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function

class MotifNode():
	"""A node in the motif.

	Attributes:
	mn_id 				 -- unique ID of the node
	mn_ty 				 -- type of the node in the motif
	mn_has_outgoing 	 -- whether the node has outgoing edges (default to False when it is initialized)
	mn_has_name_recorded -- whether the node has its path name recorded already (default to False when it is initialized) 
	mn_kernel_version 	 -- the kernel version associated with the node (default to 0)
	mn_is_initialized 	 -- if the node is initialized (default to False)
	"""
	node_id = 0  # unique motif node ID for each new node

	def __init__(self, mn_ty):
		self.mn_id = MotifNode.node_id
		self.mn_ty = mn_ty
		MotifNode.node_id += 1

	@property
	def mn_id(self):
		return self.__mn_id

	@property
	def mn_ty(self):
		return self.__mn_ty

	def __eq__(self, other):
		return self.mn_id == other.mn_id and self.mn_ty == other.mn_ty


def create_motif_node(node_type):
	"""If a motif node is never explicitly defined by 
	e.g., alloc_provenance() or get_cred_provenance() function calls,
	we will create a new motif node on the fly.

	Arguments:
	node_type -- type of the motif node (after translated by provenance_vertex_type function in provtype.py)
	"""
	return MotifNode(node_type)


class MotifEdge:
	"""An edge in the motif.

	Attributes:
	src_node -- source MotifNode of the egde
	dst_node -- destination MotifNode of the edge
	me_ty 	 -- type of the edge in the motif
	"""
	def __init__(self, src_node, dst_node, me_ty):
		self.src_node = src_node
		self.dst_node = dst_node
		self.me_ty = me_ty

	def __repr__(self):
		return '[' + repr(self.src_node.mn_id) + '](' + repr(self.src_node.mn_ty) + ')-(' + repr(self.me_ty) + ')>[' + repr(self.dst_node.mn_id) + '](' + repr(self.dst_node.mn_ty) + ')'

	@property
	def src_node(self):
		return self.__src_node

	@property
	def dst_node(self):
		return self.__dst_node

	@property
	def me_ty(self):
		return self.__me_ty

	def update_src_node(self, new_id):
		self.src_node.mn_id = new_id

	def update_dst_node(self, new_id):
		self.dst_node.mn_id = new_id


class RTMTreeNode:
	"""
	A binary tree that represents the regular temporal motif (RTM) with regular expression operators in the internal tree nodes and MotifEdges in the leaf nodes.

	Regular expression operators are:
	'*': zero or more times (i.e., an edge appears zero or more times)
	'+': one or more times (i.e., an edge appears one or more times)
	'?': zero or once (i.e., an edge appears zero or once)
	'{m, n}': m to n times (i.e., an edge appears m to n times)
	'{m, }': m or more times (i.e., an edge appears at least m times)
	'{m}': exactly m times (i.e., an edge appears exactly m times)
	'.': capturing group (i.e., a group of two edges appear together)
	'|': alternation (i.e., either edge A or edge B)

	A leaf node consists of:
	* A MotifEdge
	
	A unary internal node consists of:
	* Left child: A node (i.e., an internal operator node or a leaf node)
	* Right child: None
	* Value: A unary regular expression operator ('*', '+', '?', '{m, n}', '{m, }', '{m}')

	A binary internal node consists of:
	* Left and right child: a node (i.e., an internal operator node or a leaf node)
	* Value: A binary regular expression operator ('.', '|')

	Attributes:
	left  -- left child of the node
	right -- right child of the node
	value -- value of the node
	nid   -- tree node ID
	"""
	unid = 0	 # unique node ID for visualization

	def __init__(self, value):
		"""Constructor to create a node.
		left, right -- a MotifEdge (i.e., leaf node), or an internal node
		value 		-- regular expression operator or a MotifEdge

		In the case of a leaf node: left, right are None
		In the case of a unary internal node: right is None. 
		"""
		self.left = None
		self.right = None
		self.value = value
		self.nid = RTMTreeNode.unid
		RTMTreeNode.update()

	@property
	def left(self):
		return self.__left

	@property
	def right(self):
		return self.__right

	@property
	def value(self):
		return self.__value

	@property
	def nid(self):
		return self.__nid

	def update_value(self, new_value):
		self.value = new_value

	@classmethod
	def update(cls):
		cls.unid += 1


def create_leaf_node(motif_edge):
	"""This function creates a leaf node.
	The function that generates this leaf node at the lowest level is "__write_relation".
	'FuncCall', 'Assignment', and 'Decl' type with "__write_relation" can result in a leaf node.

	Arguments:
	motif_edge -- value of the leaf RTMTree node
	"""
	return RTMTreeNode(motif_edge)


def create_asterisk_node(left):
	"""This function creates a unary "*" internal node.
	Shared memory read/write can result in this node.
	
	Arguments:
	left -- a leaf node or an internal node
	""" 
	asterisk_node = RTMTreeNode('*')
	asterisk_node.left = left
	return asterisk_node


def create_question_mark_node(left):
	"""This function creates a unary "?" internal node.
	version updates can result in this question mark relation.
	
	Arguments:
	left -- a leaf node or an internal node

	""" 
	question_mark_node = RTMTreeNode('?')
	question_mark_node.left = left
	return question_mark_node


def create_group_node(left, right):
	"""This function creates a binary "." internal node.
	Compound block can result in this group relation.
	Note that None could also be an alternative in this case for either left and right, but not both.

	Arguments:
	left  -- a leaf node or internal node
	right -- a leaf node or internal node
	"""
	group_node = RTMTreeNode('.')
	group_node.left = left
	group_node.right = right
	return group_node


def create_alternation_node(left, right):
	"""This function creates a binary "|" internal node.
	"if/elif/else" block can result in this alternation relation.
	Note that "None" could also be an alternative in this case for either left and right, but not both.
	
	Arguments:
	left  -- a leaf node or internal node
	right -- a leaf node or internal node
	"""
	alternation_node = RTMTreeNode('|')
	alternation_node.left = left
	alternation_node.right = right
	return alternation_node
