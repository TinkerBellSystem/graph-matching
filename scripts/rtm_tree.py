# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function
import struct
import random
from graph_tree import *

class MotifNode():
	"""
	Each node (identified by @mn_id) in the RTM has attributes: 
	* mn_ty: type of the node in the motif.
	* mn_has_outgoing: whether the node has outgoing edges (default to False when it is initialized)
	* mn_has_name_recorded: whether the node has its path name recorded already (default to False when it is initialized) 
	* mn_kernel_version: the kernel version associated with the node (default to 0)
	* mn_is_initialized: if the node is initialized (default to False)
	"""
	node_id = 0	# Unique motif node ID for each new node.

	def __init__(self, mn_ty):
		self.mn_id = MotifNode.node_id
		self.mn_ty = mn_ty
		self.mn_has_outgoing = False
		self.mn_has_name_recorded = False
		self.mn_kernel_version = 0
		self.mn_is_initialized = False
		MotifNode.node_id += 1

	@property
	def mn_id(self):
		return self.__mn_id

	@property
	def mn_ty(self):
		return self.__mn_ty

	@property
	def mn_has_outgoing(self):
		return self.__mn_has_outgoing

	@property
	def mn_has_name_recorded(self):
		return self.__mn_has_name_recorded

	@property
	def mn_is_initialized(self):
		return self.__mn_is_initialized

	def __eq__(self, other):
		return self.mn_id == other.mn_id and self.mn_ty == other.mn_ty

class MotifEdge():
	"""
	Each edge in the RTM has attributes: 
	* src_node: source MotifNode of the egde
	* dst_node: destination MotifNode of the edge
	* me_ty: type of the edge in the motif.
	"""
	def __init__(self, src_node, dst_node, me_ty):
		self.src_node = src_node
		self.dst_node = dst_node
		self.me_ty = me_ty

	@property
	def src_node(self):
		return self.__src_node

	@property
	def dst_node(self):
		return self.__dst_node

	@property
	def me_ty(self):
		return self.__me_ty

	def print_edge(self):
		print(str(self.src_node.mn_id) + "-" + self.me_ty + "->" + str(self.dst_node.mn_id) + '   ', end='')

class RTMTreeNode():
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
	"""
	nid = 0	# Unique node ID for visualization.

	def __init__(self, value):
		"""
		Constructor to create a node.
		@left, @right: a MotifEdge (i.e., leaf node), or an internal node
		@value: regular expression operator or a MotifEdge

		In the case of a leaf node: @left, @right are None
		In the case of a unary internal node, @right is "None". 
		"""
		self.left = None
		self.right = None
		self.value = value
		self.nid = RTMTreeNode.nid
		RTMTreeNode.nid += 1

	@property
	def left(self):
		return self.__left

	@property
	def right(self):
		return self.__right

	@property
	def value(self):
		return self.__value

	def findLeftMostNode(self):
		"""
		Find left most (leaf) node.
		"""
		node = self
		while node.left != None:
			node = node.left
		return node

def is_operator(c):
	if c == '*' or c == '?' or c == '.' or c == '|':
		return True
	else:
		return False 

def inorder_traversal(node):
	"""
	Inorder traversal follows the sequence of the operation.
	"""
	if node is not None: 
		inorder_traversal(node.left) 
		if is_operator(node.value):
			print(node.value)
		else:
			node.value.print_edge()
		inorder_traversal(node.right)

def _is_all_None(l):
	is_all_None = True
	for e in l:
		if e != None:
			is_all_None = False
	return is_all_None

def bf_traversal(root):
	"""
	Print the binary RTM tree using breadth-first search.
	"""
	cur_level = [root]
	nextlevel = []
	while not _is_all_None(cur_level):
		for node in cur_level:
			if node is None:
				print("None   ", end='')
				continue
			if is_operator(node.value):
				print(node.value + '   ', end='')
			else:
				node.value.print_edge()
			if node.left: 
				nextlevel.append(node.left)
			else:
				nextlevel.append(None)
			if node.right: 
				nextlevel.append(node.right)
			else:
				nextlevel.append(None)
		print("\n")
		cur_level = nextlevel
		nextlevel = []

def visualize_rtm_tree(node, graph):
	"""
	Visualize RTM tree using Graphviz.
	@node is the node of the RTMTree
	@graph is the Graphviz graph.
	"""
	if node is None:
		return
	if is_operator(node.value):
		graph.add_entity(str(node.nid), True, node.value)
	else:
		value = str(node.value.src_node.mn_id) + "/" + str(node.value.src_node.mn_ty) + "-" + node.value.me_ty + "->" + str(node.value.dst_node.mn_id) + "/" + str(node.value.dst_node.mn_ty)
		graph.add_entity(str(node.nid), False, value)
	if node.left:
		graph.add_edge(str(node.nid), str(node.left.nid))
		visualize_rtm_tree(node.left, graph)
	if node.right: 
		graph.add_edge(str(node.nid), str(node.right.nid))
		visualize_rtm_tree(node.right, graph)





