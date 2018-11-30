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

class MotifNode():
	"""
	Each node (identified by @mn_id) in the RTM has attributes: 
	* mn_ty: type of the node in the motif.
	"""
	node_id = 0	# Unique motif node ID for each new node.

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
		print(str(self.src_node.mn_id) + "-" + self.me_ty + "->" + str(self.dst_node.mn_id))

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
	if node is not None: 
		inorder_traversal(node.left) 
		if is_operator(node.value):
			print(node.value)
		else:
			node.value.print_edge()
		inorder_traversal(node.right) 




