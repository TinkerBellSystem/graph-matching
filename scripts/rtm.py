# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

class MotifNode():
	"""
	Each node in the RTM has attributes: 
	* mn_type: type of the node in the motif.
	"""
	def __init__(self, mn_type):
		self.mn_type = mn_type

	@property
	def mn_type(self):
		return self.__mn_type

class MotifEdge():
	"""
	Each edge in the RTM has attributes: 
	* src_node: source MotifNode of the egde
	* dst_node: destination MotifNode of the edge
	* me_type: type of the edge in the motif.
	"""
	def __init__(self, src_node, dst_node, me_type):
		self.src_node = src_node
		self.dst_node = dst_node
		self.me_type = me_type

	@property
	def src_node(self):
		return self.__src_node

	@property
	def dst_node(self):
		return self.__dst_node

	@property
	def me_type(self):
		return self.__me_type

class Relation():
	"""
	Each relation represents a subset of edges in the regular temporal motif (RTM) that must be defined together, either with or without regular expression operators.

	Regular expression operators are:
	'*': zero or more times (i.e., an edge appears zero or more times)
	'+': one or more times (i.e., an edge appears one or more times)
	'?': zero or once (i.e., an edge appears zero or once)
	'{m, n}': m to n times (i.e., an edge appears m to n times)
	'{m, }': m or more times (i.e., an edge appears at least m times)
	'{m}': exactly m times (i.e., an edge appears exactly m times)
	'(...)': capturing group (i.e., a group of two edges appear together)
	'|': alternation (i.e., either edge A or edge B)

	A singular relation consists of:
	* An edge
	
	A unary relation consists of:
	* A relation (singular, unary, or binary)
	* A unary regular expression operator ('*', '+', '?', '{m, n}', '{m, }', '{m}')

	A binary relation consists of:
	* Two relations (singular, unary, or binary)
	* A binary regular expression operator ('(...)', '|')

	Note that higher order relations can be built upon singular/unary/binary relations.
	For example, given edges A, B, C, we have equivalently (A, B, C) = (A, (B, C)).
	"""
	def __init__(self, left, right, op):
		"""
		left, right: an edge (MotifEdge), or a relation (Relation)
		op: regular expression operator

		In the case of singular relation, @right and @op are both "None".
		In the case of unary relation, @right is "None". 
		"""
		self.left = left
		self.right = right
		self.op = op

	@property
	def left(self):
		return self.__dleft

	@property
	def right(self):
		return self.__right

	@property
	def op(self):
		return self.__op

	def validate(self):
		valid_left = False
		if self.left == None:
			valid_left = False
		elif isinstance(self.left, MotifEdge):
			valid_left = True
		elif self.op != None:
			valid_left = valid_left or self.left.validate()

		valid_right = False
		if self.right == None:
			valid_right = False
		elif isinstance(self.right, MotifEdge):
			valid_right = True
		elif self.op != None:
			valid_right = valid_right or self.right.validate()
		
		return valid_left or valid_right

	def print_rel(self):
		if self.left != None and not isinstance(self.left, MotifEdge):
			self.left.print_rel()
		if isinstance(self.left, MotifEdge):
			print(self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type)
		if self.op != None:
			print(self.op)
		if self.right != None and not isinstance(self.right, MotifEdge):
			self.right.print_rel()
		if isinstance(self.right, MotifEdge):
			print(self.right.src_node.mn_type + '-' + self.right.me_type + '->' + self.right.dst_node.mn_type)



class RegularTemporalMotif():
	"""
	A regular temporal motif (RTM) consists of a list of relations (Relation) in the motif.
	"""
	def __init__(self):
		self.relations = []

	@property
	def relations(self):
		return self.__relations

	def add_relation(self, relation):
		self.relations.append(relation)

	def validate(self):
		valid = False
		for relation in self.relations:
			if relation == None:
				valid = valid or relation
			else:
				valid = valid or relation.validate()
		return valid

	def print_rtm(self):
		for relation in self.relations:
			relation.print_rel()















