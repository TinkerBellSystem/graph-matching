# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function
import struct
import random
import graph

fixed_edge_color = '#000000'

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
		Relation.used_colors = []
		Relation.color = fixed_edge_color
		Relation.num = 0

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
		if self.op == None:
			if self.right != None:
				print('\33[103m' + '[error]: None OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				print("None", end='')
			elif isinstance(self.left, MotifEdge):
				print_str = self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type
				print(print_str, end='')
			else:
				self.left.print_rel()
		elif self.op == '*':
			if self.right != None:
				print('\33[103m' + '[error]: "*" OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				print('\33[103m' + '[error]: "*" OP should not have None type LHS ' + '\033[0m')
			elif isinstance(self.left, MotifEdge):
				print_str = self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type + '*'
				print(print_str, end='')
			else:
				self.left.print_rel()
				print('*', end='')
		elif self.op == '?':
			if self.right != None:
				print('\33[103m' + '[error]: "?" OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				print('\33[103m' + '[error]: "?" OP should not have None type LHS ' + '\033[0m')
			elif isinstance(self.left, MotifEdge):
				print_str = self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type + '?'
				print(print_str, end='')
			else:
				self.left.print_rel()
				print('?', end='')
		elif self.op == '|':
			if self.left == None:
				print("None", end='')
			elif isinstance(self.left, MotifEdge):
				print_str = self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type
				print(print_str, end='')
			else:
				self.left.print_rel()
			print("|", end='')
			if self.right == None:
				print("None", end='')
			elif isinstance(self.right, MotifEdge):
				print_str = self.right.src_node.mn_type + '-' + self.right.me_type + '->' + self.right.dst_node.mn_type
				print(print_str, end='')
			else:
				self.right.print_rel()
		elif self.op == '()':
			print("(", end='')
			if self.left == None:
				print("None", end='')
			elif isinstance(self.left, MotifEdge):
				print_str = self.left.src_node.mn_type + '-' + self.left.me_type + '->' + self.left.dst_node.mn_type
				print(print_str, end='')
			else:
				self.left.print_rel()
			print(",", end='')
			if self.right == None:
				print("None", end='')
			elif isinstance(self.right, MotifEdge):
				print_str = self.right.src_node.mn_type + '-' + self.right.me_type + '->' + self.right.dst_node.mn_type
				print(print_str, end='')
			else:
				self.right.print_rel()
			print(")", end='')

	def next_color(self):
		r = random.randint(0, 255)
		g = random.randint(0, 255)
		b = random.randint(0, 255)
		rgb = (r,g,b)
		hex_str = '#' + struct.pack('BBB',*rgb).encode('hex')
		while rgb in Relation.used_colors or hex_str == fixed_edge_color:
			r = random.randint(0, 255)
			g = random.randint(0, 255)
			b = random.randint(0, 255)
			rgb = (r,g,b)
			hex_str = '#' + struct.pack('BBB',*rgb).encode('hex')
		Relation.used_colors.append(rgb)
		Relation.color = hex_str

	def next_number(self):
		Relation.num = Relation.num + 1

	def draw_rtm(self, graph):
		if self.op == None:
			if self.right != None:
				print('\33[103m' + '[error]: None OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				pass
			elif isinstance(self.left, MotifEdge):
				graph_str = self.left.src_node.mn_type + '-' + self.left.me_type + str(Relation.num) + '->' + self.left.dst_node.mn_type
				# print(graph_str)
				graph.add_string(graph_str, Relation.color)
			else:
				self.left.draw_rtm(graph)
		elif self.op == '*':
			if self.right != None:
				print('\33[103m' + '[error]: "*" OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				print('\33[103m' + '[error]: "*" OP should not have None type LHS ' + '\033[0m')
			elif isinstance(self.left, MotifEdge):
				self.next_number()
				graph_str = self.left.src_node.mn_type + '-' + self.left.me_type + str(Relation.num) + '->' + self.left.dst_node.mn_type
				graph.add_string(graph_str, Relation.color)
			else:
				self.next_number()
				self.left.draw_rtm(graph)
		elif self.op == '?':
			if self.right != None:
				print('\33[103m' + '[error]: "?" OP should not have non-None type RHS ' + '\033[0m')
			if self.left == None:
				print('\33[103m' + '[error]: "?" OP should not have None type LHS ' + '\033[0m')
			elif isinstance(self.left, MotifEdge):
				self.next_number()
				graph_str = self.left.src_node.mn_type + '-' + self.left.me_type + str(Relation.num) + '->' + self.left.dst_node.mn_type
				graph.add_string(graph_str, Relation.color)
			else:
				self.next_number()
				self.left.draw_rtm(graph)
		elif self.op == '|':
			if self.left == None:
				pass
			elif isinstance(self.left, MotifEdge):
				self.next_color()
				graph_str = self.left.src_node.mn_type + '-' + self.left.me_type + str(Relation.num) + '->' + self.left.dst_node.mn_type
				# print(graph_str)
				graph.add_string(graph_str, Relation.color)
			else:
				self.next_color()
				self.left.draw_rtm(graph)
			if self.right == None:
				pass
			elif isinstance(self.right, MotifEdge):
				self.next_color()
				graph_str = self.right.src_node.mn_type + '-' + self.right.me_type + str(Relation.num) + '->' + self.right.dst_node.mn_type
				# print(graph_str)
				graph.add_string(graph_str, Relation.color)
			else:
				self.next_color()
				self.right.draw_rtm(graph)
		elif self.op == '()':
			if self.left == None:
				pass
			elif isinstance(self.left, MotifEdge):
				graph_str = self.left.src_node.mn_type + '-' + self.left.me_type + str(Relation.num) + '->' + self.left.dst_node.mn_type
				# print(graph_str)
				graph.add_string(graph_str, Relation.color)
			else:
				self.left.draw_rtm(graph)
			if self.right == None:
				pass
			elif isinstance(self.right, MotifEdge):
				graph_str = self.right.src_node.mn_type + '-' + self.right.me_type + str(Relation.num) + '->' + self.right.dst_node.mn_type
				# print(graph_str)
				graph.add_string(graph_str, Relation.color)
			else:
				self.right.draw_rtm(graph)

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

	def draw_rtm(self, graph):
		for relation in self.relations:
			relation.draw_rtm(graph)














