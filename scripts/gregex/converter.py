# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
# 
"""Convert RTM trees to regex AST."""

from automaton import Diedge
from ast import DiedgeAST, KleeneAST, QuestionMarkAST, AlternationAST, ConcatenationAST
from rtm import MotifNode, MotifEdge, RTMTreeNode

class Converter:
	"""An RTMT-to-Regex-AST converter."""

	def __init__(self, rtm):
		self._rtm = rtm
		self.ast = _parse(self._rtm)
	
def _parse(rtmt):
	"""Parsing an RTMT to a list of ASTs."""
	if not rtmt:
		return asts
	else:
		if rtmt.value == '.':
			if rtmt.left and rtmt.right:
				return ConcatenationAST(_parse(rtmt.left), _parse(rtmt.right))
			elif rtmt.left:
				return _parse(rtmt.left)
			elif rtmt.right:
				return _parse(rtmt.right)
			else:
				raise ValueError('a RTMT concatenate internal node should have at least one child')
		elif rtmt.value == '*':
			if rtmt.left and rtmt.right:
				raise ValueError('a RTMT Kleene star internal node should not have two children')
			elif rtmt.left:
				assert(rtmt.right == None)
				return KleeneAST(_parse(rtmt.left))
			elif rtmt.right:
				assert(rtmt.left == None)
				return KleeneAST(_parse(rtmt.right))
			else:
				raise ValueError('a RTMT Kleene star internal node should have one child')
		elif rtmt.value == '?':
			if rtmt.left and rtmt.right:
				raise ValueError('a RTMT question mark internal node should not have two children')
			elif rtmt.left:
				assert(rtmt.right == None)
				return QuestionMarkAST(_parse(rtmt.left))
			elif rtmt.right:
				assert(rtmt.left == None)
				return QuestionMarkAST(_parse(rtmt.right))
			else:
				raise ValueError('a RTMT question mark internal node should have one child')
		elif rtmt.value == '|':
			if rtmt.left == None or rtmt.right == None:
				# streamline_rtm should have converted all one-child alternation node to question mark node.
				raise ValueError('a RTMT alternation internal node should have two children')
			else:
				return AlternationAST(_parse(rtmt.left), _parse(rtmt.right))
		elif isinstance(rtmt.value, MotifEdge):
			diedge = Diedge(rtmt.value.src_node.mn_id, rtmt.value.src_node.mn_ty, rtmt.value.dst_node.mn_id, rtmt.value.dst_node.mn_ty, rtmt.value.me_ty)
			return DiedgeAST(diedge)
		else:
			raise ValueError('unknown RTMT node')

