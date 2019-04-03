# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
# 
# Credits to: https://github.com/osandov/pylex/blob/master/pylex/ast.py

from nfa import NFA, NFAState

class AST(object):
	"""Node in a regular expression abstract syntax tree."""

	def to_nfa(self, accepting_id=1):
		"""Convert this AST to an NFA.

		Arguments:
		accepting_id -- The ID of the accepting state (defaults to 1)

		"""

		(initial, accepting) = self._thompson()
		accepting.accepting = accepting_id
		return NFA(initial)

	def _thompson(self):
		"""
		Thompson's construction that converts this AST to an NFA

		The temporary representation of the NFA is an tuple:
		(initial state, accepting state). 
		The accepting state's ID is None.

		"""

		raise NotImplementedError

class DiedgeAST(AST):
	"""AST leaf node: directed edges in provenance.

	Attributes:
	diedge -- The directed edge for this node

	"""

	def __init__(self, diedge):
		"""Create a new diedge AST node.

		Arguments:
		diedge -- The directed edge for this node

		"""

		super(DiedgeAST, self).__init__()
		self.diedge = diedge

	def _thompson(self):
		initial = NFAState()
		accepting = NFAState()
		initial.add_transition(self.diedge, accepting)
		return (initial, accepting)

	def __repr__(self):
		return 'DiedgeAST({})'.format(repr(self.diedge))

class KleeneAST(AST):
	"""AST node for the Kleene star operator.

	Attributes:
	operand -- Operand of the closure

	"""

	def __init__(self, operand):
		"""Create a new Kleene closure AST node.

		Arguments:
		operand -- AST operand of the closure

		"""

		super(KleeneAST, self).__init__()
		self.operand = operand

	def _thompson(self):
		(initial, accepting) = self.operand._thompson()

		initial.add_transition(None, accepting)
		accepting.add_transition(None, initial)

		return (initial, accepting)

	def __repr__(self):
		return 'KleeneAST({})'.format(repr(self.operand))

class QuestionMarkAST(AST):
	"""AST node for the question mark closure.

	Attributes:
	operand -- Operand of the closure

	"""

	def __init__(self, operand):
		"""Create a new question mark closure AST node.

		Arguments:
		operand -- AST operand of the closure

		"""

		super(QuestionMarkAST, self).__init__()
		self.operand = operand

	def _thompson(self):
		new_initial = NFAState()
		(initial, accepting) = self.operand._thompson()

		new_initial.add_transition(None, initial)
		new_initial.add_transition(None, accepting)

		return (new_initial, accepting)

	def __repr__(self):
		return 'QuestionMarkAST({})'.format(repr(self.operand))

class AlternationAST(AST):
	"""Alternation (i.e., union) of two or more regular expressions.

	Attributes:
	operands -- Tuple containing the alternate regular expressions

	"""

	def __init__(self, *operands):
		"""Create a new alternation AST node.

		Arguments:
		operands -- Two or more children AST nodes

		"""

		super(AlternationAST, self).__init__()

		if len(operands) < 2:
			raise ValueError('alternation must have two or more operands')

		self.operands = ()
		for ast in operands:
			if isinstance(ast, AlternationAST):
				self.operands += ast.operands
			else:
				self.operands += (ast,)

	def _thompson(self):
		initial = NFAState()
		accepting = NFAState()

		for ast in self.operands:
			(alternate_initial, alternate_accepting) = ast._thompson()
			initial.add_transition(None, alternate_initial)
			alternate_accepting.add_transition(None, accepting)

		return (initial, accepting)

	def __repr__(self):
		return 'AlternationAST({})'.format(', '.join(repr(op) for op in self.operands))

class ConcatenationAST(AST):
	"""Concatenation of two or more regular expressions.

	Attributes:
	operands -- Tuple containing the concatenated regular expressions

	"""

	def __init__(self, *operands):
		"""Create a new concatenation AST node.

		Arguments:
		operands -- Two or more children AST nodes

		"""

		super(ConcatenationAST, self).__init__()

		if len(operands) < 2:
			raise ValueError('concatenation must have two or more operands')

		self.operands = ()
		for ast in operands:
			if isinstance(ast, ConcatenationAST):
				self.operands += ast.operands
			else:
				self.operands += (ast,)

	def _thompson(self):
		(initial, accepting) = self.operands[0]._thompson()

		for i in range(1, len(self.operands)):
			(next_initial, next_accepting) = self.operands[i]._thompson()
			accepting.add_transition(None, next_initial)
			accepting = next_accepting

		return (initial, accepting)

	def __repr__(self):
		return 'ConcatenationAST({})'.format(', '.join(repr(op) for op in self.operands))

def ast_to_nfa(ast):
	"""Convert an AST to an NFA.

	"""
	(initial, accepting) = ast._thompson()
	accepting.accepting = 1

	return NFA(initial)





