# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
# 
# Credits to: https://github.com/osandov/pylex/blob/master/pylex/dfa.py

from automaton import Automaton, AutomatonState

class DFA(Automaton):
	"""A deterministic finite automaton.

	Each state can have only a single transition for a diedge
	and episilon transitions are not allowed.

	"""

	def __init__(self, initial):
		super(DFA, self).__init__(initial)

class DFAState(AutomatonState):
	"""A state in a deterministic finite automaton.

	Attributes:
	transitions -- A set of outgoing transitions from this state
					represented as a dictionary from a directed 
					edge to another state

	"""
	def __init__(self, accepting=None):
		super(DFAState, self).__init__(accepting)

	def _all_transitions(self):
		return set(self.transitions.items())

	def add_transition(self, diedge, to):
		"""Add a transition to this state.

		Arguments:
		diedge -- The directed edge on which to take the transition;
					must not already be in the keys of transitions
					and must not be None
		to -- The state to transition to on the given diedge
		
		"""
		self._ensure_not_numbered()

		assert diedge is not None, 'DFA cannot contain epsilon transitions'
		assert diedge not in self.transitions, 'state already contains a given transition'
		self.transitions[diedge] = to
