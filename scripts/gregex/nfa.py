# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
# 
# Credits to: https://github.com/osandov/pylex/blob/master/pylex/nfa.py

from automaton import Automaton, AutomatonState

class NFA(Automaton):
	"""A nondeterministic finite automaton.

	Each state can have multiple transitions on a single diedge
	as well as transitions without consuming any input
	(i.e., epsilon transitions).

	"""

	def __init__(self, initial):
		super(NFA, self).__init__(initial)

	def to_dfa(self):
		"""Convert NFA instance to an equivalent DFA."""

		from nfa2dfa import RabinScott
		return RabinScott(self)()

class NFAState(AutomatonState):
	"""A state in a nondeterministic finite automaton.

	Attributes:
	transitions -- A set of outgoing transitions from this state represented
					as a dictionary from directed edges or None (epsilon) to
					a set of states

	"""
	def __init__(self, accepting=None):
		super(NFAState, self).__init__(accepting)

	def _all_transitions(self):
		transitions = set()

		for diedge, targets in self.transitions.items():
			transitions |= {(diedge, target) for target in targets}
		return transitions

	def add_transition(self, diedge, to):
		"""Add a transition to this state.

		Arguments:
		diedge -- The directed edge on which to take the transition;
					None to represent epsilon transition
		to -- The state to transition to on the given diedge
		"""

		self._ensure_not_numbered()

		try:
			# Invalidate the memoized epsilon closure
			del self._epsilon_closure
		except AttributeError:
			pass

		try:
			self.transitions[diedge].add(to)
		except KeyError:
			self.transitions[diedge] = {to}

	def epsilon_closure(self):
		"""Compute the epsilon closure for this state.

		The epsilon closure is the set of all states reachable from
		this state in zero or more epsilon transitions.
		Epsilon transitions may not happen in our case.

		"""
		try:
			return self._epsilon_closure
		except AttributeError:
			epsilon_closure = {self}

			worklist = [self]
			while worklist:
				state = worklist.pop()
				for target in state.transitions.get(None, set()):
					if target not in epsilon_closure:
						epsilon_closure.add(target)
						worklist.append(target)

			# Make the set immutable.
			self._epsilon_closure = frozenset(epsilon_closure)
			return self._epsilon_closure
