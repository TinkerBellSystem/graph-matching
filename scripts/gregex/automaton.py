# Credits to: https://github.com/osandov/pylex/blob/master/pylex/automaton.py
from __future__ import print_function
import sys

class Automaton(object):
	"""A finite automaton.

	Attributes:
	initial -- The initial state of the automaton
	num_states -- The number of states in this automaton

	"""

	def __init__(self, initial):
		"""Create a new automaton with the given initial state.

		Arguments:
		initial -- The initial automaton state.

		"""
		self.initial = initial
		self.num_states = self._number_states(self.initial, 0)

	def _number_states(self, state, next_number):
		"""Number the given @state and all states reachable from it.

		Arguments:
		state -- The state to start numbering. If it does not have a number already, it will be assigned @next_number.
		next_number -- The number from which to start assigning numbers.

		Returns:
		The largest number that was assigned plus one (i.e., the smallest integer that has yet been assigned).

		"""
		if state.number is None:
			state.number = next_number
			next_number += 1

			for (diedge, target) in state._all_transitions():
				next_number = self._number_states(target, next_number)

		return next_number

	def print_graphviz(self, file=sys.stdout):
		"""Print automaton for Graphviz dot rendering."""

		print('digraph {} {{'.format(type(self).__name__), file=file)
		print('    rankdir = LR;', file=file)
		print('    I [style = invis];', file=file)

		print('    I -> S{};'.format(self.initial.number), file=file)
		self.initial._print_graphviz(file, set())

		print('}', file=file)

class AutomatonState(object):
	"""A state in a finite automaton storing a set of transitions to other states.

	Attributes:
	accepting -- If this state is an accepting state, assign a positive integer
					ID representing the rule that this accepts,; None otherwise
	transitions -- A set of outgoing transitions from this state represented as
					a dictionary. The values of the dictionary depend on the
					type of automaton (determinstic vs non-deterministic)
	number -- If this state is in the automaton, a non-negative integer that is
				unique within the automaton; None otherwise
	"""

	def __init__(self, accepting=None):
		"""Create a new state with no transitions."""

		self.accepting = accepting
		self.transitions = {}
		self.number = None

	def _all_transitions(self):
		"""Return a flat set of all transitions from this state."""
		raise NotImplementedError

	def _ensure_not_numbered(self):
		if self.number is not None:
			raise ValueError('state in automaton cannot be modified')

	def add_transition(self, diedge, to):
		"""Add a transition to this state.

		Arguments:
		diedge -- The diedge (i.e., directed edge) on which to take the transition.
		to -- The state to transition to given the diedge.

		"""
		raise NotImplementedError

	def _print_graphviz(self, file, seen):
		if self in seen:
			return
		seen.add(self)

		if self.accepting:
			subscript = '{},{}'.format(self.number, self.accepting)
		else:
			subscript = self.number

		print('    S{} [label = <s<sub>{}</sub>>, shape = circle'.format(self.number, subscript), file=file, end='')

		if self.accepting:
			print(', peripheries = 2', file=file, end='')
		print('];', file=file)

		for (diedge, target) in self._all_transitions():
			target._print_graphviz(file, seen)
			if diedge is None:
				label = '\u03b5'  # Lower case epsilon
			else:
				label = repr(diedge).replace('\\', '\\\\')  # Escape slashes
			print('    S{} -> S{} [label = "{}"];'.format(self.number, target.number, label), file=file)































