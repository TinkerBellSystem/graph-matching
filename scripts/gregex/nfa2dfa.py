# Credits to: https://github.com/osandov/pylex/blob/master/pylex/rabinscott.py
"""Implementation of the Rabin-Scott subset construction (a.k.a powerset construction).

"""
from gregex.dfa import DFA, DFAState
from gregex.nfa import NFA, NFAState

class RabinScott:
	"""Using Rabin-Scott powerset construction to convert an NFA to an equivalent DFA.

	"""
	def __init__(self, nfa):
		"""Create an NFA to DFA converter for the given NFA."""

		self.initial = nfa.initial

	def _configuration_to_dfa_state(self, q):
		"""Create a DFA state from the given configuration.

		If the configuration contains any accepting states, the DFA state will
		have the minimum accepting ID to ensure that we match the first rule
		to accept a string. If the configuration does not contain any 
		accepting states, the DFA state will not be an accepting state.

		"""
		try:
			accepting = min(state.accepting for state in q if state.accepting)
		except ValueError:
			accepting = None

		return DFAState(accepting)

	def _delta_closure(self, q, e):
		"""Return epsilon_closure(delta(q, e))."""

		delta_closure = set()
		for state in q:
			for target in state.transitions.get(e, set()):
				delta_closure |= target.epsilon_closure()

		return frozenset(delta_closure)

	def _transition_closure(self, q):
		"""Return all position transition diedge from the set of states in @q."""

		transition_closure = set()
		for state in q:
			for transition in state.transitions.keys():
				if transition:	# disregard epsilon transitions, which are None
					transition_closure.add(transition)
		return transition_closure

	def __call__(self):
		# Initial configuration
		q0 = self.initial.epsilon_closure()

		# Dictionary from known configuration to corresponding DFA state
		Q = {q0: self._configuration_to_dfa_state(q0)}

		worklist = [q0]
		while worklist:
			q = worklist.pop()

			for diedge in self._transition_closure(q):
				t = self._delta_closure(q, diedge)

				if not t:
					assert False, "t should not be empty"
				else:
					try:
						dfa_state = Q[t]
					except KeyError:
						dfa_state = self._configuration_to_dfa_state(t)
						Q[t] = dfa_state
						worklist.append(t)

					Q[q].add_transition(diedge, dfa_state)

		return DFA(Q[q0])

