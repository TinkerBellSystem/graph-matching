# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

##############################################################################
# 
##############################################################################

import copy

def id_dict(ids):
	"""Returns a new ID dictionary given the list of IDs in the motif.

	Arguments:
	ids: a list of IDs exist in the motif

	Returns:
	An initialized dictionary that maps every ID in @ids to None

	"""
	id_dict = dict()
	for nid in ids:
		id_dict[nid] = None
	return id_dict

def match_types(diedge, edge):
	"""Match the node and edge type of a motif edge @diedge and the edge @edge of the graph."""
	if diedge.srcTP == edge[0] and diedge.edgeTP == edge[2] and diedge.dstTP == edge[3]:
		return True
	else:
		return False

def tracker_no_conflict(diedge, edge, ids):
	"""When matching node IDs of @diedge (in DFA) and those of @edge (in G), check if there exists any conflicts in @ids."""
	if (ids[diedge.srcID] == None or ids[diedge.srcID] == edge[1]) and (ids[diedge.dstID] == None or ids[diedge.dstID] == edge[4]):
		return True
	else:
		return False

def inverse_tracker_no_conflict(edge, diedge, ids):
	"""When matching node IDs of @edge (in G) and those of @diedge (in DFA), check if there exists any conflicts in @ids."""
	if (edge[1] not in ids or ids[edge[1]] == diedge.srcID) and (edge[4] not in ids or ids[edge[4]] == diedge.dstID):
		return True
	else:
		return False

def match_transition(states, edge, tracker, inverse_tracker):
	"""Match one transition in states with the edge in the graph."""
	matched = False
	to_delete = set()
	states_len = len(states)
	for i in range(states_len):
		state = states[i]

		transitions = state._all_transitions()
		for transition in transitions:
			transition_diedge = transition[0]
			next_state = transition[1]
			if match_types(transition_diedge, edge) and tracker_no_conflict(transition_diedge, edge, tracker[i]) and inverse_tracker_no_conflict(edge, transition_diedge, inverse_tracker[i]):
				# we find a perfect match
				tracker_copy = copy.deepcopy(tracker[i])
				tracker_copy[transition_diedge.srcID] = edge[1]
				tracker_copy[transition_diedge.dstID] = edge[4]
				inverse_tracker_copy = copy.deepcopy(inverse_tracker[i])
				inverse_tracker_copy[edge[1]] = transition_diedge.srcID
				inverse_tracker_copy[edge[4]] = transition_diedge.dstID
				states.append(next_state)
				tracker.append(tracker_copy)
				inverse_tracker.append(inverse_tracker_copy)
				to_delete.add(i)
				matched = True
	for i in to_delete:
		states.pop(i)
		tracker.pop(i)
		inverse_tracker.pop(i)
	return matched

def match_dfa(dfa, G):
	"""Matches all motifs of dfa in the graph G.

	For every index x in @G, G[x] is the x'th edge in the graph (since the edges are ordered).
	In every iteration of the graph @G, we look for one complete matches of the NFA.
	We do many iterations until no more matches can be found.

	Arguments:
	dfa: the state machine that represents a motif
	G: the graph to match

	Returns:
	All sets of edge indices that belong to the same motif (DFA)

	"""
	start = 0	# starting index of edges in @G
	end = len(G)				# Pass the last index of edge in @G. 
	indicator = [1] * len(G)	# indicator[i] = 0 means G[i] is temporarily matched to the NFA
								# We will set indicator[i] back to 1 if it turns out that it
								# was a false match, then G[i] will need to be considered again
	matches = []	# the returned list that contains lists of matched edge indices

	while start < end:
		# we first look for the first edge in @G to match the first transition in @dfa
		# we will not look at the edges that have been matched before.
		while start < end and indicator[start] == 0:
			start += 1

		# print("process to the next starting point at {}...".format(start))
		# all the rest of the graph is matched.
		if start == end:
			return matches

		# start to find matches
		current_states = [dfa.initial] 	# start from the initial state of the DFA
		tracker = [id_dict(dfa.ids)]# a list of dictionaries that track the correspondence between
									# node IDs in DFA and those in the graph
									# We start with just one such dictionary in the list
									# but we may have more as more than one transition is matched
		inverse_tracker = [dict()]	# a list of dictionaries that track the correspondence between
									# node IDs in the graph and those in the DFA
									# We start with just one such dictionary in the list
									# but we may have more as more than one transition is matched
		indices = []	# currently matched indices of edges in graph @G

		current_index = start

		while current_index < len(G):
			if indicator[current_index] == 0:
				# print("skipping edge #{}".format(current_index))
				current_index += 1
				continue

			if match_transition(current_states, G[current_index], tracker, inverse_tracker):
				# print("matched edge #{}...".format(current_index))
				indices.append(current_index)
				indicator[current_index] = 0

				accepted = 0
				for state in current_states:
					if state.accepting is not None:
						# if we have reached an accepting state
						matches.append(indices)
						accepted = 1
						break
				if accepted:
					break

			current_index += 1
			# print("current_index is {}".format(current_index))

		# we have passed the end of the graph but we still cannot match to the DFA
		if current_index == len(G):
			# reset all indicators
			for index in indices:
				indicator[index] = 1
		# move on to the next starting point
		start += 1

	return matches





