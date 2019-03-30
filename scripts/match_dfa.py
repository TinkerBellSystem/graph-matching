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


def match_types(diedge, edge):
	"""Match the node and edge type of a motif edge @diedge and the edge @edge of the graph."""
	print("Matching a motif edge's types {}({}), {}, {}({}), with a graph edge's types {}, {}, {}"
		  .format(diedge.srcTP, diedge.srcID, diedge.edgeTP, diedge.dstTP, diedge.dstID, edge[0], edge[2], edge[3]))
	if diedge.srcTP == edge[0] and diedge.edgeTP == edge[2] and diedge.dstTP == edge[3]:
		return True
	else:
		if edge[0] == 'inode_unknown' or edge[0] == 'link' or edge[0] == 'file' \
			or edge[0] == 'directory' or edge[0] == 'char' or edge[0] == 'block' \
			or edge[0] == 'pipe' or edge[0] == 'socket':
			srcGTP = 'inode'
		else:
			srcGTP = edge[0]
		if edge[3] == 'inode_unknown' or edge[3] == 'link' or edge[3] == 'file' \
			or edge[3] == 'directory' or edge[3] == 'char' or edge[3] == 'block' \
			or edge[3] == 'pipe' or edge[3] == 'socket':
			dstGTP = 'inode'
		else:
			dstGTP = edge[3]
		if diedge.srcTP == srcGTP and diedge.edgeTP == edge[2] and diedge.dstTP == dstGTP:
			return True
		else:
			return False


def get_canonical_id(mid, canonical):
	"""Get canonical motif node ID, due to the possible effect of version_activity and version_activity."""
	while canonical.get(mid) is not None:
		mid = canonical[mid]
	return mid


def tracker_no_conflict(diedge, edge, ids, canonical):
	"""When matching node IDs of @diedge (in DFA) and those of @edge (in G), check if there exists any conflicts in @ids."""
	print("Matching motif source node {}/{} ({}) to {}, and destintaion node {}/{} ({}) to {}"
		  .format(diedge.srcID, get_canonical_id(diedge.srcID, canonical), ids.get(get_canonical_id(diedge.srcID, canonical)),
				  edge[1], diedge.dstID, get_canonical_id(diedge.dstID, canonical),
				  ids.get(get_canonical_id(diedge.dstID, canonical)), edge[4]))
	# a special '*' case
	if diedge.edgeTP == 'sh_read':
		# inode ID matching is ghosted
		if ids.get(get_canonical_id(diedge.dstID, canonical)) is None or ids[get_canonical_id(diedge.dstID, canonical)] == edge[4]:
			return True
		else:
			return False
	elif diedge.edgeTP == 'version_activity' or diedge.edgeTP == 'version_entity':
		# destination should be ghosted
		if ids.get(get_canonical_id(diedge.srcID, canonical)) is None or ids[get_canonical_id(diedge.srcID, canonical)] == edge[1]:
			return True
		else:
			return False
	elif (ids.get(get_canonical_id(diedge.srcID, canonical)) is None or ids[get_canonical_id(diedge.srcID, canonical)] == edge[1]) \
			and (ids.get(get_canonical_id(diedge.dstID, canonical)) is None or ids[get_canonical_id(diedge.dstID, canonical)] == edge[4]):
		return True
	else:
		return False

def inverse_tracker_no_conflict(edge, diedge, ids, canonical):
	"""When matching node IDs of @edge (in G) and those of @diedge (in DFA), check if there exists any conflicts in @ids."""
	print("Matching graph source node {} ({}) to {}/{}, and destintaion node {} ({}) to {}/{}"
		  .format(edge[1], ids.get(edge[1]), diedge.srcID, get_canonical_id(diedge.srcID, canonical),
				  edge[4], ids.get(edge[4]), diedge.dstID, get_canonical_id(diedge.dstID, canonical)))
	if (edge[1] not in ids or ids[edge[1]] == get_canonical_id(diedge.srcID, canonical)) \
			and (edge[4] not in ids or ids[edge[4]] == get_canonical_id(diedge.dstID, canonical)):
		return True
	else:
		return False


def match_transition(states, edge, tracker, inverse_tracker, canonicals):
	"""Match one transition in states with the edge in the graph."""
	matched = False
	# We can delete the state and safely proceed to the next state because we are doing thread-level matching
	to_delete = set()
	states_len = len(states)
	for i in range(states_len):
		state = states[i]

		transitions = state._all_transitions()
		print("Checking state: {} with {} transitions".format(i, len(transitions)))
		for transition in transitions:
			transition_diedge = transition[0]
			next_state = transition[1]
			if match_types(transition_diedge, edge):
				if tracker_no_conflict(transition_diedge, edge, tracker[i], canonicals[i]) \
					and inverse_tracker_no_conflict(edge, transition_diedge, inverse_tracker[i], canonicals[i]):
					# we find a perfect match
					# if the match is version, then we update the canonical map
					canonical_copy = copy.deepcopy(canonicals[i])
					if transition_diedge.edgeTP == 'version_activity' or transition_diedge.edgeTP == 'version_entity':
						canonical_copy.pop(transition_diedge.dstID, None)
					tracker_copy = copy.deepcopy(tracker[i])
					tracker_copy[get_canonical_id(transition_diedge.srcID, canonical_copy)] = edge[1]
					tracker_copy[get_canonical_id(transition_diedge.dstID, canonical_copy)] = edge[4]
					inverse_tracker_copy = copy.deepcopy(inverse_tracker[i])
					inverse_tracker_copy[edge[1]] = get_canonical_id(transition_diedge.srcID, canonical_copy)
					inverse_tracker_copy[edge[4]] = get_canonical_id(transition_diedge.dstID, canonical_copy)
					states.append(next_state)
					tracker.append(tracker_copy)
					inverse_tracker.append(inverse_tracker_copy)
					canonicals.append(canonical_copy)
					to_delete.add(i)
					matched = True
	for i in sorted(to_delete, reverse=True):
		states.pop(i)
		tracker.pop(i)
		inverse_tracker.pop(i)
		canonicals.pop(i)
	print("Number of states: {}".format(len(states)))
	return matched


def match_dfa(dfaname, dfa, G, canonical):
	"""Matches all motifs of dfa in the graph G.

	For every index x in @G, G[x] is the x'th edge in the graph (since the edges are ordered).
	In every iteration of the graph @G, we look for one complete matches of the NFA.
	We do many iterations until no more matches can be found.

	Arguments:
	dfaname: the name of the motif (dfa)
	dfa: the state machine that represents a motif
	G: the graph to match
	canonical: dictionary that returns the canonical ID of motif nodes

	Returns:
	All sets of edge indices that belong to the same motif (DFA)

	"""
	f = open('../matches/' + dfaname + '.txt', 'a+')
	print("\x1b[6;30;42m[+]\x1b[0m" + 'Matching ' + dfaname)

	start = 0	# starting index of edges in @G
	end = len(G)				# Pass the last index of edge in @G. 
	indicator = [1] * len(G)	# indicator[i] = 0 means G[i] is temporarily matched to the DFA
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
			f.write(repr(map(list, set(map(tuple, matches)))))
			f.write("\n")
			return

		# start to find matches
		current_states = [dfa.initial] 	# start from the initial state of the DFA
		tracker = [dict()]# a list of dictionaries that track the correspondence between
									# node IDs in DFA and those in the graph
									# We start with just one such dictionary in the list
									# but we may have more as more than one transition is matched
		inverse_tracker = [dict()]	# a list of dictionaries that track the correspondence between
									# node IDs in the graph and those in the DFA
									# We start with just one such dictionary in the list
									# but we may have more as more than one transition is matched
		canonicals = [canonical]# a list of canonical maps
		indices = []	# currently matched indices of edges in graph @G
		real_indices = []	# matched indices but real ID

		current_index = start

		while current_index < len(G):
			if indicator[current_index] == 0:
				# print("skipping edge #{}".format(current_index))
				current_index += 1
				continue
			print("matching edge #{}...".format(current_index))
			if match_transition(current_states, G[current_index], tracker, inverse_tracker, canonicals):
				print("matched edge #{}...".format(current_index))
				indices.append(current_index)
				real_indices.append(G[current_index][5])
				indicator[current_index] = 0

				# NOTE: we don't do accept and break because we may want to continue matching even if an accepting state is reached
				# accepted = 0
				for state in current_states:
					if state.accepting is not None:
						# if we have reached an accepting state
						print("Reached an accepting state...")
						real_indices_copy = copy.deepcopy(real_indices)
						matches.append(real_indices_copy)
						# accepted = 1
						# break
				# if accepted:
				# 	break

			current_index += 1
			# print("current_index is {}".format(current_index))

		# we have passed the end of the graph but we still cannot match to the DFA
		if current_index == len(G):
			# reset all indicators
			for index in indices:
				indicator[index] = 1
		# move on to the next starting point
		start += 1
	f.write(repr(map(list, set(map(tuple, matches)))))
	f.write("\n")
	# return matches


def match_dfa_wrapper(args):
	"""wrapper around match_dfa function so that multiprocessing pool can run with multiple arguments."""
	match_dfa(*args)
	# return match_dfa(*args)
