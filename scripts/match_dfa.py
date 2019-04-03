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
import os
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
	# a special '*' case for sh_read
	if diedge.edgeTP == 'sh_read':
		# inode ID matching is ghosted
		if ids.get(get_canonical_id(diedge.dstID, canonical)) is None or ids[get_canonical_id(diedge.dstID, canonical)] == edge[4]:
			return True
		else:
			return False
	# a special '*' case for arg/env (only in the hook 'provenance_bprm_check_security')
	elif diedge.edgeTP == 'arg' or diedge.edgeTP == 'env':
		# argv or env's ID matching (source) is ghosted
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


def is_consecutive(l):
	"""
	Check if a list @l have consecutive elements
	:param l: the list to check
	:return: True (if consecutive) or False
	"""
	l = list(map(int, l))
	l.sort()
	next_elem = None
	for elem in l:
		if next_elem is None:
			next_elem = elem
		else:
			if elem != next_elem + 1:
				return False
			else:
				next_elem = elem
	return True


def post_match_precheck(l, G, dfaname):
	"""
	Once a consecutive list @l is matched, before it is considered valid and record to a file, it is checked here
	for certain criteria for different hooks (as determined by @dfaname.
	Check comments for criteria used for each hook.
	:param l: the potential match (indices that allow us to map to edges in G, not real indices)
	:param G: the graph (in order to obtain values of the edges in teh list @l)
	:param dfaname: name of the hook
	:return: True for valid match (precheck success), or False for invalid match.
	"""
	if dfaname is 'provenance_bprm_check_security':
		# if only a single `machine -ran_on-> task` is matched. Then we discard such a match as it tells us nothing.
		if len(l) == 1 and G[l[0]][2] == 'ran_on':
			return False
		# if only two edges in the list, `task -version_activity-> task` followed by `machine -ran_on-> task`
		elif len(l) == 2 and G[l[0]][2] == 'version_activity' and G[l[1]][2] == 'ran_on':
			return False
		else:
			return True
	elif dfaname is 'provenance_kernel_read_file':
		# TODO: Put in the paper: one option was left out
		# TODO: GitHub: Create a new relationship such as load_undefined so that all load relationship will always be recorded one way or another
		# provenance_kernel_read_file: we would expect one of the following:
		# 1. `inode -load_file-> task` and `task -load_unknown-> machine`
		# 2. `inode -load_file-> task` and `task -load_firmware-> machine`
		# 3. `inode -load_file-> task` and `task -load_firmware_prealloc_buffer-> machine`
		# 4. `inode -load_file-> task` and `task -load_module-> machine`
		# 5. `inode -load_file-> task` and `task -load_kexec_image-> machine`
		# 6. `inode -load_file-> task` and `task -load_kexec_initramfs-> machine`
		# 7. `inode -load_file-> task` and `task -load_policy-> machine`
		# 8. `inode -load_file-> task` and `task -load_certificate-> machine`

		# if we do not see `load_file` then we will discard any matches without it
		with_load_file = False
		for index in l:
			if G[index][2] == 'load_file':
				with_load_file = True
		if not with_load_file:
			return False
		else:
			return True
	elif dfaname is 'provenance_file_permission':
		# provenance_file_permission: we would most likely expect one or more of the following, in that order:
		# 1. `process_memory -memory_read-> task` and `task -write-> inode`
		# 2. `inode -read-> task` and `task -memory_write-> process_memory`
		# 3. `inode -search-> task` and `task -memory_write-> process_memory`
		# 4. `process_memory -memory_read-> task` and `task -send-> inode`
		# 5. `inode -receive-> task` and `task -memory_write-> process_memory`
		# 6. `inode -exec-> process_memory`
		all_types = list()
		for index in l:
			all_types.append(G[index][2])

		if 'memory_read' in all_types and 'write' in all_types and all_types.index('memory_read') < all_types.index('write'):
			return True
		elif 'read' in all_types and 'memory_write' in all_types and all_types.index('read') < all_types.index('memory_write'):
			return True
		elif 'search' in all_types and 'memory_write' in all_types and all_types.index('search') < all_types.index('memory_write'):
			return True
		elif 'memory_read' in all_types and 'send' in all_types and all_types.index('memory_read') < all_types.index('send'):
			return True
		elif 'receive' in all_types and 'memory_write' in all_types and all_types.index('receive') < all_types.index('memory_write'):
			return True
		elif 'exec' in all_types:
			return True
		else:
			return False
	elif dfaname is 'provenance_inode_permission':
		# provenance_inode_permission: we would most likely expect one or more of the following, in that order:
		# 1. `inode -perm_exec-> task` and `task -memory_write-> process_memory`
		# 2. `inode -perm_read-> task` and `task -memory_write-> process_memory`
		# 3. `inode -perm_append-> task` and `task -memory_write-> process_memory`
		# 4. `inode -perm_write-> task` and `task -memory_write-> process_memory`
		all_types = list()
		for index in l:
			all_types.append(G[index][2])

		if 'perm_exec' in all_types and 'memory_write' in all_types and all_types.index('perm_exec') < all_types.index(
				'memory_write'):
			return True
		elif 'perm_read' in all_types and 'memory_write' in all_types and all_types.index('perm_read') < all_types.index('memory_write'):
			return True
		elif 'perm_append' in all_types and 'memory_write' in all_types and all_types.index('perm_append') < all_types.index('memory_write'):
			return True
		elif 'perm_write' in all_types and 'memory_write' in all_types and all_types.index('perm_write') < all_types.index('memory_write'):
			return True
		else:
			return False
	elif dfaname is 'provenance_mmap_file':
		# provenance_mmap_file: we would most likely expect one or more of the following, in that order:
		# 1. `inode -mmap_write-> task` and `task -memory_write-> process_memory`
		# 2. `inode -mmap_read-> task` and `task -memory_write-> process_memory`
		# 3. `inode -mmap_exec-> task` and `task -memory_write-> process_memory`
		# 4. `inode -mmap_write_private-> task` and `task -memory_write-> process_memory`
		# 5. `inode -mmap_read_private-> task` and `task -memory_write-> process_memory`
		# 6. `inode -mmap_exec_private-> task` and `task -memory_write-> process_memory`
		all_types = list()
		for index in l:
			all_types.append(G[index][2])

		if 'mmap_write' in all_types and 'memory_write' in all_types and all_types.index('mmap_write') < all_types.index(
				'memory_write'):
			return True
		elif 'mmap_read' in all_types and 'memory_write' in all_types and all_types.index('mmap_read') < all_types.index('memory_write'):
			return True
		elif 'mmap_exec' in all_types and 'memory_write' in all_types and all_types.index('mmap_exec') < all_types.index('memory_write'):
			return True
		elif 'mmap_write_private' in all_types and 'memory_write' in all_types and all_types.index('mmap_write_private') < all_types.index('memory_write'):
			return True
		elif 'mmap_read_private' in all_types and 'memory_write' in all_types and all_types.index('mmap_read_private') < all_types.index('memory_write'):
			return True
		elif 'mmap_exec_private' in all_types and 'memory_write' in all_types and all_types.index('mmap_exec_private') < all_types.index('memory_write'):
			return True
		else:
			return False
	# Other hooks do not have checks against them
	# provenance_bprm_committing_creds: `task -exec_task-> process_memory` must be matched at the end
	# provenance_bprm_set_creds: `inode -exec-> process_memory` must be matched at the end
	# provenance_cred_free: `process_memory -terminate_proc-> process_memory` must be matched at the end
	# provenance_cred_prepare: `process_memory -memory_read-> task` and `task -clone_mem-> process_memory` must exist in this order
	# provenance_file_ioctl: `process_memory -memory_read-> task` and `task -write_ioctl-> inode` and `inode -read_ioctl-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_file_lock: `process_memory -memory_read-> task` and `task -file_lock-> inode` must exist in this order
	# provenance_file_open: `inode -open-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_file_permission: #TODO: See above
	# provenance_file_receive: `inode -file_rcv-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_file_send_sigiotask: `inode -file_sigio-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_file_splice_pipe_to_pipe: `inode -splice_in-> task` and `task -memory_write-> process_memory` and `process_memory -memory_read-> task` and `task -splice_out-> inode` must exist in this order
	# provenance_inode_alloc_security: #TODO: Is this hook for naming inode only? # GitHub issue: Should do nothing
	# provenance_inode_create: `process_memory -memory_read-> task` and `task -inode_create-> inode` must exist in this order
	# provenance_inode_free_security: `inode -free-> inode` must be matched
	# provenance_inode_getattr: `inode -getattr-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_inode_getsecurity: #TODO: Only versioning and naming exist in this hook? # GitHub issue: Should do nothing
	# provenance_inode_getxattr: `inode -getxattr_inode-> xattr` and `xattr -getxattr-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_inode_link: `process_memory -memory_read-> task` and `task -link-> inode` must exist in this order
	# provenance_inode_listxattr: `inode -listxattr-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_inode_permission: #TODO: See above
	# provenance_inode_post_setxattr: `process_memory -memory_read-> task` and `task -setxattr-> xattr` and `xattr -setxattr_inode-> inode` and `xattr -removexattr_inode-> inode` must exist in this order
	# provenance_inode_readline: `inode -read_link-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_inode_removexattr: `process_memory -memory_read-> task` and `task -removexattr-> xattr` and `xattr -setxattr_inode-> inode` and `xattr -removexattr_inode-> inode` must exist in this order
	# provenance_inode_rename: `process_memory -memory_read-> task` and `task -link-> inode` must exist in this order #TODO: To be confused with provenance_inode_link # GitHub: Should have its own type
	# provenance_inode_setattr: `process_memory -memory_read-> task` and `task -setattr-> iattr` and `iattr -setattr_inode-> inode` must exist in this order
	# provenance_inode_setxattr: #TODO: Only versioning and naming exist in this hook? To be confused with provenance_inode_getsecurity # GitHub issue: Should do nothing
	# provenance_inode_symlink: `process_memory -memory_read-> task` and `task -symlink-> inode` must exist in this order
	# provenance_inode_unlink: `process_memory -memory_read-> task` and `task -unlink-> inode` must exist in this order
	# provenance_ipv4_out: `inode -send_packet-> packet` must be matched
	# provenance_mmap_file: #TODO: See above
	# provenance_mmap_munmap: #TODO: Why is munmap relationship optional? # GitHub: munmap should be reflected always? (Currently only non-private memory unmap is shown in provenance graph)
	# provenance_mq_timedreceive: `msg -receive_msg_queue-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_mq_timedsend: `process_memory -memory_read-> task` and `task -send_msg_queue-> msg` must exist in this order
	# provenance msg_msg_alloc_security: `process_memory -memory_read-> task` and `task -msg_create-> msg` must exist in this order
	# provenance msg_msg_free_security: `msg -free-> msg` must be matched
	# provenance_msg_queue_msgrcv: `/msg -receive_msg_queue-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_msg_queue_msgsnd: `process_memory -memory_read-> task` and `task -send_msg_queue-> msg` must exist in this order
	# provenance_shm_alloc_security: `process_memory -memory_read-> task` and `task -sh_create_read-> shm` and `process_memory -memory_read-> task` and `task -sh_create_write-> shm` must exist in this order
	# provenance_shm_free_security: `shm -free-> shm`
	# provenance_shm_shmat: we would expect one of the following that must exist in its order:
	# 1. `shm -sh_attach_read-> task` and `task -memory_write-> process_memory`
	# 2. `shm -sh_attach_read-> task` and `task -memory_write-> process_memory` and `process_memory -memory_read-> task` and `task -sh_attach_write-> shm`
	# provenance_shm_shmdt: `process_memory -memory_read-> task` and `task -shmdt-> shm` must exist in this order
	# provenance_sk_alloc_security: #TODO: Only versioning and namning exist in this hook? # GitHub: Should do nothing
	# provenance_socket_accept: `inode -accept_socket-> inode` and `inode -accept-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_socket_bind: `process_memory -memory_read-> task` and `task -bind-> inode` must exist in this order
	# provenance_socket_connect: `process_memory -memory_read-> task` and `task -connect-> inode` must exist in this order
	# provenance_socket_listen: `process_memory -memory_read-> task` and `task -listen-> inode` must exist in this order
	# provenance_socket_post_create: `process_memory -memory_read-> task` and `task -socket_create-> inode` must exist in this order
	# provenance_socket_recvmsg_always: `inode -receive_msg-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_socket_sendmsg_always: `process_memory -memory_read-> task` and `task -send_msg-> inode` must exist in this order
	# provenance_socket_sock_rcv_skb: `packet -receive_packet-> inode` must be matched
	# provenance_socket_socketpair: `process_memory -memory_read-> task` and `task -socket_pair_create-> inode` and `process_memory -memory_read-> task` and `task -socket_pair_create-> inode` must exist in this order
	# provenance_task_alloc: `process_memory -memory_read-> task` and `task -clone-> task` must exist in this order
	# provenance_task_fix_setuid: `process_memory -memory_read-> task` and `task -setuid-> process_memory` must exist in this order
	# provenance_task_free: `task -terminate_task -> task` must be matched
	# provenance_task_getpgid: `process_memory -getpgid-> task` and `task -memory_write-> process_memory` must exist in this order
	# provenance_task_setpgid: `process_memory -memory_read-> task` and `task -setpgid-> process_memory` must exist in this order
	# provenance_unix_may_send: `process_memory -send_unix-> inode` must be matched
	# provenance_unix_stream_connect: `process_memory -memory_read-> task` and `task -connect-> inode` must exist in this order #TODO: To be confused with provenance_socket_connect # GitHub: Use another name to be able to distinguish
	else:
		return True


def match_dfa(dfaname, dfa, G, canonical, hooks2indices, indices2hooks):
	"""Matches all motifs of dfa in the graph G.

	For every index x in @G, G[x] is the x'th edge in the graph (since the edges are ordered).
	In every iteration of the graph @G, we look for one complete matches of the NFA.
	We do many iterations until no more matches can be found.

	Arguments:
	dfaname: the name of the motif (dfa)
	dfa: the state machine that represents a motif
	G: the graph to match
	canonical: dictionary that returns the canonical ID of motif nodes
	hooks2indices: a dictionary that matches a hook to a list of lists of potential matches
	indices2hooks: a dictionary that matches each edge index to a list of hooks that match it

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
			# save the matching in memory
			if dfaname not in hooks2indices:
				hooks2indices[dfaname] = map(list, set(map(tuple, matches)))
			else:
				hooks2indices[dfaname].extend(map(list, set(map(tuple, matches))))
			# write the matching to a file for inspection
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
						indices_copy = copy.deepcopy(indices)
						# only considered matched if real indices are consecutive
						# and certain criteria are met (which are different for different hooks)
						if is_consecutive(real_indices_copy) and post_match_precheck(indices_copy, G, dfaname):
							matches.append(real_indices_copy)
							# now populate indices2hooks based on real_indices_copy array
							for idx in real_indices_copy:
								if int(idx) in indices2hooks:
									indices2hooks[int(idx)].add(dfaname)
								else:
									indices2hooks[int(idx)] = set()
									indices2hooks[int(idx)].add(dfaname)
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
	# save the matching in memory
	if dfaname not in hooks2indices:
		hooks2indices[dfaname] = map(list, set(map(tuple, matches)))
	else:
		hooks2indices[dfaname].extend(map(list, set(map(tuple, matches))))
	# write the matching to a file for inspection
	f.write(repr(map(list, set(map(tuple, matches)))))
	f.write("\n")
	# return matches


def match_dfa_wrapper(args):
	"""wrapper around match_dfa function so that multiprocessing pool can run with multiple arguments."""
	match_dfa(*args)
	# return match_dfa(*args)


def match_hooks(G_size, hooks2indices, indices2hooks, matched):
	"""
	Match the entire graph G with a set of hooks, chosen from all possibilities from the hooks in @hook_folder
	We match the graph from the very beginning and always matches the largest possible set begin with the starting index.
	For example, if we start from edges 1, 2, 3, 4, 5
	if a hook has options: [1, 2, 3] and [1, 2] we match [1, 2, 3]
	then we start to match from index 4.

	:param G_size: The entire graph size (total number of edges in the graph including all threads)
	:param hooks2indices: a dictionary that matches a hook to a list of lists of potential matches
	:param indices2hooks: a dictionary that matches each edge index to a list of hooks that match it
	:param matched: a matched dictionary from hook to a list of lists of matches
	"""
	real_index = 1
	while real_index <= G_size:
		longest_match_length = 0
		current_matched_hook = None
		current_matched_list = None

		if real_index not in indices2hooks:
			print('\x1b[6;30;41m[x]\x1b[0m [match_hooks] The edge {} is not matched'.format(real_index))
			exit(1)
		else:
			potential_hooks = indices2hooks[real_index]
		for ph in potential_hooks:
			potential_matches = hooks2indices[ph]
			for pm in potential_matches:
				if int(pm[0]) == real_index:
					if len(pm) > longest_match_length:
						current_matched_hook = ph
						current_matched_list = pm
						longest_match_length = len(pm)

		# at this point, we must find the best match for the current real_index
		# if not, then this index is mismatched, we need to reconsider this algorithm
		if current_matched_hook is None:
			print("The algorithm breaks at index {}.".format(real_index))
			exit(1)
		real_index = int(current_matched_list[-1]) + 1
		if current_matched_hook not in matched:
			matched[current_matched_hook] = [current_matched_list]
		else:
			matched[current_matched_hook].append(current_matched_list)





