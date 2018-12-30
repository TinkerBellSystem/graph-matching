# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

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

def match_nfa(nfa, G, tracker):
	"""Matches all motifs of nfa in the graph G.

	For every index x in @G, G[x] is the x'th edge in the graph (since the edges are ordered).
	G[x] is either matched to the start state of the NFA @nfa,
	or G[x] is matched to one of the existing partial matches in the @tracker.

	@tracker remembers the state in which a partial match belongs to, and the mapping between the nodes in NFA and those in the graph @G. 

	Arguments:
	nfa: the state machine that represents a motif
	G: the graph to match
	tracker: a dictionary that tracks all intermediate states being matched and the correspondence between nodes in the motif and nodes in the graph.

	Returns:
	All sets of edge indices that belong to the same motif

	"""
	for index, edge in enumerate(G):
		
