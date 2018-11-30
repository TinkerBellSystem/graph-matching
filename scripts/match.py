# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import numpy as np

#TODO: G should be implemented as a map, not a matrix.
def findNextMatch(G, E, e_M, e_G, map_MG, map_GM, t, E_G, E_M, elm_G, elm_M, nlm_G, nlm_M):
"""
Finding the next matching temporal edge that matches edge e_M in the motif M.

G: numpy adjacency matrix of the graph G, with each element in the matrix identifying the indices of the edges incident from the corresponding nodes, i.e., G[i][j] = [e_G1, e_G2, ...].
E: a list of all edge indices in G. (Should not change unless G changes).
e_M: index into the sorted list of motif edges E_M.
e_G: index into the sorted list of graph edges E_G.
map_MG: a mapping of nodes in M (motif) to nodes in G (graph). An array of length |V_M| (i.e., the order of the motif M).
		If a node is not yet assigned to node in G, it will have a value of -1.
map_GM: a mapping of nodes in G (graph) to nodes in M (motif). An array of length |V_G| (i.e., the order of the graph G).
		If a node is not yet assigned to node in M, it will have a value of -1.
t: the latest time an edge can have in the matching motif, given the time for the first edge and delta.
	This is initially undefined until the first edge is matched and added, and it gets reset when all matched edges are unmapped.
E_G: a list of edges in G sorted chronologically by timestamp.
E_M: a list of edges in M sorted chronologically by timestamp.
elm_G: a mapping of edges in G (graph) to its label(s).
elm_M: a mapping of edges in M (motif) to its label(s).
nlm_G: a mapping of nodes in G (graph) to its label(s).
nlm_M: a mapping of nodes in M (motif) to its label(s). 
"""
	(u_M, v_M) = E_M[e_M]	# An edge is represented by a tuple of incident nodes. u_M is the source node of motif M and v_M is the destination node.
	
	# Check if u_M and v_M are already mapped before. If not, u_G and/or v_G will have a value of -1.
	u_G = map_MG[u_M]
	v_G = map_MG[v_M]

	# Determine the potential edges to try.
	S = []
	if u_G >= 0 and v_G >= 0:	# When both u_M and v_M have been mapped, we can only try to match edges incident to them.
		temp = G[u_G,v_G]
		for e in temp:
			# We check order and timestamp.
			if e >= e_G and elm_G[e].time <= t:
				S.append(e)
	elif u_G >= 0:	# When only u_G has been mapped, we can only try to match edges incident from u_G.
		temp = np.concatenate(G[u_G,:], axis=None)
		for e in temp:
			# We check order and timestamp.
			if e >= e_G and elm_G[e].time <= t:
				S.append(e)
	elif v_G >= 0:	# When only v_G has been mapped, we can only try to match edges incident to v_G.
		temp = np.concatenate(G[:,v_G], axis=None)
		for e in temp:
			# We check order and timestamp.
			if e >= e_G and elm_G[e].time <= t:
				S.append(e)
	else:	# Neither node has been mapped, all edges are possible
		S = E

	S.sort()
	# Try each edge in S until a perfect match is made
	# Since S is sorted, will always returned the earliest edge, if at all.
	for e in S:
		(u_G_prime, v_G_prime) = E_G[e]
		# The mapping must match or be unassigned.
		if u_G == u_G_prime or (u_G < 0 and map_GM[u_G_prime] < 0):
			if v_G == v_G_prime or (v_G < 0 and map_GM[v_G_prime] < 0):
				if elm_G[e].type == elm_M[e_M].type and nlm_G[u_G_prime].type == nlm_M[u_M].type and nlm_G[v_G_prime].type == nlm_M[v_M].type:
					return e

	# Reach here only if no match is found.
	return len(E_G)

def nextMotifEdge(M, ):
"""
Finding the next edge (temporally ordered) of the motif
"""

def motifMatch(G, M, delta, V_G, V_M, map_GM, map_MG):
"""
Finding all subgraphs in G isomorphic to the motif M.

G: numpy adjacency matrix of the graph G, with each element in the matrix identifying the indices of the edges incident from the corresponding nodes, i.e., G[i][j] = [e_G1, e_G2, ...].
"""

