# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2019 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import sys
import json
import logging
import hashlib
import argparse

def nodeidgen(hashstr):
	hasher = hashlib.md5()
	hasher.update(hashstr)
	return int(hasher.hexdigest()[:8], 16) # make sure it is only 32 bits

def _parse_nodes(json_string, nlm_G):
	"""Parsing nodes from a CamFlow provenance JSON string.

	Arguments:
	nlm_G -- A mapping of nodes in G (graph) to its label
	"""

	json_object = json.loads(json_string)
	if "activity" in json_object:
		activity = json_object["activity"]
		for uid in activity:
			if uid in nlm_G:
				logging.debug("the ID of the activity node shows up more than once: {}".format(uid))
			else:
				if "prov:type" not in activity[uid]:
					logging.debug("skipping a problematic activity node with no 'prov:type'. ID: {}".format(uid))
				else:
					nlm_G[uid] = activity[uid]["prov:type"]

	if "entity" in json_object:
		entity = json_object["entity"]
		for uid in entity:
			if uid in nlm_G:
				logging.debug("the ID of the entity node shows up more than once: {}".format(uid))
			else:
				if "prov:type" not in entity[uid]:
					logging.debug("skipping a problematic entity node with no 'prov:type'. ID: {}".format(uid))
				else:
					nlm_G[uid] = entity[uid]["prov:type"]

def parse_nodes(filename, nlm_G):
	"""Parsing nodes from CamFlow JSON provenance.

	Arguments:	
	nlm_G -- A mapping of nodes in G (graph) to its label
	"""
	with open(filename) as f:
		for line in f:
			_parse_nodes(line, nlm_G)
	f.close()

def parse_edges(filename, nlm_G, E_G):
	"""Parse timestamped edges from CamFlow JSON provenance.

	Arguments:
	nlm_G -- A mapping of nodes in G (graph) to its label
	E_G -- A list of edges in G sorted chronologically by timestamp
	"""

	with open(filename) as f:
		for line in f:
			json_object = json.loads(line)
			
			if "used" in json_object:
				used = json_object["used"]
				for uid in used:
					srcUID = used[uid]["prov:entity"]
					dstUID = used[uid]["prov:activity"]
					if srcUID not in nlm_G:
						logging.debug("skipping an edge in 'used' because we cannot find the source node. Node ID: {}".format(srcUID))
						continue
					if dstUID not in nlm_G:
						logging.debug("skipping an edge in 'used' because we cannot find the destination node. Node ID: {}".format(dstUID))
						continue

					srcTP = nlm_G[srcUID]
					dstTP = nlm_G[dstUID]
					
					edgeID = used[uid]["cf:id"]	# Can be used as timestamp
					edgeTP = used[uid]["prov:type"]

					E_G.append((srcTP, srcUID, edgeTP, dstTP, dstUID, edgeID))
			
			if "wasGeneratedBy" in json_object:
				wasGeneratedBy = json_object["wasGeneratedBy"]
				for uid in wasGeneratedBy:
					srcUID = wasGeneratedBy[uid]["prov:activity"]
					dstUID = wasGeneratedBy[uid]["prov:entity"]
					if srcUID not in nlm_G:
						logging.debug("skipping an edge in 'wasGeneratedBy' because we cannot find the source node. Node ID: {}".format(srcUID))
						continue
					if dstUID not in nlm_G:
						logging.debug("skipping an edge in 'wasGeneratedBy' because we cannot find the destination node. Node ID: {}".format(dstUID))
						continue

					srcTP = nlm_G[srcUID]
					dstTP = nlm_G[dstUID]

					edgeID = wasGeneratedBy[uid]["cf:id"]
					edgeTP = wasGeneratedBy[uid]["prov:type"]

					E_G.append((srcTP, srcUID, edgeTP, dstTP, dstUID, edgeID))
								
			if "wasInformedBy" in json_object:
				wasInformedBy = json_object["wasInformedBy"]
				for uid in wasInformedBy:
					srcUID = wasInformedBy[uid]["prov:informant"]
					dstUID = wasInformedBy[uid]["prov:informed"]
					if srcUID not in nlm_G:
						logging.debug("skipping an edge in 'wasInformedBy' because we cannot find the source node. Node ID: {}".format(srcUID))
						continue
					if dstUID not in nlm_G:
						logging.debug("skipping an edge in 'wasInformedBy' because we cannot find the destination node. Node ID: {}".format(dstUID))
						continue

					srcTP = nlm_G[srcUID]
					dstTP = nlm_G[dstUID]

					edgeID = wasInformedBy[uid]["cf:id"]
					edgeTP = wasInformedBy[uid]["prov:type"]

					E_G.append((srcTP, srcUID, edgeTP, dstTP, dstUID, edgeID))

			if "wasDerivedFrom" in json_object:
				wasDerivedFrom = json_object["wasDerivedFrom"]
				for uid in wasDerivedFrom:
					srcUID = wasDerivedFrom[uid]["prov:usedEntity"]
					dstUID = wasDerivedFrom[uid]["prov:generatedEntity"]
					if srcUID not in nlm_G:
						logging.debug("skipping an edge in 'wasDerivedFrom' because we cannot find the source node. Node ID: {}".format(srcUID))
						continue
					if dstUID not in nlm_G:
						logging.debug("skipping an edge in 'wasDerivedFrom' because we cannot find the destination node. Node ID: {}".format(dstUID))
						continue

					srcTP = nlm_G[srcUID]
					dstTP = nlm_G[dstUID]

					edgeID = wasDerivedFrom[uid]["cf:id"]
					edgeTP = wasDerivedFrom[uid]["prov:type"]

					E_G.append((srcTP, srcUID, edgeTP, dstTP, dstUID, edgeID))

	f.close()

def comp_two_edges(e1, e2):
	"""Comparison function for sorting edges based on timestamps.

	Arguments:
	e1 -- One edge
	e2 -- Another edge
	"""
	e1TS = long(e1[5])
	e2TS = long(e2[5])

	if e1TS > e2TS:
		return 1
	elif e1TS == e2TS:
		return 0
	else:
		return -1

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parse CamFlow Data for TinkerBell.')
	parser.add_argument('-v', '--verbose', action='store_true', help='increase console verbosity')
	parser.add_argument('-i', '--input', help='input datafile (CamFlow audit logs)', required=True)
	global args
	args = parser.parse_args()

	logging.basicConfig(filename='error.log',level=logging.DEBUG)

	nlm_G = dict()
	E_G = list()
	parse_nodes(args.input, nlm_G)
	parse_edges(args.input, nlm_G, E_G)
	E_G.sort(comp_two_edges)

