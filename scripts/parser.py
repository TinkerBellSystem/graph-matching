# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import sys
import json
import logging
import hashlib

# TODO: is it necessary to hash?
def hashgen(hashstr):
	hasher = hashlib.md5()
	hasher.update(hashstr)
	return hasher.hexdigest()

def nodeidgen(hashstr):
	hasher = hashlib.md5()
	hasher.update(hashstr)
	return int(hasher.hexdigest()[:8], 16) # make sure it is only 32 bits

class Node:
"""
A provenance node is identified by a unique identifier (@nid) and its type (@nty)
"""
	def __init__(self, nid, nty):
		self.nid = nid
		self.nty = nty

	def getnid(self):
		return self.nid

	def getnty(self):
		return self.nty

def _parse_nodes(json_string, nlm_G):
"""
Parsing nodes from a CamFlow provenance JSON string to 
@nlm_G: a mapping of nodes in G (graph) to its label.

Check nlm_G usage in match.py. 
"""
	json_object = json.loads(json_string)
	if "activity" in json_object:
		activity = json_object["activity"]
		for uid in activity:
			nid = nodeidgen(uid)
			if nid in nlm_G:
				logging.debug("The ID of the activity node shows up more than once: %s", uid)
			else:
				if "prov:type" not in activity[uid]:
					logging.debug("Skipping a problematic activity node with no 'prov:type'. ID: %s", uid)	# A node must have a type.
				else:
					nty = hashgen(activity[uid]["prov:type"])
					nlm_G[nid] = Node(nid, nty)

	if "entity" in json_object:
		entity = json_object["entity"]
		for uid in entity:
			nid = nodeidgen(uid)
			if nid in nlm_G:
				logging.debug("The ID of the entity node shows up more than once: %s", uid)
			else:
				if "prov:type" not in entity[uid]:
					logging.debug("Skipping a problematic entity node with no 'prov:type'. ID: %s", uid)
				else:
					nty = hashgen(activity[uid]["prov:type"])
					node_map[nid] = Node(nid, nty)

def parse_nodes(filename, nlm_G):
"""
Parsing nodes from CamFlow JSON provenance.
@nlm_G: a mapping of nodes in G (graph) to its label.
"""
	with open(filename) as f:
		for line in f:
			_parse_nodes(line, nlm_G)
		f.close()

def parse_edges(filename, nlm_G, elm_G, E_G, G):
"""
Parse timestamped edges from CamFlow JSON provenance.
@nlm_G: a mapping of nodes in G (graph) to its label.
@elm_G: a mapping of edges in G (graph) to its label(s).
@E_G: a list of edges in G sorted chronologically by timestamp.
@G: a mapping of tuple (source_nid, destination_nid) in G (graph) to a list of edge IDs i.e., G[i][j] = [e_G1, e_G2, ...].

Check nlm_G, elm_G, E_G, and G usages in match.py.
"""
	with open(filename) as f:
		for line in f:
			json_object = json.loads(line)
			
			if "used" in json_object:
				used = json_object["used"]
				for uid in used:
					from_id = used[uid]["prov:entity"]
					to_id = used[uid]["prov:activity"]
					if from_id not in node_map:
						logging.debug("Skipping an edge in 'used' because we cannot find the source node. Node ID: %s", from_id)
						continue
					if to_id not in node_map:
						logging.debug("Skipping an edge in 'used' because we cannot find the destination node. Node ID: %s", to_id)
						continue

					from_node = node_map[from_id]
					from_type = hashgen(from_node.getntype() + from_node.getsecctx() + from_node.getmode() + from_node.getname())

					to_node = node_map[to_id]
					to_type = hashgen(to_node.getntype() + to_node.getsecctx() + to_node.getmode() + to_node.getname())
					
					edge_id = used[uid]["cf:id"]	# Can be used as timestamp
					
					edge_flags = "N/A"
					if "cf:flags" in used[uid]:
						edge_flags = used[uid]["cf:flags"]
					edge_flags = hashgen(edge_flags)
					edge_type = hashgen(hashgen(used[uid]["prov:type"]) + edge_flags)

					output.write(str(from_node.getnid()) + '\t' + str(to_node.getnid()) + '\t' + from_type + ':' + to_type + ':' + edge_type + ':' + edge_id + '\t' + '\n')
			
			if "wasGeneratedBy" in json_object:
				wasGeneratedBy = json_object["wasGeneratedBy"]
				for uid in wasGeneratedBy:
					from_id = wasGeneratedBy[uid]["prov:activity"]
					to_id = wasGeneratedBy[uid]["prov:entity"]
					if from_id not in node_map:
						logging.debug("Skipping an edge in 'wasGeneratedBy' because we cannot find the source node. Node ID: %s", from_id)
						continue
					if to_id not in node_map:
						logging.debug("Skipping an edge in 'wasGeneratedBy' because we cannot find the destination node. Node ID: %s", to_id)
						continue

					from_node = node_map[from_id]
					from_type = hashgen(from_node.getntype() + from_node.getsecctx() + from_node.getmode() + from_node.getname())

					to_node = node_map[to_id]
					to_type = hashgen(to_node.getntype() + to_node.getsecctx() + to_node.getmode() + to_node.getname())

					edge_id = wasGeneratedBy[uid]["cf:id"]

					edge_flags = "N/A"
					if "cf:flags" in wasGeneratedBy[uid]:
						edge_flags = wasGeneratedBy[uid]["cf:flags"]
					edge_flags = hashgen(edge_flags)
					edge_type = hashgen(hashgen(wasGeneratedBy[uid]["prov:type"]) + edge_flags)
					
					output.write(str(from_node.getnid()) + '\t' + str(to_node.getnid()) + '\t' + from_type + ':' + to_type + ':' + edge_type + ':' + edge_id + '\t' + '\n')
			
			if "wasInformedBy" in json_object:
				wasInformedBy = json_object["wasInformedBy"]
				for uid in wasInformedBy:
					from_id = wasInformedBy[uid]["prov:informant"]
					to_id = wasInformedBy[uid]["prov:informed"]
					if from_id not in node_map:
						logging.debug("Skipping an edge in 'wasInformedBy' because we cannot find the source node. Node ID: %s", from_id)
						continue
					if to_id not in node_map:
						logging.debug("Skipping an edge in 'wasInformedBy' because we cannot find the destination node. Node ID: %s", to_id)
						continue

					from_node = node_map[from_id]
					from_type = hashgen(from_node.getntype() + from_node.getsecctx() + from_node.getmode() + from_node.getname())

					to_node = node_map[to_id]
					to_type = hashgen(to_node.getntype() + to_node.getsecctx() + to_node.getmode() + to_node.getname())

					edge_id = wasInformedBy[uid]["cf:id"]

					edge_flags = "N/A"
					if "cf:flags" in wasInformedBy[uid]:
						edge_flags = wasInformedBy[uid]["cf:flags"]
					edge_flags = hashgen(edge_flags)
					edge_type = hashgen(hashgen(wasInformedBy[uid]["prov:type"]) + edge_flags)

					output.write(str(from_node.getnid()) + '\t' + str(to_node.getnid()) + '\t' + from_type + ':' + to_type + ':' + edge_type + ':' + edge_id + '\t' + '\n')
					
			if "wasDerivedFrom" in json_object:
				wasDerivedFrom = json_object["wasDerivedFrom"]
				for uid in wasDerivedFrom:
					from_id = wasDerivedFrom[uid]["prov:usedEntity"]
					to_id = wasDerivedFrom[uid]["prov:generatedEntity"]
					if from_id not in node_map:
						logging.debug("Skipping an edge in 'wasDerivedFrom' because we cannot find the source node. Node ID: %s", from_id)
						continue
					if to_id not in node_map:
						logging.debug("Skipping an edge in 'wasDerivedFrom' because we cannot find the destination node. Node ID: %s", to_id)
						continue

					from_node = node_map[from_id]
					from_type = hashgen(from_node.getntype() + from_node.getsecctx() + from_node.getmode() + from_node.getname())
					
					to_node = node_map[to_id]
					to_type = hashgen(to_node.getntype() + to_node.getsecctx() + to_node.getmode() + to_node.getname())

					edge_id = wasDerivedFrom[uid]["cf:id"]

					edge_flags = "N/A"
					if "cf:flags" in wasDerivedFrom[uid]:
						edge_flags = wasDerivedFrom[uid]["cf:flags"]
					edge_flags = hashgen(edge_flags)
					edge_type = hashgen(hashgen(wasDerivedFrom[uid]["prov:type"]) + edge_flags)
					
					output.write(str(from_node.getnid()) + '\t' + str(to_node.getnid()) + '\t' + from_type + ':' + to_type + ':' + edge_type + ':' + edge_id + '\t' + '\n')
	
	f.close()
	output.close()


if __name__ == "__main__":
	if (len(sys.argv) < 3):
		print("""
			Usage: python prepare.py <input_file> <output_file_with_timestamp>
		"""
		)
		sys.exit(1)
	logging.basicConfig(filename='error.log',level=logging.DEBUG)

	node_map = {}
	parse_all_nodes(sys.argv[1], node_map)
	parse_all_edges(sys.argv[1], sys.argv[2], node_map)
