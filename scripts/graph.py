# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
import re

class Graph:
	def __init__(self):
		self.str = 'digraph RGL__DirectedAdjacencyGraph {'

	def add_entity(self, name):
		if name == 'task':
			self.str += name
			self.str += "[fontsize = 8,label = '+name+',shape = rectangle, fillcolor='#e6e6fa', style = filled]"
			self.str += "\n\n"
		else:
			self.str += name
			self.str += "[fontsize = 8,label = '+name+',shape = ellipse, fillcolor='#fffacd', style = filled]"
			self.str += "\n\n"

	def add_edge(self, fr, to, name):
		self.str += fr + ' -> '+ to
		self.str += "[fontsize = 8,label = '+name+']"
		self.str += "\n\n"

	def process_string(self, provenance_str):
		seen = []
		entries = provenance_str.split(',')
		for e in entries:
			elements = re.match(r"([a-z_]+)-([a-z_]+)->([a-z_]+)", e.strip())
			if elements.group(1) not in seen: 
				self.add_entity(elements.group(1))
				seen.append(elements.group(1))
			if elements.group(3) not in seen:
				self.add_entity(elements.group(3))
				seen.append(elements.group(3))
			if e not in seen:
				self.add_edge(elements.group(1), elements.group(3), elements.group(2))
				seen.append(e)

	def get_graph(self):
		self.str += '}'
		return self.str