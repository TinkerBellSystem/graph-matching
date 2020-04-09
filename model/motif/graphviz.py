# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function
import re

class RTMGraph:
    def __init__(self):
        self.str = "digraph RGL__DirectedAdjacencyGraph {"
        self.objects = []

    def add_entity(self, name, is_op, value):
        if is_op:
            self.str += name
            self.str += "[fontsize = 8,label = \"" + value + "\",shape = ellipse, fillcolor=\"#e6e6fa\", style = filled]"
            self.str += "\n\n"
        else:
            if value == 'None':
                pass
            else:
                self.str += name
                self.str += "[fontsize = 8,label = \"" + value + "\",shape = rectangle, fillcolor=\"#fffacd\", style = filled]"
                self.str += "\n\n"

    def add_edge(self, src, dst):
        self.str += src + ' -> '+ dst
        self.str += "[fontsize = 8, color=\"#000000\"]"
        self.str += "\n\n"

    def get_graph(self):
        self.str += '}'
        return self.str

