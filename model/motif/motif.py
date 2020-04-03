# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function


class MotifNode():
    """A node in the motif.

    Attributes:
    _id                 -- unique ID of the node (protected)
    _t                  -- type of the node in the motif (protected)
    has_outgoing        -- whether the node has outgoing edges (default to False when it is initialized)
    has_name_recorded   -- whether the node has its path name recorded already (default to False when it is initialized) 
    kernel_version      -- the kernel version associated with the node (default to 0)
    is_initialized      -- if the node is initialized (default to False)"""

    # Within a motif, ID is made unique by using a class 
    # variable, which is shared among all class instances.
    uid = 0

    def __init__(self, t):
        self._id = MotifNode.uid
        self._t = t
        self.has_outgoing = False
        self.has_name_recorded = False
        self.kernel_version = 0
        self.is_initialized = False

        MotifNode.update_uid()

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, nid):
        self._id = nid

    # property "t" is read-only, since
    # its setter is not defined. Once the
    # protected attribute "_t" is initialized,
    # one cannot modify it through "t"
    # note that Python has no real way to
    # protect an attribute or make an
    # attribute truly private (even with double
    # underscore, one can still access it
    # with the obfuscated name).
    @property
    def t(self):
        return self._t

    @classmethod
    def update_uid(cls):
        cls.uid += 1

    def __eq__(self, other):
        return self.id == other.id and self.t == other.t


class MotifEdge:
    """An edge in the motif.

    Attributes:
    _src     -- source MotifNode of the egde (protected)
    _dst     -- destination MotifNode of the edge (protected)
    _t       -- type of the edge in the motif (protected)"""

    def __init__(self, src, dst, t):
        self._src = src
        self._dst = dst
        self._t = t

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @property
    def t(self):
        return self._t

    def update_src_id(self, nid):
        self.src.id = nid

    def update_dst_id(self, nid):
        self.dst.id = nid

    def __repr__(self):
        return "{}({})--[{}]-->{}({})".format(self.src.id, self.src.t, self.t, self.dst.id, self.dst.t)


def create_motif_node(t):
    """If a motif node is never explicitly defined by 
    e.g., alloc_provenance() or get_cred_provenance(),
    we will create a new motif node on the fly.

    Arguments:
    t   -- type of the motif node (after translated by provenance_vertex_type())"""

    return MotifNode(t)

