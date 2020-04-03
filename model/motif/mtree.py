# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
from __future__ import print_function


class RTMTreeNode:
    """
    A binary tree that represents the regular temporal motif (RTM) with regular 
    expression operators in the internal tree nodes and MotifEdges in the leaf nodes.

    Regular expression operators are:
    '*': zero or more times (i.e., an edge appears zero or more times)
    '+': one or more times (i.e., an edge appears one or more times)
    '?': zero or once (i.e., an edge appears zero or once)
    '{m, n}': m to n times (i.e., an edge appears m to n times)
    '{m, }': m or more times (i.e., an edge appears at least m times)
    '{m}': exactly m times (i.e., an edge appears exactly m times)
    '.': capturing group (i.e., a group of two edges appear together)
    '|': alternation (i.e., either edge A or edge B)

    A leaf node consists of:
    * A MotifEdge
	
    A unary internal node consists of:
    * Left child: A node (i.e., an internal operator node or a leaf node)
    * Right child: None
    * Value: A unary regular expression operator ('*', '+', '?', '{m, n}', '{m, }', '{m}')

    A binary internal node consists of:
    * Left and right child: a node (i.e., an internal operator node or a leaf node)
    * Value: A binary regular expression operator ('.', '|')

    Attributes:
    _left   -- left child of the node
    _right  -- right child of the node
    _value  -- value of the node
    _id     -- tree node ID"""

    uid = 0	 # unique node ID in a tree (for visualization)

    def __init__(self, value):
        """Constructor to create a node.
        _left, _right   -- a MotifEdge (i.e., leaf node), or an internal node
        _value          -- regular expression operator or a MotifEdge

        In the case of a leaf node: left, right are None
        In the case of a unary internal node: right is None."""

        self._left = None
        self._right = None
        self._value = value
        self.nid = RTMTreeNode.uid

        RTMTreeNode.update_uid()

    @property
    def left(self):
        return self._left

    @left.setter
    def left(self, left):
        self._left = left

    @property
    def right(self):
        return self._right

    @right.setter
    def right(self, right):
        self._right = right

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @classmethod
    def update_uid(cls):
        cls.uid += 1


def create_leaf_node(motif_edge):
    """This function creates a leaf node. The function that generates
    this leaf node at the lowest level is "__write_relation".
    'FuncCall', 'Assignment', and 'Decl' type with "__write_relation"
    can result in a leaf node.

    Arguments:
    motif_edge -- value of the leaf RTMTree node"""

    return RTMTreeNode(motif_edge)


def create_unary_node(value, left):
    """This function creates a unary internal node,
    which can be either "*" or "?".
    Shared memory read/write can result in "*"
    internal node.
    Version updates can result in "?" internal node.

    Argument:
    value   -- the "*" or "?" operator
    left    -- a leaf node or an internal node"""
    unary_node = RTMTreeNode(value)
    unary_node.left = left
    return unary_node


def create_binary_node(value, left, right):
    """This function creates a binary internal node,
    which can be either "." (group) or "|" (alternation).
    Compound block can result in group relation.
    "if/elif/else" block can result in alternation relation.
    Note that in both relations, either left or right can be
    None, but not both at the same time.
    
    Argument:
    value   -- the "." or "|" operator
    left    -- a leaf node or internal node or None
    right   -- a leaf node or internal node or None"""
    binary_node = RTMTreeNode(value)
    binary_node.left = left
    binary_node.right = right
    return binary_node

