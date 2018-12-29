# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

# Rules that the algorithm must follow:
#
## If No Other Operators But Concatenate (.) Operator:
### 1. We can match any leaf node of the tree. Once matched, we must check all of its ancestor (internal nodes) to make sure:
###		A. All leaf nodes to the left of the matched node have been matched before (join table has entries with smaller timestamps).
###		B. The new match does not create conflicts with matches of all leaf nodes to its left (at least one join does not fail because of conflits).
### 2. If rule (1) is met, update all internal nodes to remember this partial matching. 
###
## With ? Operator:
### 3. The leaf node whose parent internal node is a ? operator (i.e., versioning) needs only be optionally matched.
### 4. All leaf nodes to its right can correspond to either node ID (new or old version) in the RTM if the optional leaf node is ever matched, although the tree only shows the node ID of the newer version (i.e., the model assumes that the new version always exists).
### 5. If the optional leaf node is never matched, all nodes to its right must match to the old version.
### 6. If an edge is matched to the new version of the node, then all edges with larger timestamps must be matched to the new version as well.
### 7. All nodes to the right must match to the same version of the node in the model.
###
## With Or (|) Operator:
### 8. Leaf nodes who are children of the Or internal node must check all nodes to its left except those in the other branch of the Or internal node.
### 9. If nodes to the right of the leaf node under Or internal node need to be checked, then only those not in the other branch of the Or internal node need to be checked.
###
## With Kleene Star (*) Operator:
### 10. ?

### Questions to Think About:
### What data structures do we use for internal and leaf nodes to hold partial match information? 

