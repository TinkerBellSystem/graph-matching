from rtm_tree import MotifEdge
import copy
import itertools

def dict_to_list(motif_dict):
	"""
	For later computation, we convert the motif dictionary @motif_dict into a list of names and a list of motifs.
	"""
	hooknames = []
	motifs = []
	for hookname, motif in motif_dict.iteritems():
		hooknames.append(hookname)
		motifs.append(motif)
	return hooknames, motifs

def map_operator(motif, operator, motif_map, has_operator):
	"""
	We map in @motif_map "version_entity" and "version_activity" nodes in @motif.
	We also count the number of @operator in @motif. 
	@has_operator let us know if there is actually any @operator in @motif and how many.
	"""
	if not motif:
		return
	if motif.left:
		map_operator(motif.left, operator, motif_map, has_operator)
	if motif.value == operator:
		has_operator.append(True)
	elif isinstance(motif.value, MotifEdge):
		if motif.value.me_ty == 'version_entity' or motif.value.me_ty == 'version_activity':
			motif_map[motif.value.dst_node.mn_id] = motif.value.src_node.mn_id
	if motif.right:
		map_operator(motif.right, operator, motif_map, has_operator)

def __all_permutations(num):
	"""
	Return a list of permutation list of True and/or False.
	Each permutation list contains @num of Trues and/or Falses.
	For example if num == 2:
	[[True, True], [True, False], [False, True], [False, False]]
	"""
	permute_options = [[True, False]] * num
	return list(itertools.product(*permute_options))

def remap_after_remove_operator(motif, seen, motif_map):
	"""
	We must remap MotifNode IDs based on @motif_map after we remove @operator branches. 
	@motif is the RTM tree with @operator branches removed.
	@seen is a list of nodes seen in the @motif that are associated with "version_entity" or "version_activity"
	"""
	if not motif:
		return
	if motif.left:
		remap_after_remove_operator(motif.left, seen, motif_map)
	if isinstance(motif.value, MotifEdge):
		if motif.value.me_ty == 'version_entity' or motif.value.me_ty == 'version_activity':
			if motif.value.dst_node.mn_id not in seen:
				seen.append(motif.value.dst_node.mn_id)
			if motif.value.src_node.mn_id not in seen:
				seen.append(motif.value.src_node.mn_id)
		else:
			if motif.value.src_node.mn_id in motif_map:
				while motif.value.src_node.mn_id not in seen:
					if motif.value.src_node.mn_id in motif_map:
						motif.value.update_src_node(motif_map[motif.value.src_node.mn_id])
					else:
						break
			if motif.value.dst_node.mn_id in motif_map:
				while motif.value.dst_node.mn_id not in seen:
					if motif.value.dst_node.mn_id in motif_map:
						motif.value.update_dst_node(motif_map[motif.value.dst_node.mn_id])
					else:
						break
	if motif.right:
		remap_after_remove_operator(motif.right, seen, motif_map)

def remove_question_mark(motif, permutation, pos):
	"""
	We remove some branches whose ancestor is a question mark '?' internal node,
	and convert some internal '?' to '.'
	based on @permutation and @pos.
	If @permutation[len(@pos)] is True, we remove the branch; otherwise we convert it.
	"""
	if not motif:
		return
	if motif.left:
		remove_question_mark(motif.left, permutation, pos)
	if motif.value == '?':
		if permutation[len(pos)] == True:
			motif.value = '.'
			motif.left = None
			motif.right = None
			pos.append(True)
		else:
			motif.value = '.'
			pos.append(False)
	if motif.right:
		remove_question_mark(motif.right, permutation, pos)

def expand_question_mark(motif):
	"""
	By expanding question mark, we create 2^X copies of the original @motif,
	One that we replace all question mark with '.' by calling @convert_question_mark
	and the rest we remove or keep (as append) the branches with question marks with different permutations by calling @remove_question_mark
	Therefore the function returns a list of motifs.
	Some motifs may overlap since some question marks are ancestors of other question marks. (We will do some redundant work but this is OK.)
	"""
	has_question_mark = []
	motif_map = {}
	map_operator(motif, '?', motif_map, has_question_mark)
	num_question_marks = len(has_question_mark)
	permutations = __all_permutations(num_question_marks)

	list_of_motifs = []
	for i in range(len(permutations)):
		permutation = permutations[i]
		dcopy = copy.deepcopy(motif)
		remove_question_mark(dcopy, permutation, [])
		remap_after_remove_operator(dcopy, [], motif_map)
		list_of_motifs.append(dcopy)
	return list_of_motifs

def remove_or(motif, permutation, pos):
	"""
	We remove one child whose ancestor is an or ('|') internal node
	and keep the other child
	based on @permutation and @pos.
	If @permutation[len(@pos)] is True, we keep the left branch and remove the right one; otherwise we do the opposite.
	"""
	if not motif:
		return
	if motif.left:
		remove_or(motif.left, permutation, pos)
	if motif.value == '|':
		if permutation[len(pos)] == True:
			motif.value = '.'
			motif.right = None
			pos.append(True)
		else:
			motif.value = '.'
			motif.left = None
			pos.append(False)
	if motif.right:
		remove_or(motif.right, permutation, pos)

def expand_or(motif):
	"""
	By expanding or, we create 2^X copies of the original @motif,
	The function returns a list of motifs.
	Some motifs may overlap since some ors are ancestors of other ors. (We will do some redundant work but this is OK.)
	"""
	has_or = []
	motif_map = {}
	map_operator(motif, '|', motif_map, has_or)
	num_ors = len(has_or)
	permutations = __all_permutations(num_ors)

	list_of_motifs = []
	for i in range(len(permutations)):
		permutation = permutations[i]
		dcopy = copy.deepcopy(motif)
		remove_or(dcopy, permutation, [])
		remap_after_remove_operator(dcopy, [], motif_map)
		list_of_motifs.append(dcopy)
	return list_of_motifs

def convert_star(motif):
	"""
	We consider a Kleene Star operator to be "zero or more repetitions".
	We thus can convert a Kleene star operator to a question mark operator.
	"""
	if not motif:
		return
	if motif.left:
		convert_star(motif.left)
	if motif.value == '*':
		motif.update_value('?')
	if motif.right:
		convert_star(motif.right)

def combine_question_mark(motif):
	"""
	After @convert_star, a motif may have a question mark internal node followed only by another question mark internal node.
	We combine them and keep only one question mark operator internal node. 
	"""
	if not motif:
		return
	if motif.value == '?':
		if motif.left and motif.right:
			# if both left and right children exist, it is unlikely that we will have ? <- ? -> ? structure.
			# We will convert the left and right question mark children to '.' children if we encounter them
			# Now we simply print something to alert us should such situation arises.
			if motif.left.value == '?' and motif.right.value == '?':
				print("Unexpected Scenario. Check Hook Function.")
				exit(1)
			else:
				# we cannot combine question marks in situations such as ? <- ? -> |
				combine_question_mark(motif.left)
				combine_question_mark(motif.right)
		elif motif.left:
			if motif.left.value == '?':
				# Case: ? <- ? -> None
				motif.left = motif.left.left
				motif.right = motif.left.right
				# need to check again in case of ? <- ? <- ?
				combine_question_mark(motif)
		elif motif.right:
			if motif.right.value == '?':
				# Case:  ? -> ?
				motif.left = motif.right.left
				motif.right = motif.right.right
				# need to check again in case of ? -> ? -> ?
				combine_question_mark(motif)
		else:
			# we cannot have something like None <- ? -> None
			print("\33[101m" + "[ERROR][combine_question_mark]. An internal node cannot connect to both None children." + "\033[0m")
			exit(1)
	else:
		combine_question_mark(motif.left)
		combine_question_mark(motif.right)

def is_regular_operator(c):
	if c == '?' or c == '*' or c == '|':
		return True
	else:
		return False

def tree_to_list(motif, edge_list):
	"""
	Convert a basic @motif tree (with no regular expression involved) to a list of edges @edge_list.
	The order in the list is the temporal order of the basic motif.
	"""
	if not motif:
		return
	if motif.left:
		tree_to_list(motif.left, edge_list)
	if motif.value == '.':
		pass
	elif isinstance(motif.value, MotifEdge):
		edge_list.append(motif.value)
	elif is_regular_operator(motif.value):
		print('\33[5;30;103m[ERROR]' + str(motif.value) + " should not be in basic motif." + '\033[0m')
		exit(1)
	else:
		print('\33[5;30;103m[ERROR]' + motif.value.__class__ + ' Unknown motif type.\033[0m')
		exit(1)
	if motif.right:
		tree_to_list(motif.right, edge_list)

def matches(e1, e2, node_map):
	"""
	Test whether MotifEdge @e1 can be matched to MotifEdge @e2.
	node_map makes sure corresponding nodes are matched perfectly.
	Return True if they match; False otherwise.
	"""
	if e1.me_ty == e2.me_ty and e1.src_node.mn_ty == e2.src_node.mn_ty and e1.dst_node.mn_ty == e2.dst_node.mn_ty:
		if e1.src_node.mn_id not in node_map:
			node_map[e1.src_node.mn_id] = e2.src_node.mn_id
		else:
			if node_map[e1.src_node.mn_id] != e2.src_node.mn_id:
				return False
		if e1.dst_node.mn_id not in node_map:
			node_map[e1.dst_node.mn_id] = e2.dst_node.mn_id
		else:
			if node_map[e1.dst_node.mn_id] != e2.dst_node.mn_id:
				return False
		return True
	else:
		return False

def partial_match(l_a, l_b, node_map):
	"""
	A very costly partial match function.
	@l_a is the list of edges that need to be matched to @l_b.
	We are trying to figure out if @l_a can be a subgraph of @l_b.

	"""
	matched = False
	for i in range(len(l_b)):
		dcopy = copy.deepcopy(node_map)
		if matches(l_a[0], l_b[i], dcopy):
			if len(l_a) > 1:
				matched = partial_match(l_a[1:], l_b[i:], dcopy)
				if matched:
					break
			else:
				return True
	return matched

def perfect_partial_match(l_a, l_b, node_map):
	"""
	In this case,
	@l_a must be matched completely from the beginning of @l_b, and every edge needs to be matched in the exact, consecutive sequence.
	"""
	matched = False
	if matches(l_a[0], l_b[0], node_map):
		if len(l_a) > 1:
			matched = perfect_partial_match(l_a[1:], l_b[1:], node_map)
	return matched

def is_submotif(i, j, is_perfect):
	"""
	Check if @i is a submotif of @j.
	@i and @j are both basic motifs with no regular expression involved.
	"""
	i_list = []
	j_list = []
	tree_to_list(i, i_list)
	tree_to_list(j, j_list)

	if len(i_list) > len(j_list):
		return False
	if len(i_list) == 0 or len(j_list) == 0:
		return False
	else:
		if is_perfect:
			return perfect_partial_match(i_list, j_list, {})
		else:
			return partial_match(i_list, j_list, {})

def submotif_relation(m_i, m_j, is_perfect):
	"""
	Find if there exists a submotif relationship between basic motif @m_i and @m_j by calling @is_submotif.
	If @m_i is a submotif of @m_j, return True
	If @m_j is a submotif of @m_i, return True
	Otherwise return False.
	"""

	if is_submotif(m_i, m_j, is_perfect):
		return True
	elif is_submotif(m_j, m_i, is_perfect):
		return True
	else:
		return False

def submotif(motif_list_i, motif_list_j, is_perfect):
	"""
	Find whether a motif in @motif_list_i is a submotif (subgraph/substructure) of another motif in @motif_list_j.
	
	For a motif A to be a submotif of another motif B,
	1. Each edge must match exactly.
	2. Temporal order must be obeyed exactly.

	We perform pair-wise comparison and compare both ends (i.e., A<->B).
	Given a list of motifs A B C D, we compare:
	A<->B, A<->C, A<->D, B<->C, B<->D, C<->D

	Submotif isomorphism is transitive.

	All motifs (no regular expression involved, i.e., basic) in the same list are different versions of the same RTM Tree, thus representing the same tree.
	"""
	submotif = False
	for m_i in motif_list_i:
		for m_j in motif_list_j:
			submotif = submotif or submotif_relation(m_i, m_j, is_perfect)
	return submotif


