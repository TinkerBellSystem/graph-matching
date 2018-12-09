from rtm_tree import MotifEdge
import copy

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

def find_submotif(hooknames, motifs):
	"""
	Find whether a motif in @motifs is a submotif (subgraph/substructure) of another motif in @motifs.
	For a motif A to be a submotif of another motif B,
	1. Each edge must match exactly.
	2. Temporal order must be obeyed exactly.

	We perform pair-wise comparison and compare both ends (i.e., A<->B).
	Given a list of motifs A B C D, we compare:
	A<->B, A<->C, A<->D, B<->C, B<->D, C<->D

	Submotif isomorphism is transitive.
	"""
	for i in range(len(motifs)):
		for j in range(i + 1, len(motifs)):
			submotif = submotif_relation(motifs[i], motifs[j], i, j)
			if submotif != None:
				print(hooknames[i] + " and " + hooknames[j] + ":" + hooknames[submotif] + " is the submotif.")

def version_maps(motif):
	"""
	Whenever we see a "version" 
	"""

def remap_motif(motif):
	"""
	Go through the RTM Tree to remap MotifNodes because of the "or" operator.
	"""
	pass


def expand_or(motif, motif_list):
	"""
	Expand the @motif to a list of motifs @motif_list
	"""

def expand_question_mark(motif):
	"""
	By expanding question mark, we create two copies of the original @motif,
	One that we replace question mark with '.' by calling @convert_question_mark
	and the other one we remove the branches with question marks by calling @remove_question_mark
	Therefore the function returns two motif if necessary, or the original @motif and None if no question mark is in the original @motif.
	"""
	dcopy = copy.deepcopy(motif)

	has_question_mark = []
	convert_question_mark(motif, has_question_mark)
	if len(has_question_mark) > 0:
		remove_question_mark(dcopy)
		return motif, dcopy
	else:
		return motif, None

def remap_after_remove_question_mark(motif, map):
	"""
	We must remap MotifNode IDs based on @map after we remove question mark branches. 
	@motif is the RTM tree with question mark branches removed.
	"""
	pass

def remove_question_mark(motif):
	"""
	We remove branches whose ancestor is a question mark '?' internal node.
	"""
	if not motif:
		return
	if motif.value == '?':
		motif.value = '.'
		motif.left = None
		motif.right = None
	if motif.left:
		remove_question_mark(motif.left)
	if motif.right:
		remove_question_mark(motif.right)

def convert_question_mark(motif, has_question_mark):
	"""
	We convert a question mark operator to a regular append '.' operator.
	@has_question_mark let us know if there is actually any convertion happened during this process.
	"""
	if not motif:
		return
	if motif.value == '?':
		motif.value = '.'
		has_question_mark.append(True)
	if motif.left:
		convert_question_mark(motif.left, has_question_mark)
	if motif.right:
		convert_question_mark(motif.right, has_question_mark)

def convert_star(motif):
	"""
	We consider a Kleene Star operator to be "zero or more repetitions".
	We thus can convert a Kleene star operator to a question mark operator, then call @expand_question_mark.
	"""
	if not motif:
		return
	if motif.value == '*':
		motif.value = '?'
	if motif.left:
		convert_star(motif.left)
	if motif.right:
		convert_star(motif.right)

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

def is_submotif(i, j):
	"""
	Check if @i is a submotif of @j.
	@i and @j are both basic motifs with no regular expression involved.
	"""
	pass

def submotif_relation(m_i, m_j, i, j):
	"""
	Find if there exists a submotif relationship between motif @m_i and @m_j by calling @is_submotif.
	If @m_i is a submotif of @m_j, return @i
	If @m_j is a submotif of @m_i, return @j
	Otherwise return None.
	"""

	if is_submotif(m_i, m_j):
		return i
	elif is_submotif(m_j, m_i):
		return j
	else:
		return None
