from __future__ import print_function
import sys
import os

from pycparser import c_parser, c_ast, parse_file

from static_analysis.parse import *
from gregex.rtm import visualize_rtm_tree, streamline_rtm
from gregex.graphviz import *
from gregex.converter import *
from gregex.ast import *

ast_hooks = parse_file("./camflow-dev/security/provenance/hooks_pp.c")
ast_inode = parse_file("./camflow-dev/security/provenance/include/provenance_inode_pp.h")
ast_net = parse_file("./camflow-dev/security/provenance/include/provenance_net_pp.h")
ast_record = parse_file("./camflow-dev/security/provenance/include/provenance_record_pp.h")
ast_task = parse_file("./camflow-dev/security/provenance/include/provenance_task_pp.h")

functions = dict()

list_functions(ast_hooks, functions)
list_functions(ast_inode, functions)
list_functions(ast_net, functions)
list_functions(ast_record, functions)
list_functions(ast_task, functions)

# eval_function_body(functions['provenance_inode_alloc_security'][1], functions, {})

# func_body = functions['get_arg_page'][1]
# print(func_body)

# TODO: NOTE hook `__mq_msgrcv` is a helper function and should not be analyzed as a hook!
func_body = functions['provenance_cred_prepare'][1]
motif_node_map = dict()
kernel_node = MotifNode('machine')
# TODO: `prov_machine` occurs in two different places, although they should represent the same machine.
# TODO: `prov_machine` is hard-coded.
motif_node_map['record_kernel_link.prov_machine'] = [kernel_node]
motif_node_map['record_influences_kernel.prov_machine'] = motif_node_map['record_kernel_link.prov_machine']
_, tree = eval_function_body('provenance_cred_prepare', func_body, functions, motif_node_map, {})
g = Graph()
streamline_rtm(tree)
visualize_rtm_tree(tree, g)
dot_str = g.get_graph()
with open('../dot/0' + '_tree.dot', 'w') as f:
    f.write(dot_str)
f.close()

# converter = Converter(tree)
# nfa = ast_to_nfa(converter.ast)
# print("\x1b[6;30;42m[+]\x1b[0m" + ' [test] Generating NFA')
# with open('../dot/0''_nfa.dot', 'w') as f:
#     nfa.print_graphviz(f)
# f.close()
#
# dfa = nfa.to_dfa()
# print("\x1b[6;30;42m[+]\x1b[0m" + ' [test] Generating DFA')
# with open('../dot/0' + '_dfa.dot', 'w') as f:
#     dfa.print_graphviz(f)
# f.close()

# for item in func_body.block_items:
# 	if type(item).__name__ == 'FuncCall':
# 		print(item.name.name)

# ast = parse_file("./camflow/hooks_pp.c")

# def version(ast):
# 	for ext in ast.ext:
# 		if type(ext).__name__ == 'FuncDef':
# 			function_decl = ext.decl
# 			# print(function_decl)
# 			function_name = function_decl.name
# 			function_arguments = function_decl.type.args.params
# 			if function_name == 'provenance_inode_getsecurity':
# 				# print(function_decl)
# 				function_body = ext.body
# 				print(function_body)
# 				# print(function_arguments[0].name)
# 				# print(function_arguments[0])

# version(ast)

# gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -D'bool=int' -D'uint32_t=int' -D'uint8_t=int' -D'uint16_t=int'  -E -Iutils/fake_libc_include hooks.c > hooks_pp.c

# import match_nfa as mnfa
# import gregex.dfa as gdfa
# from gregex.automaton import Diedge

# init = gdfa.DFAState()
# second = gdfa.DFAState()
# third = gdfa.DFAState(0)
# diedge1 = Diedge(2, 'f', 1, 'p', 'r')
# diedge2 = Diedge(1, 'p', 3, 'f', 'w')
# init.add_transition(diedge1, second)
# second.add_transition(diedge2, third)
# dfa = gdfa.DFA(init)

# e1 = ('p', 1, 'v', 'p', 2)
# e2 = ('f', 3, 'r', 'p', 2)
# e3 = ('p', 2, 'v', 'p', 6)
# e4 = ('p', 2, 'w', 'f', 4)
# e5 = ('f', 4, 'm', 'f', 5)
# G = [e1, e2, e3, e4, e5]

# matches = mnfa.match_dfa(dfa, G)
# print(matches)

