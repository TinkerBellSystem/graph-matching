from __future__ import print_function
import sys
import os
import provenance_tree as prov

from pycparser import c_parser, c_ast, parse_file
from static_analysis.parse import *

ast_hooks = parse_file("./camflow/hooks_pp.c")
ast_inode = parse_file("./camflow/provenance_inode_pp.h")
ast_net = parse_file("./camflow/provenance_net_pp.h")
ast_record = parse_file("./camflow/provenance_record_pp.h")
ast_task = parse_file("./camflow/provenance_task_pp.h")

functions = dict()

list_functions(ast_hooks, functions)
list_functions(ast_inode, functions)
list_functions(ast_net, functions)
list_functions(ast_record, functions)
list_functions(ast_task, functions)

# eval_function_body(functions['provenance_inode_alloc_security'][1], functions, {})

print(functions['provenance_task_alloc'][0])
func_body = functions['provenance_task_alloc'][1]
eval_function_body(func_body, functions, {})


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

