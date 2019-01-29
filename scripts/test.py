from __future__ import print_function
import sys
import os
import provenance_tree as prov

from pycparser import c_parser, c_ast, parse_file

# ast = parse_file("./camflow/provenance_record_pp.h")
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

import match_nfa as mnfa
import gregex.dfa as gdfa

init = gdfa.DFAState()
second = gdfa.DFAState()
third = gdfa.DFAState(0)
diedge1 = ('f', 2, 'r', 'p', 1)
diedge2 = ('p', 1, 'w', 'f', 3)
init.add_transition(diedge1, second)
second.add_transition(diedge2, third)
dfa = gdfa.DFA(init)

e1 = ('p', 1, 'v', 'p', 2)
e2 = ('f', 3, 'r', 'p', 2)
e3 = ('p', 2, 'w', 'f', 4)
e4 = ('f', 4, 'm', 'f', 5)
G = [e1, e2, e3, e4]

matches = mnfa.match_dfa(dfa, G)
print(matches)
