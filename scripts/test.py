from __future__ import print_function
import sys
import os
import provenance as prov

from pycparser import c_parser, c_ast, parse_file

# ast = parse_file("../camflow/provenance_record_pp.h")
ast = parse_file("../camflow/hooks_pp.c")

def version(ast):
	for ext in ast.ext:
		if type(ext).__name__ == 'FuncDef':
			function_decl = ext.decl
			# print(function_decl)
			function_name = function_decl.name
			function_arguments = function_decl.type.args.params
			if function_name == 'provenance_bprm_check_security':
				function_body = ext.body
				print(function_body)
				# print(function_arguments[0].name)

version(ast)
