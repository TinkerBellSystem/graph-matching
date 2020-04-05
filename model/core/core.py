# -*- coding: utf-8 -*-
# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

# PyCParser reference: https://github.com/eliben/pycparser
import logging
logger = logging.getLogger(__name__)


def parse_funcs(ast):
    """Parse all functions in an AST.

    Argument:
    ast     -- AST from a parsed C file. This "top" AST contains many function ASTs, among other things.

    Return:
    a dictionary that maps a function name to a tuple of (function parameters, function body)"""
    
    # We use PyCParser to parse CamFlow C files.
    # PyCParser must begin at the top level of the C files (which is @ast),
    # with either declarations or function definitions.
    # A C parser must also have all the types declared
    # to build the correct AST.

    # Uncomment the following line to see the AST in a nice, human
    # readable way. show() is the most useful tool in exploring ASTs
    # created by pycparser. See the c_ast.py file for the options you can pass to it.
    # ast.show(showcoord=True)

    # We've seen that the top node is FileAST. This is always the
    # top node of the AST. Its children are "external declarations",
    # and are stored in a list called ext[] (see _c_ast.cfg for the
    # names and types of Nodes and their children).

    # We declare a dictionary to be populated and returned.
    funcs = dict()

    # We go through each function definition that defines a hook.
    for ext in ast.ext:
        if type(ext).__name__ == 'FuncDef':
            # A FuncDef consists of a declaration, a list of parameter
            # declarations (for K&R style function definitions), and a body.
            # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
            body = ext.body
            # print(body)

            # function_decl, like any other declaration, is a Decl.
            # Its type child is a FuncDecl, which has a return type and arguments stored in a ParamList node
            function_decl = ext.decl
            # function_decl.type.show()
            # function_decl.type.args.show()

            # From declaration, we can also get the function name.
            function_name = function_decl.name

            # We declare a dictionary to map parameter name to its type
            params = dict()
            # The following goes through the name and type of each argument.
            # type contains multiple fields such as "TypeDecl" and "IdentifierType"
            for param_decl in function_decl.type.args.params:
                params[param_decl.name] = param_decl.type
                # param_decl.type.show(offset=6)

            funcs[function_name] = {"params": params, "body": body}
    
    return funcs


# Quick module test
if __name__ == "__main__":
    ast_hooks = pycparser.parse_file("./camflow-dev/security/provenance/hooks_pp.c")
    funcs = parse_funcs(ast_hooks)
    print(funcs)
