# -*- coding: utf-8 -*-
# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

from __future__ import print_function

import logging
logger = logging.getLogger(__name__)

import tool as ct
import motif.motif as motif
import motif.mtree as mtree


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


def eval_func_body(func_name, func_body, func_dict, node_dict, name_dict):
    """Evaluate a Compound (function body is a Compound).

    Arguments:
    func_name       -- the name of the function whose body we are inspecting
    func_body       -- function body to be evaluated
    func_dict       -- dict that stores all function bodies
    node_dict       -- MotifNode dict
    name_dict       -- caller argument to callee paramter name dict

    Returns:
    a MotifNode and an RTMTree, both of which can be None."""
    node = None
    tree = None

    # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
    # The following goes through the declarations and statements in the function body
    for block in func_body.block_items:
        logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating {}".format(type(block).__name__))
        # Case 1: provenance-graph-related function call
        if type(block).__name__ == "FuncCall":
            node, subtree = eval_func_call(func_name, block, func_dict, node_dict, name_dict)
            if not subtree is None:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 2: rc = ...
        elif type(block).__name__ == "Assignment":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 3: declaration with initialization
        elif type(block).__name__ == "Decl":
            subtree = eval_decl(func_name, block, func_dict, node_dict, name_dict)
            if not subtree is None:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 4: if/else
        elif type(block).__name__ == "If":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 5: return with function call
        elif type(block).__name__ == 'Return':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 6: while block
        elif type(block).__name__ == 'While':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 7: unary operation such as: node_identifier(prov_elt(prov)).version++;
        elif type(block).__name__ == 'UnaryOp':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 8: goto
        elif type(block).__name__ == 'Goto':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 9: label associated with goto
        elif type(block).__name__ == 'Label':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 10: Switch statement
        elif type(block).__name__ == 'Switch':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 11: For loop
        elif type(block).__name__ == 'For':
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        else:
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))

    return node, tree


def eval_func_call(func_name, call, func_dict, node_dict, name_dict):
    """Evaluate a single function call.
    We may skip the function call if it is irrelevant to modeling, 
    or call eval_func_body to further evaluate the function call's body.
    For certain "basic" function calls, we generate motif elements.
    
    Arguments:
    func_name       -- the name of the caller function that calls this function
    call            -- function call to be evaluated
    func_dict       -- dict that stores all function bodies
    node_dict       -- MotifNode dict
    name_dict       -- caller argument to callee parameter name dict
    
    Returns:
    a MotifNode and an RTMTree, both of which can be None."""
    logger.debug('\x1b[6;30;42m[+]\x1b[0m Evaluating function call {} (core/core.py/eval_func_call)'.format(call.name.name))
    
    node = None
    tree = None

    # Base case 1: provenance_cred(), which returns a pointer to a process_memory node
    if call.name.name == "provenance_cred":
        node = motif.create_motif_node("process_memory")
    # Recursive case: go into a function body (if call is in @func_dict) to evaluate
    elif call.name.name in func_dict:
        # func_* are extracted from function definition by parse_funcs()
        func_body = func_dict[call.name.name]["body"]

        args = ["{}.{}".format(func_name, arg) for arg in ct.get_func_args(call)]
        params = ["{}.{}".format(call.name.name, param) for param in func_dict[call.name.name]["param"]]
        name_dict = ct.create_name_dict(args, params, name_dict)
        node, tree = eval_func_body(call.name.name, func_body, func_dict, node_dict, name_dict)
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping function call {} (core/core.py/eval_func_call)".format(call.name.name))
    
    return node, tree


def eval_decl(func_name, decl, func_dict, node_dict, name_dict):
    """Evaluate a single declaration that generates new TreeNodes.

    Arguments:
    func_name       -- the name of the function whose declaration statement we are inspecting
    decl            -- declaration to be evaluated
    func_dict       -- dict that stores all function bodies
    node_dict       -- MotifNode dict
    name_dict       -- caller argument to callee parameter name dict

    Returns:
    an RTMTree, which can be None."""
    # We are only concerned with declaration type "struct provenance" or "struct provenance *"
    # We define an inner function to check if the declaration type is provenance-related
    def prov_decl(decl):
        is_prov = False
        # Case 1: e.g., struct provenance *cprov = provenance_cred(cred); 
        if type(decl.type).__name__ == "PtrDecl" and \
           type(decl.type.type).__name__ == "TypeDecl" and \
           type(decl.type.type.type).__name__ == "Struct" and \
           decl.type.type.type.name == "provenance":
               is_prov = True

        return is_prov

    tree = None

    if prov_decl(decl):
        # In any case, since it is a declaration, the variable should not have already existed in @node_dict.
        # TODO: @node_dict will not work for recursion, we may have name conflicts that are justified!
        node_name = ct.get_global_name(ct.local_name(func_name, decl.name), name_dict)
        if node_name in node_dict:
            logger.fatal("\x1b[6;30;41m[x]\x1b[0m MotifNode named {} (globally, {}) has already existed. \
                    Please check naming conflict (core/core.py/eval_decl)".format(decl.name, node_name))
            raise RuntimeError("MotifNode has a global naming conflict")

        # Case 1: if the declaration is assigned by a function call
        if type(decl.init).__name__ == "FuncCall":
            node, tree = eval_func_call(func_name, decl.init, func_dict, node_dict, name_dict)
            if node is None:
                logger.fatal("\x1b[6;30;41m[x]\x1b[0m {} must be associated with a MotifNode (core/core.py/eval_decl)".format(decl.name))
                raise RuntimeError("MotifNode should not be None")
            else:
                node_dict[node_name] = [node]
        else:
            raise NotImplementedError("Declaration method {} is not properly implemented".format(type(decl.init).__name__))
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping declaration: {} (core/core.py/eval_decl)".format(ct.ast_snippet(decl)))
        
    return tree


# Quick module test
if __name__ == "__main__":
    import pycparser
    ast_hooks = pycparser.parse_file("../camflow-dev/security/provenance/hooks_pp.c")
    funcs = parse_funcs(ast_hooks)
    print(funcs)
