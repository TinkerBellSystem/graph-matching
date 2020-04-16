# -*- coding: utf-8 -*-
# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

from __future__ import print_function
from collections import OrderedDict

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

            # We declare an ordered dictionary to map parameter name to its type
            # It is ordered because we want the items to be aligned with the
            # arguments when we perform name mapping between parameters and
            # arguments.
            params = OrderedDict()
            # The following goes through the name and type of each argument.
            # type contains multiple fields such as "TypeDecl" and "IdentifierType"
            for param_decl in function_decl.type.args.params:
                params[param_decl.name] = param_decl.type
                # param_decl.type.show(offset=6)

            funcs[function_name] = {"params": params, "body": body}
    
    return funcs


def eval_func_body(func_name, func_body, context):
    """Evaluate a Compound (function body is a Compound).

    Arguments:
    func_name       -- the name of the function whose body we are inspecting
    func_body       -- function body to be evaluated
    context         -- contextual information, which contains:
                    funcs:  a dictionary that stores all function bodies
                    nodes:  a MotifNode dictionary
                    rels:   a relation dictionary
                    name:   a dictionary that maps caller argument to callee paramter

    Returns:
    a MotifNode and an RTMTree, both of which can be None."""
    node = None
    tree = None

    # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
    # The following goes through the declarations and statements in the function body
    for block in func_body.block_items:
        logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating {}: {} (core/core.py/eval_func_body)".format(type(block).__name__, ct.ast_snippet(block)))
        # Case 1: provenance-graph-related function call
        if type(block).__name__ == "FuncCall":
            node, subtree = eval_func_call(func_name, block, context)
            if subtree:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 2: rc = ...
        elif type(block).__name__ == "Assignment":
            subtree = eval_assign(func_name, block, context)
            if subtree:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 3: declaration with initialization
        elif type(block).__name__ == "Decl":
            subtree = eval_decl(func_name, block, context)
            if subtree:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 4: if/else
        elif type(block).__name__ == "If":
            subtree = eval_if(func_name, block, context)
            if subtree:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 5: return with function call
        elif type(block).__name__ == "Return":
            node, subtree = eval_ret(func_name, block, context)
            if subtree:
                tree = mtree.create_binary_node(".", tree, subtree)
        # Case 6: while block
        elif type(block).__name__ == "While":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 7: unary operation such as: node_identifier(prov_elt(prov)).version++;
        elif type(block).__name__ == "UnaryOp":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 8: goto
        elif type(block).__name__ == "Goto":
            logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {}: {} (core/core.py/eval_func_body)".format(type(block).__name__, ct.ast_snippet(block)))
        # Case 9: label associated with goto
        elif type(block).__name__ == "Label":
            logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {}: {} (core/core.py/eval_func_body)".format(type(block).__name__, ct.ast_snippet(block)))
        # Case 10: Switch statement
        elif type(block).__name__ == "Switch":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        # Case 11: For loop
        elif type(block).__name__ == "For":
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))
        else:
            raise NotImplementedError("{} is not properly implemented".format(type(block).__name__))

    return node, tree


def eval_func_call(func_name, call, context):
    """Evaluate a single function call.
    We may skip the function call if it is irrelevant to modeling, 
    or call eval_func_body to further evaluate the function call's body.
    For certain "basic" function calls, we generate motif elements.
    
    Arguments:
    func_name       -- the name of the caller function that calls this function
    call            -- function call to be evaluated
    context         -- contextual information

    Returns:
    a MotifNode and an RTMTree, both of which can be None."""
    # Name of the function call
    name = call.name.name
    # Call arguments in the function call
    args = ct.get_func_args(call)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating function call {} (core/core.py/eval_func_call)".format(name))
    
    node = None
    tree = None

    # Unpack contextual information to use
    func_dict = context["funcs"]
    node_dict = context["nodes"]
    rel_dict = context["rels"]
    name_dict = context["names"]

    # Base case 1: provenance_cred()
    if name == "provenance_cred":
        node = motif.create_motif_node("process_memory")
    # Base case 2: provenance_task()
    elif name == "provenance_task":
        node = motif.create_motif_node("task")
    # Base case 3: provenance_inode()
    elif name == "provenance_inode":
        node = motif.create_motif_node("inode")
    # Base case 4: record_terminate()
    # Function signature: static __always_inline int record_terminate(uint64_t type, struct provenance *prov)
    # TODO: can we remove this special case?
    elif name == "record_terminate":
        # Obtain the provenance node (latest version) to be terminated by name in node_dict.
        # This node is passed in as the second argument (prov) of the function call.
        node_name = ct.get_global_name(ct.local_name(func_name, args[1]), name_dict)
        old_node = node_dict[node_name][-1]
        # The terminate relation creates a new node of the same type (but a new version)
        # that connects the original node to show termination.
        # This node is returned.
        node = motif.create_motif_node(old_node.t)
        # Add the new node to the node_dict
        node_dict[node_name].append(node)
        # Create a terminate edge, the type of the edge 
        # is determined by the first argument (type) of
        # the function call.
        edge = motif.MotifEdge(old_node, node, ct.get_rel(rel_dict, args[0]))
        tree = mtree.create_leaf_node(edge)
    # Base case 5: update_inode_type()
    # Function signature: static inline void update_inode_type(uint16_t mode, struct provenance *prov)
    # TODO: can we remove this special case?
    elif name == "update_inode_type":
        # Obtain the provenance node (latest version) to be updated by name in node_dict.
        # This node is passed in as the second argument (prov) of the function call.
        node_name = ct.get_global_name(ct.local_name(func_name, args[1]), name_dict)
        old_node = node_dict[node_name][-1]
        # The update creates a new node of the same node type (but different inode type).
        # This node is returned.
        node = motif.create_motif_node(old_node.t)
        # Add the new node to the node_dict
        node_dict[node_name].append(node)
        # Create a version edge
        edge = motif.MotifEdge(old_node, node, ct.get_rel(rel_dict, "RL_VERSION"))
        # We also create a unary node because inode type update may or may not occur (check CamFlow code).
        tree = mtree.create_unary_node("?", mtree.create_leaf_node(edge))
    # Base case 6: alloc_long_provenance()
    # TODO: can we remove this special case?
    elif name == "alloc_long_provenance":
        t = args[0]
        node = motif.create_motif_node(ct.get_vtype(t))
    # Base case 7: __update_version()
    # Function signature: static __always_inline int __update_version(const uint64_t type, prov_entry_t *prov)
    # TODO: can we remove this special case?
    elif name == "__update_version":
        # Obtain the provenance node (latest version) to be updated by name in node_dict.
        # This node is passed in as the second argument (prov) of the function call.
        node_name = ct.get_global_name(ct.local_name(func_name, args[1]), name_dict)
        old_node = node_dict[node_name][-1]
        # If the node type is RL_VERSION_TASK, RL_VERSION, or RL_NAMED,
        # filter_update_node() will filter the node out, and no update;
        node_type = ct.get_global_name(ct.local_name(func_name, args[0]), name_dict).split(".")[1]
        if node_type == "RL_VERSION_TASK" or \
                node_type == "RL_VERSION" or \
                node_type == "RL_NAMED":
                    pass
        else:
            node = motif.create_motif_node(old_node.t)
            # Add the new node to the node_dict
            node_dict[node_name].append(node)
            if old_node.t == "task":
                edge = motif.MotifEdge(old_node, node, ct.get_rel(rel_dict, "RL_VERSION_TASK"))
            else:
                edge = motif.MotifEdge(old_node, node, ct.get_rel(rel_dict, "RL_VERSION"))
            tree = mtree.create_unary_node("?", mtree.create_leaf_node(edge))
    # Base case 8: __write_relation()
    # Function signature: static __always_inline int __write_relation(const uint64_t type, void *from, void *to, const struct file *file, const uint64_t flags)
    # TODO: can we remove this special case?
    elif name == "__write_relation":
        rel_name = ct.get_global_name(ct.local_name(func_name, args[0]), name_dict).split(".")[1]
        rel_type = ct.get_rel(rel_dict, rel_name)
        src_name = ct.get_global_name(ct.local_name(func_name, args[1]), name_dict)
        dst_name = ct.get_global_name(ct.local_name(func_name, args[2]), name_dict)
        src_node = node_dict[src_name][-1]
        dst_node = node_dict[dst_name][-1]
        edge = motif.MotifEdge(src_node, dst_node, rel_type)
        tree = mtree.create_leaf_node(edge)
    # The following function calls are EXPLICITLY skipped,
    # because at the time of coding, I am not sure if they
    # should actually be skipped or otherwise inspected.
    # TODO: Check with Thomas to make sure it is OK to skip them, then remove them from this list
    elif name == "init_provenance_struct":
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping function call {} (core/core.py/eval_func_call)".format(name))

    # Recursive case: go into a function body (if call is in @func_dict) to evaluate
    elif name in func_dict:
        # func_body and params are extracted from function definition using parse_funcs()
        func_body = func_dict[name]["body"]
        args = [ct.local_name(func_name, arg) for arg in args]
        params = [ct.local_name(name, param) for param in func_dict[name]["params"]]
        name_dict = ct.create_name_dict(args, params, name_dict)
        context["names"] = name_dict
        node, tree = eval_func_body(name, func_body, context)
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping function call {} (core/core.py/eval_func_call)".format(name))
    
    return node, tree


def eval_assign(func_name, assign, context):
    """Evaluate a single assignment that generates new TreeNodes.

    Arguments:
    func_name       -- the name of the function whose assignment statement we are inspecting
    assign          -- assignment to be evaluated
    context         -- contextual information

    Returns:
    an RTMTree, which can be None."""
    # Unpack contextual information to use
    node_dict = context["nodes"]
    name_dict = context["names"]

    tree = None
    # Case 1: where a provenance node was previously declared but not assigned.
    # and it is now assigned by a function, e.g.,
    # struct provenance *tprov;
    # tprov = provenance_task(t);
    if type(assign.rvalue).__name__ == "FuncCall":
        node, tree = eval_func_call(func_name, assign.rvalue, context)
        # Case 1: consider tprov = provenance_task(t);
        # tprov should have already been declared so it
        # should have been saved in node_dict.
        if type(assign.lvalue).__name__ == "ID":
            node_name = ct.get_global_name(ct.local_name(func_name, assign.lvalue.name), name_dict)
            if node_name in node_dict:
                if not node:
                    raise NotImplementedError("Node {} should not be None.".format(node_name))
                else:
                    node_dict[node_name].append(node)
            else:
                logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping function assignment of node {} (core/core.py/eval_assign) because no previous declaration is known".format(node_name))
        # Case 2: consider *tprov = ...
        # or &tprov = ...
        elif type(assign.lvalue).__name__ == 'UnaryOp':
            node_name = ct.get_global_name(ct.local_name(func_name, assign.lvalue.expr.name), name_dict)
            raise NotImplementedError("Node {} is not properly implemented.".format(node_name))
    # Case 2: where a provenance node was previously declared but not assigned.
    # We care only provenance nodes, for example, we consider this scenario:
    # struct provenance *tprov;
    # tprov = t->provenance;
    # Other ID assignments are ignored.
    # We populate those cases when we see them
    elif type(assign.lvalue).__name__ == "ID":
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {} assignment: {} (core/core.py/eval_assign)".format(type(assign.lvalue).__name__, ct.ast_snippet(assign)))
    # Case 3: e.g., prov_elt(prov)->inode_info.mode = mode;
    elif type(assign.lvalue).__name__ == "StructRef":
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {} assignment: {} (core/core.py/eval_assign)".format(type(assign.lvalue).__name__, ct.ast_snippet(assign)))
    # Case 4: e.g., prov_type(prov_elt(prov)) = type;
    elif type(assign.lvalue).__name__ == "FuncCall":
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {} assignment: {} (core/core.py/eval_assign)".format(type(assign.lvalue).__name__, ct.ast_snippet(assign)))
    else:
        raise NotImplementedError("Assignment method is not properly implemented")

    return tree


def eval_decl(func_name, decl, context):
    """Evaluate a single declaration that generates new TreeNodes.

    Arguments:
    func_name       -- the name of the function whose declaration statement we are inspecting
    decl            -- declaration to be evaluated
    context         -- contextual information

    Returns:
    an RTMTree, which can be None."""
    # We are only concerned with declaration type "struct provenance", "struct provenance *"
    # or "union long_prov_elt *". We define an inner function to check if the declaration 
    # type is provenance-related.
    def prov_decl(decl):
        is_prov = False
        # Case 1: e.g., struct provenance *cprov = provenance_cred(cred); 
        if type(decl.type).__name__ == "PtrDecl" and \
                type(decl.type.type).__name__ == "TypeDecl" and \
                type(decl.type.type.type).__name__ == "Struct" and \
                decl.type.type.type.name == "provenance":
                    is_prov = True
        # Case 2: e.g., union long_prov_elt *fname_prov;
        elif type(decl.type).__name__ == "PtrDecl" and \
                type(decl.type.type).__name__ == "TypeDecl" and \
                type(decl.type.type.type).__name__ == "Union" and \
                decl.type.type.type.name == "long_prov_elt":
                    is_prov = True

        return is_prov

    # Unpack contextual information to use
    func_dict = context["funcs"]
    node_dict = context["nodes"]
    name_dict = context["names"]

    tree = None

    if prov_decl(decl):
        # In any case, since it is a declaration, the variable should not have already existed in @node_dict.
        # TODO: @node_dict will not work for recursion (or calling the same function multiple times), we may 
        # have name conflicts that are justified!
        node_name = ct.get_global_name(ct.local_name(func_name, decl.name), name_dict)
        if node_name in node_dict:
            logger.fatal("\x1b[6;30;43m[!]\x1b[0m MotifNode named {} (globally, {}) has already existed. Please check naming conflict. We will reset this entry for now (core/core.py/eval_decl)".format(decl.name, node_name))

        # Case 1: if the declaration is assigned by a function call
        if type(decl.init).__name__ == "FuncCall":
            node, tree = eval_func_call(func_name, decl.init, context)
            if node is None:
                logger.fatal("\x1b[6;30;41m[x]\x1b[0m {} must be associated with a MotifNode (core/core.py/eval_decl)".format(decl.name))
                raise RuntimeError("MotifNode should not be None")
            else:
                node_dict[node_name] = [node]
        # Case 2: if it is not set when it is declare, 
        # then it must be set later, so we declare its
        # existence in node_dict with an empty list.
        elif type(decl.init).__name__ == "NoneType":
            node_dict[node_name] = list()
        else:
            raise NotImplementedError("Declaration method {} is not properly implemented".format(type(decl.init).__name__))
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping declaration: {} (core/core.py/eval_decl)".format(ct.ast_snippet(decl)))
        
    return tree


#NOTE: Implementation-specific function.
#TODO: Is it possible to generalize? Maybe change CamFlow design?
def eval_if_condition(func_name, condition, context):
    """Evaluate if condition. This function is very specific to the
    CamFlow code implementation, thus hardcoded and need to be modified
    if CamFlow code changes.

    Arguments:
    func_name       -- the name of the function whose if/else block we are inspecting
    condition       -- if condition
    context         -- contextual information

    Returns:
    True if the condition warrants for an alternation relation in RTMTree."""

    logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating if condition: {} (core/core.py/eval_if_condition)".format(ct.ast_snippet(condition)))
    check_condition = False
    if type(condition).__name__ == "BinaryOp":
        # We have yet seen any BinaryOp if condition we need to consider so far
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping if condition of type {} (core/core.py/eval_if_condition)".format(type(condition).__name__))
    elif type(condition).__name__ == "ID":
        # We have yet seen any ID if condition we need to consider so far
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping if condition of type {} (core/core.py/eval_if_condition)".format(type(condition).__name__))
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping if condition: {} (core/core.py/eval_if_condition)".format(ct.ast_snippet(condition)))

    return check_condition


def eval_if_branch(func_name, branch, context):
    """Evaluate a branch in if/else block, whether it is a if/else if/else branch.
    This is a helper function that eval_if function calls.

    Arguments:
    func_name       -- the name of the function whose if/else branch we are inspecting
    branch          -- the branch to be evaluate
    context         -- contextual information

    Returns:
    an RTMTree that represents the branch, which can be None."""
    tree = None
    if type(branch).__name__ == "FuncCall":
        _, tree = eval_func_call(func_name, branch, context)
    elif type(branch).__name__ == "Assignment":
        tree = eval_assign(func_name, branch, context)
    elif type(branch).__name__ == "Decl":
        tree = eval_decl(func_name, branch, context)
    elif type(branch).__name__ == "Return":
        _, tree = eval_ret(func_name, branch, context)
    elif type(branch).__name__ == "Compound":
        _, tree = eval_func_body(func_name, branch, context)
    elif type(branch).__name__ == "If":     # else if case
        tree = eval_if(func_name, branch, context)
    elif type(branch).__name__ == "Goto":
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping {}: {} (core/core.py/eval_if_branch)".format(type(branch).__name__, ct.ast_snippet(branch)))
    elif type(branch).__name__ == "While":
        raise NotImplementedError("{} is not properly implemented".format(type(branch).__name__))
    elif type(branch).__name__ == "Switch":
        raise NotImplementedError("{} is not properly implemented".format(type(branch).__name__))
    elif type(branch).__name__ == "For":
        raise NotImplementedError("{} is not properly implemented".format(type(branch).__name__))
    elif type(branch).__name__ == "NoneType":
        logger.debug("\x1b[6;30;42m[+]\x1b[0m Branch does not exist (core/core.py/eval_if_branch)")
    else:
        raise NotImplementedError("{} is not properly implemented".format(type(branch).__name__))
    
    return tree


def eval_if(func_name, block, context):
    """Evalaute a (nested) if/else block. Only if/else blocks that could potentially
    create MotifNodes or RTMTree are of interest to us. Some if/else condition
    checks are also of interest to us. Most if/else are for error handling only.

    Arguments:
    func_name       -- the name of the function whose if/else block we are inspecting
    block           -- the if/else block
    context         -- contextual information

    Returns:
    an RTMTree, which can be None."""
    # Only under some if condition do we actually create an alternation node
    if eval_if_condition(func_name, block.cond, context):
        raise NotImplementedError("If/else block is not properly implemented when if condition is checked")
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m If condition {} is skipped. We do not create an alternation RTMTreeNode (core/core.py/eval_if)".format(ct.ast_snippet(block.cond)))
        logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating true branch: {} (core/core.py/eval_if)".format(ct.ast_snippet(block.iftrue)))
        true_branch = eval_if_branch(func_name, block.iftrue, context)
        logger.debug("\x1b[6;30;42m[+]\x1b[0m Evaluating false branch: {} (core/core.py/eval_if)".format(ct.ast_snippet(block.iffalse)))
        false_branch = eval_if_branch(func_name, block.iffalse, context)

        if true_branch and false_branch:
            logger.warning("\x1b[6;30;43m[!]\x1b[0m Neither true nor false branch are None. Are you sure if condition is correctly checked? (core/core.py/eval_if)")
            raise NotImplementedError("Check if condition before removing this error.")
        
        if true_branch:
            return true_branch
        else:
            return false_branch


def eval_ret(func_name, ret, context):
    """Evaluate a single return statement that generates new MotifNode or TreeNodes.

    Argument:
    func_name       -- the name of the function whose assignment statement we are inspecting
    ret             -- the return statement to be evaluated
    context         -- contextual information

    Returns:
    a MotifNode and an RTMTree, both of which can be None."""
    # Unpack contextual information to use
    node_dict = context["nodes"]
    name_dict = context["names"]

    node = None
    tree = None

    if type(ret.expr).__name__ == 'FuncCall':
        node, tree = eval_func_call(func_name, ret.expr, context)
    elif type(ret.expr).__name__ == 'ID':
        # Obtain the global bame of the variable returned
        node_name = ct.get_global_name(ct.local_name(func_name, ret.expr.name), name_dict)
        if node_name in node_dict:
            node = node_dict[node_name][-1]
        else:
            # For example, "NULL" is returned.
            logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping return because of unrecognized ID: {} (core/core.py/eval_ret)".format(ret.expr.name))
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Skipping return: {} (core/core.py/eval_ret)".format(ct.ast_snippet(ret)))

    return node, tree

# Quick module test
if __name__ == "__main__":
    import pycparser
    ast_hooks = pycparser.parse_file("../camflow-dev/security/provenance/hooks_pp.c")
    funcs = parse_funcs(ast_hooks)
    print(funcs)
