# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

from __future__ import print_function
import sys
import os
import provenance_graph as prov
from gregex.rtm import *
from graph import *

from pycparser import c_parser, c_ast, parse_file

def get_arg_name(args):
    """
    Get names of function arguments.
    """
    names = []
    for arg in args:
        if type(arg).__name__ == 'ID':
            names.append(arg.name)
        elif type(arg).__name__ == 'UnaryOp':
            names.append(arg.expr.name)
    return names

def eval_prov_func_call(func_call, ast):
    """
    Evaluate a single function call that directly generates relations.
    """
    if func_call.name.name == 'uses' or func_call.name.name == 'generates':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        func = None
        for ext in ast.ext:
            if type(ext).__name__ == 'FuncDef':
                function_decl = ext.decl
                function_name = function_decl.name
                if function_name == func_call.name.name:
                    func = ext
        if func == None:
            print('\33[103m' + '[error]: cannot find: '+ func_call.name.name + '\033[0m')
            exit()
        else:
            return prov.relation_with_four_args(func, arg_names[0], arg_names[1], arg_names[2], arg_names[3])
    elif func_call.name.name == 'derives' or func_call.name.name == 'informs' or func_call.name.name == 'uses_two':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        func = None
        for ext in ast.ext:
            if type(ext).__name__ == 'FuncDef':
                function_decl = ext.decl
                function_name = function_decl.name
                if function_name == func_call.name.name:
                    func = ext
        if func == None:
            print('\33[103m' + '[error]: cannot find: '+ func_call.name.name + '\033[0m')
            exit()
        else:
            return prov.relation_with_three_args(func, arg_names[0], arg_names[1], arg_names[2])
    elif func_call.name.name == 'get_cred_provenance':
        return prov.get_cred_provenance_to_relation()
    elif func_call.name.name == 'inode_provenance':
        return prov.inode_provenance_to_relation()
    elif func_call.name.name == 'dentry_provenance':
        return prov.inode_provenance_to_relation()
    elif func_call.name.name == 'file_provenance':
        return prov.inode_provenance_to_relation()
    elif func_call.name.name == 'refresh_inode_provenance':
        return prov.inode_provenance_to_relation()
    elif func_call.name.name == 'provenance_record_address':
        return prov.provenance_record_address_to_relation()
    elif func_call.name.name == 'record_write_xattr':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.record_write_xattr_to_relation(arg_names[0])
    elif func_call.name.name == 'record_read_xattr':
        return prov.record_read_xattr_to_relation()
    elif func_call.name.name == 'provenance_packet_content':
        return prov.provenance_packet_content_to_relation()
    elif func_call.name.name == 'prov_record_args':
        return prov.prov_record_args_to_relation()
    elif func_call.name.name == 'record_terminate':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.record_terminate_to_relation(arg_names[0], arg_names[1])
    elif func_call.name.name == 'influences_kernel':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.influences_kernel_to_relation(arg_names[0], arg_names[1], arg_names[2])
    else:
        return None

def eval_assignment(assignment, ast):
    """
    Evaluate a single assignment that directly generates a relation.
    """
    if type(assignment.rvalue).__name__ == 'FuncCall':
        return eval_prov_func_call(assignment.rvalue, ast)
    else:
        return None

def eval_declaration(declaration, ast):
    """
    Evaluate a single declaration that directly generates a relation.
    """
    if type(declaration.init).__name__ == 'FuncCall':
        return eval_prov_func_call(declaration.init, ast)
    else:
        return None

def eval_return(statement, ast):
    """
    Evaluate a single return statement that directly generates a relation.
    """
    if type(statement.expr).__name__ == 'FuncCall':
        return eval_prov_func_call(statement.expr, ast)
    else:
        return None

def eval_if_else(item, ast):
    """
    Evaluate (nesting) if/else blocks.
    """
    true_branch = item.iftrue

    if type(true_branch).__name__ == 'FuncCall':
        left = eval_prov_func_call(true_branch, ast)
    elif type(true_branch).__name__ == 'Assignment':
        left = eval_assignment(true_branch, ast)
    elif type(true_branch).__name__ == 'Decl':
        left = eval_declaration(true_branch, ast)
    elif type(true_branch).__name__ == 'Return':
        left = eval_return(true_branch, ast)
    elif type(true_branch).__name__ == 'Compound':
        left = eval_function_body(true_branch, ast)
    else:
        left = None
    
    false_branch = item.iffalse

    if type(false_branch).__name__ == 'FuncCall':
        right = eval_prov_func_call(false_branch, ast)
    elif type(false_branch).__name__ == 'Assignment':
        right = eval_assignment(false_branch, ast)
    elif type(false_branch).__name__ == 'Decl':
        right = eval_declaration(false_branch, ast)
    elif type(false_branch).__name__ == 'Return':
        right = eval_return(false_branch, ast)
    elif type(false_branch).__name__ == 'Compound':
        right = eval_function_body(false_branch, ast)
    elif type(false_branch).__name__ == 'If':   # else if case
        right = eval_if_else(false_branch, ast)
    else:
        right = None

    if left != None or right != None:
        return prov.create_alternation_relation(left, right)
    else:
        return None

def eval_function_body(function_body, ast):
    """
    Evaluate a Compound function body.
    """
    # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
    # The following goes through the declarations and statements in the function body
    relation = None
    for item in function_body.block_items:
        if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
            right = eval_prov_func_call(item, ast)
            if right == None and relation == None:
                relation = None
            else:
                relation = prov.create_group_relation(relation, right)
        elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
            right = eval_assignment(item, ast)
            if right == None and relation == None:
                relation = None
            else:
                relation = prov.create_group_relation(relation, right)
        elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
            right = eval_declaration(item, ast)
            if right == None and relation == None:
                relation = None
            else:
                relation = prov.create_group_relation(relation, right)
        elif type(item).__name__ == 'If':   # Case 4: if
            right = eval_if_else(item, ast)
            if right == None and relation == None:
                relation = None
            else:
                relation = prov.create_group_relation(relation, right)
        elif type(item).__name__ == 'Return':   # Case 5: return with function call
            right = eval_return(item, ast)
            if right == None and relation == None:
                relation = None
            else:
                relation = prov.create_group_relation(relation, right)
    return relation

def eval_hook(function_body, ast):
    """
    Evaluate function body of each hook function to generate its regular temporal motif.
    """
    motif = RegularTemporalMotif()
    motif.add_relation(eval_function_body(function_body, ast))
    return motif

# PyCParser must begin at the top level of the C files,
# with either declarations or function definitions.

# A C parser must also have all the types declared
# to build the correct AST. 

# Parse the preprocessed hooks.c file.
ast = parse_file("./camflow/hooks_pp.c")
record_ast = parse_file("./camflow/provenance_record_pp.h")
# Uncomment the following line to see the AST in a nice, human
# readable way. show() is the most useful tool in exploring ASTs
# created by pycparser. See the c_ast.py file for the options you
# can pass it.

# ast.show(showcoord=True)

# We've seen that the top node is FileAST. This is always the
# top node of the AST. Its children are "external declarations",
# and are stored in a list called ext[] (see _c_ast.cfg for the
# names and types of Nodes and their children).

# A dictionary that saves a motif for each hook.
hooks = {}

# We go through each function definition that defines a hook.
for ext in ast.ext:
    if type(ext).__name__ == 'FuncDef':
        # A FuncDef consists of a declaration, a list of parameter
        # declarations (for K&R style function definitions), and a body.
        # function_decl, like any other declaration, is a Decl.
        # Its type child is a FuncDecl, which has a return type and arguments stored in a ParamList node
        function_decl = ext.decl
        # From declaration, we can also get the function name.
        function_name = function_decl.name
        # function_decl.type.show()
        # function_decl.type.args.show()
        # The following displays the name and type of each argument:
        #for param_decl in function_decl.type.args.params:
            #print('Arg name: %s' % param_decl.name)
            #print('Type:')
            #param_decl.type.show(offset=6)

        # Now we only care about functions that are hook definitions
        # Their names all start with "provenance",
        # with the exception that some calls "__mq_msgsnd", and "__mq_msgrcv" that contain real definitons. 
        # We deal with "__mq_msgsnd", and "__mq_msgrcv" first,
        # Then go through all the rest of the functions again.
        if function_name.startswith("__mq_msgsnd") or function_name.startswith("__mq_msgrcv"):
            # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
            function_body = ext.body
            # print(function_body)
            motif = eval_hook(function_body, record_ast)
            hooks[function_name] = motif
        
# We go through each hook function again to draw model graphs.
for ext in ast.ext:
    if type(ext).__name__ == 'FuncDef':
        function_decl = ext.decl
        function_name = function_decl.name

        # We skip those that are not explicitly defined
        if function_name != 'provenance_socket_sendmsg' or function_name != 'provenance_socket_recvmsg' or function_name != 'provenance_inode_rename' or function_name != 'provenance_msg_queue_msgsnd' or function_name != 'provenance_mq_timedsend' or function_name != 'provenance_msg_queue_msgrcv' or function_name != 'provenance_mq_timedreceive' or function_name != "__mq_msgsnd" or function_name != "__mq_msgrcv":
            function_body = ext.body
            if function_body.block_items != None:
                motif = eval_hook(function_body, record_ast)
                if motif.validate():
                    hooks[function_name] = motif
                    
# Deal with function hooks that are not explicitly defined
hooks['provenance_socket_sendmsg'] = hooks['provenance_socket_sendmsg_always']
hooks['provenance_socket_recvmsg'] = hooks['provenance_socket_recvmsg_always']
hooks['provenance_inode_rename'] = hooks['provenance_inode_link']
hooks['provenance_msg_queue_msgsnd'] = hooks['__mq_msgsnd']
hooks['provenance_mq_timedsend'] = hooks['__mq_msgsnd']
hooks['provenance_msg_queue_msgrcv'] = hooks['__mq_msgrcv']
hooks['provenance_mq_timedreceive'] = hooks['__mq_msgrcv']

# Print them out for inspection
for hookname, motif in hooks.iteritems():
    print("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(hookname)
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    motif.print_rtm()
    g = Graph()
    motif.draw_rtm(g)
    dot_str = g.get_graph()
    with open('../dot/'+ hookname +'.dot', 'w') as f:
        f.write(dot_str)
    f.close()
    # os.system('dot -Tpng ../dot/'+ hookname +'.dot -o ../img/'+ hookname +'.png')


