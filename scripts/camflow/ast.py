# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2015-2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

from __future__ import print_function
import sys
import os
import provenance as prov
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

def eval_prov_func_call(func_call):
    """
    Evaluate a single function call that directly generates a provenance string.
    """
    # print(func_call.name.name)
    if func_call.name.name == 'uses':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.uses_to_relation(arg_names[0], arg_names[1], arg_names[2], arg_names[3])
    elif func_call.name.name == 'generates':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.generates_to_relation(arg_names[0], arg_names[1], arg_names[2], arg_names[3])
    elif func_call.name.name == 'derives':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.derives_to_relation(arg_names[0], arg_names[1], arg_names[2])
    elif func_call.name.name == 'informs':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.informs_to_relation(arg_names[0], arg_names[1], arg_names[2])
    elif func_call.name.name == 'uses_two':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return prov.uses_two_to_relation(arg_names[0], arg_names[1], arg_names[2])
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
    else:
        return ""

def eval_assignment(assignment):
    """
    Evaluate a single assignment that directly generates a provenance string.
    """
    if type(assignment.rvalue).__name__ == 'FuncCall':
        return eval_prov_func_call(assignment.rvalue)
    else:
        return ""

def eval_declaration(declaration):
    """
    Evaluate a single declaration that directly generates a provenance string.
    """
    if type(declaration.init).__name__ == 'FuncCall':
        return eval_prov_func_call(declaration.init)
    else:
        return ""

def eval_if_else(item):
    """
    Evaluate possible nesting if/else blocks.
    """
    return_str = ""

    true_branch = item.iftrue
    if type(true_branch).__name__ == 'FuncCall':
        edge_str = eval_prov_func_call(true_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(true_branch).__name__ == 'Assignment':
        edge_str = eval_assignment(true_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(true_branch).__name__ == 'Decl':
        edge_str = eval_declaration(true_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(true_branch).__name__ == 'Compound':
        edge_str = eval_function_body(true_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    
    false_branch = item.iffalse
    if type(false_branch).__name__ == 'FuncCall':
        edge_str = eval_prov_func_call(false_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(false_branch).__name__ == 'Assignment':
        edge_str = eval_assignment(false_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(false_branch).__name__ == 'Decl':
        edge_str = eval_declaration(false_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(false_branch).__name__ == 'Compound':
        edge_str = eval_function_body(false_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    elif type(false_branch).__name__ == 'If':   # else if case
        edge_str = eval_if_else(false_branch)
        if edge_str != "":
            if return_str != "":
                return_str += ","
            return_str += edge_str
    return return_str


def eval_function_body(function_body):
    """
    Evaluate function body of each hook function to generate graph string.
    """
    # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
    # The following goes through the declarations and statements in the function body
    graph_str = ""
    for item in function_body.block_items:
        if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
            edge_str = eval_prov_func_call(item)
            if edge_str != "":
                if graph_str != "":
                    graph_str += ","
                graph_str += edge_str
        elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
            edge_str = eval_assignment(item)
            if edge_str != "":
                if graph_str != "":
                    graph_str += ","
                graph_str += edge_str
        elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
            edge_str = eval_declaration(item)
            if edge_str != "":
                if graph_str != "":
                    graph_str += ","
                graph_str += edge_str
        elif type(item).__name__ == 'If':   # Case 4: if/else if/else
            # TODO: Disregard conditions for now.
            edge_str = eval_if_else(item)
            if edge_str != "":
                if graph_str != "":
                    graph_str += ","
                graph_str += edge_str
    return graph_str

# PyCParser must begin at the top level of the C files,
# with either declarations or function definitions.

# A C parser must also have all the types declared
# to build the correct AST. 

# Parse the preprocessed hooks.c file.
ast = parse_file("../camflow/hooks_pp.c")

# Uncomment the following line to see the AST in a nice, human
# readable way. show() is the most useful tool in exploring ASTs
# created by pycparser. See the c_ast.py file for the options you
# can pass it.

# ast.show(showcoord=True)

# We've seen that the top node is FileAST. This is always the
# top node of the AST. Its children are "external declarations",
# and are stored in a list called ext[] (see _c_ast.cfg for the
# names and types of Nodes and their children).

# A dictionary that saves prov_string for each hook.
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
            prov_string = eval_function_body(function_body)
            hooks[function_name] = prov_string
        
# We go through each hook function again to draw model graphs.
for ext in ast.ext:
    if type(ext).__name__ == 'FuncDef':
        function_decl = ext.decl
        function_name = function_decl.name

        # We skip those that are not explicitly defined
        if function_name != 'provenance_socket_sendmsg_always' or function_name != 'provenance_socket_recvmsg_always' or function_name != 'provenance_inode_rename' or function_name != 'provenance_msg_queue_msgsnd' or function_name != 'provenance_mq_timedsend' or function_name != 'provenance_msg_queue_msgrcv' or function_name != 'provenance_mq_timedreceive' or function_name != "__mq_msgsnd" or function_name != "__mq_msgrcv":
            function_body = ext.body
            if function_body.block_items != None:
                prov_string = eval_function_body(function_body)
                if prov_string != "":
                    hooks[function_name] = prov_string
                    # Draw a graph
                    g = Graph()
                    g.process_string(hooks[function_name])
                    dot = g.get_graph()
                    with open('../tmp/'+ function_name +'.dot', 'w') as f:
                        f.write(dot)
                    f.close()
                    os.system('dot -Tpng ../tmp/'+ function_name +'.dot -o ../img/'+ function_name +'.png')

# Deal with function hooks that are not explicitly defined
hooks['provenance_socket_sendmsg_always'] = hooks['provenance_socket_sendmsg']
g = Graph()
g.process_string(hooks['provenance_socket_sendmsg_always'])
dot = g.get_graph()
with open('../tmp/provenance_socket_sendmsg_always.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_socket_sendmsg_always.dot -o ../img/provenance_socket_sendmsg_always.png')

hooks['provenance_socket_recvmsg_always'] = hooks['provenance_socket_recvmsg']
g = Graph()
g.process_string(hooks['provenance_socket_recvmsg_always'])
dot = g.get_graph()
with open('../tmp/provenance_socket_recvmsg_always.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_socket_recvmsg_always.dot -o ../img/provenance_socket_recvmsg_always.png')

hooks['provenance_inode_rename'] = hooks['provenance_inode_link']
g = Graph()
g.process_string(hooks['provenance_inode_rename'])
dot = g.get_graph()
with open('../tmp/provenance_inode_rename.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_inode_rename.dot -o ../img/provenance_inode_rename.png')

hooks['provenance_msg_queue_msgsnd'] = hooks['__mq_msgsnd']
g = Graph()
g.process_string(hooks['provenance_msg_queue_msgsnd'])
dot = g.get_graph()
with open('../tmp/provenance_msg_queue_msgsnd.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_msg_queue_msgsnd.dot -o ../img/provenance_msg_queue_msgsnd.png')

hooks['provenance_mq_timedsend'] = hooks['__mq_msgsnd']
g = Graph()
g.process_string(hooks['provenance_mq_timedsend'])
dot = g.get_graph()
with open('../tmp/provenance_mq_timedsend.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_mq_timedsend.dot -o ../img/provenance_mq_timedsend.png')

hooks['provenance_msg_queue_msgrcv'] = hooks['__mq_msgrcv']
g = Graph()
g.process_string(hooks['provenance_msg_queue_msgrcv'])
dot = g.get_graph()
with open('../tmp/provenance_msg_queue_msgrcv.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_msg_queue_msgrcv.dot -o ../img/provenance_msg_queue_msgrcv.png')

hooks['provenance_mq_timedreceive'] = hooks['__mq_msgrcv']
g = Graph()
g.process_string(hooks['provenance_mq_timedreceive'])
dot = g.get_graph()
with open('../tmp/provenance_mq_timedreceive.dot', 'w') as f:
    f.write(dot)
f.close()
os.system('dot -Tpng ../tmp/provenance_mq_timedreceive.dot -o ../img/provenance_mq_timedreceive.png')

