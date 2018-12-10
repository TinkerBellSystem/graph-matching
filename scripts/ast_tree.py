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
import provenance_tree as provenance
from rtm_tree import *
from helper import *
from graph_tree import *
from analyze_motif import *

from pycparser import c_parser, c_ast, parse_file

def get_arg_name(args):
    """
    Get names of function arguments in a function call.
    """
    names = []
    for arg in args:
        if type(arg).__name__ == 'ID':
            names.append(arg.name)
        elif type(arg).__name__ == 'UnaryOp':
            names.append(arg.expr.name)
        elif type(arg).__name__ == 'StructRef':
            #############################################
            # So far, we don't care about this situation:
            # fun(a->b)
            # POSSIBLE CODE HERE
            #############################################
            names.append(None)
    return names

def eval_function_call(func_call, motif_node_dict):
    """
    Evaluate a single subroutine function call in hook functions.
    All evaluated function calls should return a tuple: (New Motif Node, New RTM Tree Node), either or both of which can be None
    """
    print("\x1b[6;30;42m" + 'Evaluating ' + func_call.name.name + ' function...' + '\x1b[0m')
    # CamFlow "alloc_provenance" take two arguments but only the first is needed for modeling.
    if func_call.name.name == 'alloc_provenance':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        return provenance.alloc_provenance(arg_names[0], None)
    # CamFlow "task_cred_xxx" take two arguments but no argument is needed for modeling.
    elif func_call.name.name == 'task_cred_xxx':
        return provenance.task_cred_xxx(None, None)
    # CamFlow "branch_mmap" take two arguments but no argument is needed for modeling.
    elif func_call.name.name == 'branch_mmap':
        return provenance.branch_mmap(None, None)
    # CamFlow "uses_two" function takes five arguments but only the first three are needed for modeling.
    elif func_call.name.name == 'uses_two':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second and third arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in uses_two must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in uses_two must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in uses_two must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in uses_two must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.uses_two(arg_names[0], val1, val2, None, None, motif_node_dict)
    # CamFlow "informs" function takes five arguments but only the first three are needed for modeling.
    elif func_call.name.name == 'informs':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second and third arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in informs must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in informs must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in informs must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in informs must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.informs(arg_names[0], val1, val2, None, None, motif_node_dict)
    # CamFlow "record_terminate" function takes two arguments.
    elif func_call.name.name == 'record_terminate':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second arguments must be converted to MotifNode object first.
        arg1 = arg_names[1]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_terminate must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_terminate must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_terminate(arg_names[0], val1, motif_node_dict)
    # CamFlow "generates" function takes six arguments but only the first four are needed for modeling.
    elif func_call.name.name == 'generates':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second, third, and fourth arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        arg3 = arg_names[3]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in generates must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in generates must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in generates must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in generates must have values in the dictionary.\033[0m')
            exit(1)
        if arg3 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in generates must exist in the dictionary.\033[0m')
            exit(1)
        val3 = getLastValueFromKey(motif_node_dict, arg3)
        if not val3:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in generates must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.generates(arg_names[0], val1, val2, val3, None, None, motif_node_dict)
    # CamFlow "get_task_provenance" takes no arguments.
    elif func_call.name.name == 'get_task_provenance':
        return provenance.get_task_provenance()
    # CamFlow "get_cred_provenance" takes no arguments.
    elif func_call.name.name == 'get_cred_provenance':
        return provenance.get_cred_provenance(motif_node_dict)
    # CamFlow "uses" takes six arguments but only the first four are needed for modeling.
    elif func_call.name.name == 'uses':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second, third, and fourth arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        arg3 = arg_names[3]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in uses must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in uses must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in uses must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in uses must have values in the dictionary.\033[0m')
            exit(1)
        if arg3 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in uses must exist in the dictionary.\033[0m')
            exit(1)
        val3 = getLastValueFromKey(motif_node_dict, arg3)
        if not val3:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in uses must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.uses(arg_names[0], val1, val2, val3, None, None, motif_node_dict)
    # CamFlow "refresh_inode_provenance" takes two arguments but only the second one is needed for modeling.
    elif func_call.name.name == 'refresh_inode_provenance':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second argument must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in refresh_inode_provenance must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in refresh_inode_provenance must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.refresh_inode_provenance(None, val1, motif_node_dict)
    # CamFlow "get_inode_provenance" takes two arguments but only the second argument is needed for modeling.
    elif func_call.name.name == 'get_inode_provenance':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        if arg_names[1] == 'false':
            arg1 = False
        elif arg_names[1] == 'true':
            arg1 = True
        else:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg_names[1] + ' in get_inode_provenance is unknown.\033[0m')
            exit(1)
        return provenance.get_inode_provenance(None, arg1, motif_node_dict)
    # CamFlow "get_dentry_provenance" takes two arguments but only the second argument is needed for modeling.  
    elif func_call.name.name == 'get_dentry_provenance':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        if arg_names[1] == 'false':
            arg1 = False
        elif arg_names[1] == 'true':
            arg1 = True
        else:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg_names[1] + ' in get_dentry_provenance is unknown.\033[0m')
            exit(1)
        return provenance.get_dentry_provenance(None, arg1, motif_node_dict)
    # CamFlow "record_inode_name_from_dentry" takes three arguments, but only the second and the third arguments are needed for modeling.
    elif func_call.name.name == 'record_inode_name_from_dentry':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second argument must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_inode_name_from_dentry must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_inode_name_from_dentry must have values in the dictionary.\033[0m')
            exit(1)
        if arg_names[2] == 'false':
            arg2 = False
        elif arg_names[2] == 'true':
            arg2 = True
        else:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_inode_name_from_dentry is unknown.\033[0m')
            exit(1)
        return provenance.record_inode_name_from_dentry(None, val1, arg2, motif_node_dict)
    # CamFlow "record_node_name" takes three arguments, but only the first and the third arguments are needed for modeling.
    elif func_call.name.name == 'record_node_name':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second argument must be converted to MotifNode objects first.
        arg0 = arg_names[0]
        if arg0 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_node_name must exist in the dictionary.\033[0m')
            exit(1)
        val0 = getLastValueFromKey(motif_node_dict, arg0)
        if not val0:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_node_name must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_node_name(val0, None, arg_names[2], motif_node_dict)
    # CamFlow "derives" function takes five arguments but only the first three are needed for modeling.
    elif func_call.name.name == 'derives':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second and third arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in derives must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in derives must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in derives must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in derives must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.derives(arg_names[0], val1, val2, None, None, motif_node_dict)
    # CamFlow "record_write_xattr" function takes eight arguments but only the first four are needed for modeling.
    elif func_call.name.name == 'record_write_xattr':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second, third, and fourth arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        arg3 = arg_names[3]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_write_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_write_xattr must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_write_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_write_xattr must have values in the dictionary.\033[0m')
            exit(1)
        if arg3 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in record_write_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val3 = getLastValueFromKey(motif_node_dict, arg3)
        if not val3:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg3 + ' in record_write_xattr must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_write_xattr(arg_names[0], val1, val2, val3, None, None, None, None, motif_node_dict)
    # CamFlow "record_read_xattr" function takes four arguments but only the first three are needed for modeling.
    elif func_call.name.name == 'record_read_xattr':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        arg0 = arg_names[0]
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        if arg0 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_read_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val0 = getLastValueFromKey(motif_node_dict, arg0)
        if not val0:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_read_xattr must have values in the dictionary.\033[0m')
            exit(1)
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_read_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_read_xattr must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_read_xattr must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_read_xattr must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_read_xattr(val0, val1, val2, None, motif_node_dict)
    # CamFlow "get_file_provenance" takes two arguments but only the second argument is needed for modeling.  
    elif func_call.name.name == 'get_file_provenance':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        if arg_names[1] == 'false':
            arg1 = False
        elif arg_names[1] == 'true':
            arg1 = True
        else:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg_names[1] + ' in get_file_provenance is unknown.\033[0m')
            exit(1)
        return provenance.get_file_provenance(None, arg1, motif_node_dict)
    # CamFlow "influences_kernel" function takes four arguments but only the first three are needed for modeling.
    elif func_call.name.name == 'influences_kernel':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        # The second and third arguments must be converted to MotifNode objects first.
        arg1 = arg_names[1]
        arg2 = arg_names[2]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in influences_kernel must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in influences_kernel must have values in the dictionary.\033[0m')
            exit(1)
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in influences_kernel must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in influences_kernel must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.influences_kernel(arg_names[0], val1, val2, None, motif_node_dict)
    # CamFlow "get_socket_inode_provenance" takes one argument but it is not needed for modeling.
    elif func_call.name.name == 'get_socket_provenance':
        return provenance.get_socket_provenance(None, motif_node_dict)
    # CamFlow "get_socket_inode_provenance" takes one argument but it is not needed for modeling.  
    elif func_call.name.name == 'get_socket_inode_provenance':
        return provenance.get_socket_inode_provenance(None, motif_node_dict)
    # CamFlow "record_address" takes three arguments but only the last argument is needed for modeling. 
    elif func_call.name.name == 'record_address':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        arg2 = arg_names[2]
        if arg2 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_address must exist in the dictionary.\033[0m')
            exit(1)
        val2 = getLastValueFromKey(motif_node_dict, arg2)
        if not val2:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg2 + ' in record_address must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_address(None, None, val2, motif_node_dict)
    # CamFlow "get_sk_inode_provenance" takes one argument but it is not needed for modeling.  
    elif func_call.name.name == 'get_sk_inode_provenance':
        return provenance.get_sk_inode_provenance(None, motif_node_dict)
    # CamFlow "get_sk_provenance" takes one argument but it is not needed for modeling.
    elif func_call.name.name == 'get_sk_provenance':
        return provenance.get_sk_provenance(None, motif_node_dict)
    # CamFlow "record_packet_content" takes two arguments but only the second argument is needed for modeling. 
    elif func_call.name.name == 'record_packet_content':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        arg1 = arg_names[1]
        if arg1 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_packet_content must exist in the dictionary.\033[0m')
            exit(1)
        val1 = getLastValueFromKey(motif_node_dict, arg1)
        if not val1:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg1 + ' in record_packet_content must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_packet_content(None, val1, motif_node_dict)
    # CamFlow "record_args" takes two arguments but only the first argument is needed for modeling.
    elif func_call.name.name == 'record_args':
        args = func_call.args.exprs
        arg_names = get_arg_name(args)
        arg0 = arg_names[0]
        if arg0 not in motif_node_dict:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_args must exist in the dictionary.\033[0m')
            exit(1)
        val0 = getLastValueFromKey(motif_node_dict, arg0)
        if not val0:
            print('\33[101m' + '[error][eval_function_call]:  ' + arg0 + ' in record_args must have values in the dictionary.\033[0m')
            exit(1)
        return provenance.record_args(val0, None, motif_node_dict)
    else:
        return None, None

def eval_assignment(assignment, motif_node_dict):
    """
    Evaluate a single assignment that directly creates new MotifNodes or TreeNodes.
    """
    if type(assignment.rvalue).__name__ == 'FuncCall':
        motif_node, tree_node = eval_function_call(assignment.rvalue, motif_node_dict)
        # consider "var = XXX;" and "*var = XXX" and "&var = XXX" situations
        if (type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in motif_node_dict) or (type(assignment.lvalue).__name__ == 'UnaryOp' and assignment.lvalue.expr.name in motif_node_dict):
            if not motif_node:
                print('\33[101m' + '[error][eval_assignment]:  ' + assignment.lvalue.name + ' is in the dictionary. MotifNode should not be None.\033[0m')
                exit(1)
            else:
                motif_node_dict[assignment.lvalue.name].append(motif_node)
        return tree_node
    # In a case where a provenance node was declared but then assigned or reassigned. For example:
    #   struct provenance *tprov;
    #   ...
    #   tprov = t->provenance;
    # tprov must then be in the motif_node_dict.
    elif type(assignment.lvalue).__name__ == 'ID' and assignment.lvalue.name in motif_node_dict:
        # we can only infer its type from the name of the variable
        motif_node = provenance.create_motif_node(assignment.lvalue.name)
        motif_node_dict[assignment.lvalue.name].append(motif_node)
        return None
    elif type(assignment.lvalue).__name__ == 'UnaryOp' and type(assignment.lvalue.expr).__name__ == 'ID' and assignment.lvalue.expr.name in motif_node_dict:
        # similar case as the previous one, except that we have: *tprov = ...
        # we can only infer its type from the name of the variable
        motif_node = provenance.create_motif_node(assignment.lvalue.expr.name)
        motif_node_dict[assignment.lvalue.expr.name].append(motif_node)
        return None
    else:
        #######################################################
        # We will consider other conditions if we ever see them
        # POSSIBLE CODE HERE.
        #######################################################
        return None

def eval_declaration(declaration, motif_node_dict):
    """
    Evaluate a single declaration that directly generates new MotifNodes or TreeNodes.
    """
    # We are only concerned with declaration type "struct provenance" or "struct provenance *"
    if (type(declaration.type).__name__ == 'PtrDecl' and type(declaration.type.type).__name__ == 'TypeDecl' and type(declaration.type.type.type).__name__ == 'Struct' and declaration.type.type.type.name == 'provenance') or (type(declaration.type).__name__ == 'TypeDecl' and type(declaration.type.type).__name__ == 'Struct' and declaration.type.type.name == 'provenance'):
        # if it is immediately assigned by a function call
        if type(declaration.init).__name__ == 'FuncCall':
            motif_node, tree_node = eval_function_call(declaration.init, motif_node_dict)
            if not motif_node:
                print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' must be associated with a MotifNode.\033[0m')
                exit(1)
            else:
                # it should be the first time we see the name in the dictionary
                if declaration.name in motif_node_dict:
                    print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' should not already be in the dictionary.\033[0m')                    
                    exit(1)
                else:
                    motif_node_dict[declaration.name] = [motif_node]
            return tree_node
        # if it is set to NULL first
        elif type(declaration.init).__name__ == 'ID':
            if declaration.init.name == 'NULL':
                # it should be the first time we see the name in the dictionary
                if declaration.name in motif_node_dict:
                    print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' is set to NULL and should not already be in the dictionary.\033[0m')                    
                    exit(1)
                else:
                    motif_node_dict[declaration.name] = []
            else:
                #######################################################
                # We will consider other conditions if we ever see them
                # POSSIBLE CODE HERE.
                #######################################################
                print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' is set to an unknown condition that is not considered yet.\033[0m')                    
                exit(1)
            return None
        # if it is not set at all, then it must be set later
        elif type(declaration.init).__name__ == 'NoneType':
            if declaration.name in motif_node_dict:
                print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' is not set and should not already be in the dictionary.\033[0m')                    
                exit(1)
            else:
                #######################################################
                # We encounter an exception here
                # TODO: WHAT CAN WE DO?
                #######################################################
                if declaration.name == 'pckprov':
                    motif_node_dict[declaration.name] = [provenance.create_motif_node(declaration.name)]
                else:
                    motif_node_dict[declaration.name] = []
            return None
        # it must be set through other methods, so we can only infer the type from its name
        else:
            if declaration.name in motif_node_dict:
                print('\33[101m' + '[error][eval_declaration]:  ' + declaration.name + ' is not set in an unknown way but should not already be in the dictionary.\033[0m')                    
                exit(1)
            else:
                motif_node_dict[declaration.name] = [provenance.create_motif_node(declaration.name)]
            return None
            
    else:
        return None

def eval_return(statement, motif_node_dict):
    """
    Evaluate a single return statement that directly generates new TreeNodes.
    Return statement should not generate new MotifNode at the hook level, because it does not make sense.
    """
    # the only way to generate new TreeNodes is though a function call
    if type(statement.expr).__name__ == 'FuncCall':
        motif_node, tree_node = eval_function_call(statement.expr, motif_node_dict)
        if motif_node:
            print('\33[101m' + '[error][eval_return]: return statement should not generate a new MotifNode.\033[0m')                    
            exit(1)
        else:
            return tree_node
    else:
        return None

def eval_if_condition(condition):
    """
    Evaluate `if` condition.
    Returns True if the `if` condition requires alternation consideration.
    Otherwise, return False.
    """
    if type(condition).__name__ == 'BinaryOp':
        if type(condition.left).__name__ == 'ID':
            # case: if (mask & XXX) {...} in "provenance_inode_permission"; mask can only be determined at runtime
            if condition.left.name == 'mask':
                return True
            # case: if (shmflg & SHM_RDONLY) {...} in "provenance_shm_shmat"; shmflg can be only be determined at runtime
            if condition.left.name == 'shmflg':
                return True
        elif type(condition.left).__name__ == 'BinaryOp':
            if type(condition.left.left).__name__ == 'ID':
                # case: if ((perms & (DIR__WRITE)) != 0) in "provenance_file_permission"; perms can only be determined at runtime
                if condition.left.left.name == 'perms':
                    return True
                # case: if ((prot & (PROT_WRITE)) != 0) in "provenance_mmap_file"; prot can only be determined at runtime
                elif condition.left.left.name == 'prot':
                    return True
            elif type(condition.left.left).__name__ == 'BinaryOp':
                if type(condition.left.left.left).__name__ == 'ID':
                    # case: if ((flags & MAP_TYPE) == MAP_SHARED...) in "provenance_mmap_file"; flags can only be determined at runtime
                    if condition.left.left.left.name == 'flags':
                        return True
            elif type(condition.left.right).__name__ == 'ID':
                # case: if (sock->sk->sk_family == PF_UNIX &&...) in "provenance_socket_recvmsg", "provenance_socket_recvmsg_always", "provenance_socket_sendmsg", "provenance_socket_sendmsg_always"; sock->sk->sk_family can only be determined at runtime
                if condition.left.right.name == 'PF_UNIX':
                    return True
    elif type(condition).__name__ == 'FuncCall':
        # case: if (is_inode_dir(inode)) in "provenance_file_permission"; inode type can only be determined at runtime
        if condition.name.name == 'is_inode_dir':
            return True
        # case: else if (is_inode_socket(inode)) in "provenance_file_permission"
        elif condition.name.name == 'is_inode_socket':
            return True
        # case: if ( vm_mayshare(flags) ) in "provenance_mmap_munmap"; flags can only be determined at runtime
        elif condition.name.name == 'vm_mayshare':
            return True
    elif type(condition).__name__ == 'ID':
        # case: if (iprovb) in "provenance_socket_sendmsg", "provenance_socket_sendmsg_always"
        if condition.name == 'iprovb':
            return True
        # case: if (pprov) in "provenance_socket_recvmsg", "provenance_socket_recvmsg_always"
        elif condition.name == 'pprov':
            return True
    #######################################################
    # We will consider other conditions if we ever see them
    # POSSIBLE CODE HERE.
    #######################################################
    else:
        return False
    
def eval_if_else(item, motif_node_dict):
    """
    Evaluate (nesting) if/else blocks.
    Only if/else blocks that contain statements that create MotifNodes/TreeNodes are of interest here.
    Within those blocks, only specific if/else condition checks are of interest here.
    Most if/else are for error handling only. 
    """
    # evaluate the `if` branch first
    true_branch = item.iftrue
    if type(true_branch).__name__ == 'FuncCall':
        motif_node, left = eval_function_call(true_branch, motif_node_dict)             
    elif type(true_branch).__name__ == 'Assignment':
        left = eval_assignment(true_branch, motif_node_dict)
    elif type(true_branch).__name__ == 'Decl':
        left = eval_declaration(true_branch, motif_node_dict)
    elif type(true_branch).__name__ == 'Return':
        left = eval_return(true_branch, motif_node_dict)
    elif type(true_branch).__name__ == 'Compound':
        left = eval_function_body(true_branch, motif_node_dict)
    else:
        left = None
    # evaluate the `else` branch if it exists
    false_branch = item.iffalse
    if type(false_branch).__name__ == 'FuncCall':
        motif_node, right = eval_function_call(false_branch, motif_node_dict)
    elif type(false_branch).__name__ == 'Assignment':
        right = eval_assignment(false_branch, motif_node_dict)
    elif type(false_branch).__name__ == 'Decl':
        right = eval_declaration(false_branch, motif_node_dict)
    elif type(false_branch).__name__ == 'Return':
        right = eval_return(false_branch, motif_node_dict)
    elif type(false_branch).__name__ == 'Compound':
        right = eval_function_body(false_branch, motif_node_dict)
    elif type(false_branch).__name__ == 'If':   # else if case
        right = eval_if_else(false_branch, motif_node_dict)
    else:
        right = None

    if left or right:
        # only under certain circumstances do we actually create alternation node
        if eval_if_condition(item.cond):
            return provenance.create_alternation_node(left, right)
        else:
            # if only one branch is not None, we need not create a group node
            if not left:
                return right
            if not right:
                return left
            return provenance.create_group_node(left, right)
    else:
        return None

def eval_function_body(function_body, motif_node_dict):
    """
    Evaluate a Compound function body.
    """
    # The body of FuncDef is a Compound, which is a placeholder for a block surrounded by {}
    # The following goes through the declarations and statements in the function body
    tree = None
    for item in function_body.block_items:
        if type(item).__name__ == 'FuncCall':   # Case 1: provenance-graph-related function call
            motif_node, tree_node = eval_function_call(item, motif_node_dict)
            if tree_node != None:
                tree = provenance.create_group_node(tree, tree_node)
        elif type(item).__name__ == 'Assignment': # Case 2: rc = provenance-graph-related function call
            tree_node = eval_assignment(item, motif_node_dict)
            if tree_node != None:
                tree = provenance.create_group_node(tree, tree_node)
        elif type(item).__name__ == 'Decl': # Case 3: declaration with initialization
            tree_node = eval_declaration(item, motif_node_dict)
            if tree_node != None:
                tree = provenance.create_group_node(tree, tree_node)
        elif type(item).__name__ == 'If':   # Case 4: if/else
            tree_node = eval_if_else(item, motif_node_dict)
            if tree_node != None:
                tree = provenance.create_group_node(tree, tree_node)
        elif type(item).__name__ == 'Return':   # Case 5: return with function call
            tree_node = eval_return(item, motif_node_dict)
            if tree_node != None:
                tree = provenance.create_group_node(tree, tree_node)
    return tree

def eval_hook(function_body, motif_node_dict):
    """
    Evaluate function body of each hook function to generate its RTM Tree.

    motif_node_dict is a dictionary that maps a MotifNode's name to a list of MotifNode objects.
    It is a list because a MotifNode could have multiple versions.
    """
    return eval_function_body(function_body, motif_node_dict)

def eval_function_declaration(function_decl, motif_node_dict):
    """
    If hook function declaration contains provenance MotifNodes in their parameter list, 
    we need to include them in the @motif_node_dict
    This function is currently for the special the "__mq_msgrcv" case.
    """
    if type(function_decl.type.args).__name__ == 'ParamList':
        function_parameters = function_decl.type.args.params
        for param in function_parameters:
            if type(param.type).__name__ == 'PtrDecl' and type(param.type.type).__name__ == 'TypeDecl' and type(param.type.type.type).__name__ == 'Struct' and param.type.type.type.name == 'provenance':
                # we can only infer the type from its name
                motif_node_dict[param.name] = [provenance.create_motif_node(param.name)]

# PyCParser must begin at the top level of the C files,
# with either declarations or function definitions.

# A C parser must also have all the types declared
# to build the correct AST. 

# Parse the preprocessed hooks.c file.
ast = parse_file("./camflow/hooks_pp.c")
# Uncomment the following line to see the AST in a nice, human
# readable way. show() is the most useful tool in exploring ASTs
# created by pycparser. See the c_ast.py file for the options you
# can pass it.

# ast.show(showcoord=True)

# We've seen that the top node is FileAST. This is always the
# top node of the AST. Its children are "external declarations",
# and are stored in a list called ext[] (see _c_ast.cfg for the
# names and types of Nodes and their children).

# A dictionary that saves a RTM tree for each hook.
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
            # Each hook's RTM MotifNode ID starts from 0
            MotifNode.node_id = 0
            # Each hook's RTM TreeNode ID starts from 0
            RTMTreeNode.nid = 0
            # Each hook has a dictionary.
            motif_node_dict = {}
            print("\x1b[6;30;42m" + "Evaluating " + function_name + " hook..." + '\x1b[0m')
            function_decl = ext.decl
            # We must preprocess function declaration for "__mq_msgrcv" 
            # because their declaration contains provenance MotifNode declarations that are needed to exist.
            eval_function_declaration(function_decl, motif_node_dict)
            motif = eval_hook(function_body, motif_node_dict)
            hooks[function_name] = motif
            print("\x1b[6;30;42m" + 'Success!' + '\x1b[0m')
        
# We go through each hook function again to draw model graphs.
for ext in ast.ext:
    if type(ext).__name__ == 'FuncDef':
        function_decl = ext.decl
        function_name = function_decl.name

        # We skip those that are not explicitly defined
        if function_name != 'provenance_socket_sendmsg' and function_name != 'provenance_socket_recvmsg' and function_name != 'provenance_inode_rename' and function_name != 'provenance_msg_queue_msgsnd' and function_name != 'provenance_mq_timedsend' and function_name != 'provenance_msg_queue_msgrcv' and function_name != 'provenance_mq_timedreceive' and function_name != "__mq_msgsnd" and function_name != "__mq_msgrcv" and function_name != 'provenance_inode_rename':
            function_body = ext.body
            if function_body.block_items != None:   # make sure the function is not empty
                MotifNode.node_id = 0
                RTMTreeNode.nid = 0
                motif_node_dict = {}
                print("\x1b[6;30;42m" + "Evaluating " + function_name + " hook..." + '\x1b[0m')
                motif = eval_hook(function_body, motif_node_dict)
                if motif != None:
                    hooks[function_name] = motif
                    print("\x1b[6;30;42m" + 'Success!' + '\x1b[0m')
                else:
                    print('\33[5;30;42m[warning]' + function_name + " does not have an RTM Motif." + '\033[0m')
                    
# Deal with function hooks that are not explicitly defined
hooks['provenance_socket_sendmsg'] = hooks['provenance_socket_sendmsg_always']
hooks['provenance_socket_recvmsg'] = hooks['provenance_socket_recvmsg_always']
hooks['provenance_inode_rename'] = hooks['provenance_inode_link']
hooks['provenance_msg_queue_msgsnd'] = hooks['__mq_msgsnd']
hooks['provenance_mq_timedsend'] = hooks['__mq_msgsnd']
hooks['provenance_msg_queue_msgrcv'] = hooks['__mq_msgrcv']
hooks['provenance_mq_timedreceive'] = hooks['__mq_msgrcv']
hooks['provenance_inode_rename'] = hooks['provenance_inode_link']

# for hookname, motif in hooks.iteritems():
#     print("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
#     print(hookname)
#     print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
#     # inorder_traversal(motif)
#     # bf_traversal(motif)
#     g = Graph()
#     visualize_rtm_tree(motif, g)
#     dot_str = g.get_graph()
#     with open('../dot/'+ hookname +'_tree.dot', 'w') as f:
#         f.write(dot_str)
#     f.close()
#     # os.system('dot -Tpng ../dot/'+ hookname +'_tree.dot -o ../img/'+ hookname +'_tree.png')

# for hookname_i, motif_i in hooks.iteritems():
#     for hookname_j, motif_j in hooks.iteritems():
#         if hookname_i == hookname_j:
#             continue
#         else:
#             motif_list_i = []
#             motif_list_j = []

#             convert_star(motif_i)
#             combine_question_mark(motif_i)
#             for motif in expand_or(motif_i):
#                 motif_list_i.extend(expand_question_mark(motif))

#             convert_star(motif_j)
#             combine_question_mark(motif_j)
#             for motif in expand_or(motif_j):
#                 motif_list_j.extend(expand_question_mark(motif))

#             if submotif(motif_list_i, motif_list_j):
#                 print(hookname_i + " and " + hookname_j + " have submotif relations.")
#             else:
#                 print(hookname_i + " and " + hookname_j + " do not have submotif relations.")

#########################DEBUG
convert_star(hooks["provenance_file_lock"])
combine_question_mark(hooks["provenance_file_lock"])
for motif in expand_question_mark(hooks["provenance_file_lock"]):
    edge_list = []
    tree_to_list(motif, edge_list)
    for e in edge_list:
        e.print_edge()
        print()
    print("---------------------------")


