# -*- coding: utf-8 -*-
# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2020 Harvard University
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

# PyCParser reference: https://github.com/eliben/pycparser
from __future__ import print_function
import argparse
import sys
import os
import pycparser
import logging

import core.core as core


class FuncDefVisitor(pycparser.c_ast.NodeVisitor):
    def __init__(self, function_name):
        self.function_name = function_name

    def visit_FuncDef(self, node):
        """Returns the location of the function definition in the parsed C file"""
        if node.decl.name == self.function_name:
            logger.info("\x1b[6;30;42m[+]\x1b[0m Evaluating hook: {} ({})".format(self.function_name, node.decl.coord))


def main(args):
    # parse all the camflow files that relevant to our analysis into ASTs
    hook_file = "{}/security/provenance/hooks_pp.c".format(args.camflow)
    ast_hooks = pycparser.parse_file(hook_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(hook_file))
    inode_file = "{}/security/provenance/include/provenance_inode_pp.h".format(args.camflow)
    ast_inode = pycparser.parse_file(inode_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(inode_file))
    net_file = "{}/security/provenance/include/provenance_net_pp.h".format(args.camflow)
    ast_net = pycparser.parse_file(net_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(net_file))
    record_file = "{}/security/provenance/include/provenance_record_pp.h".format(args.camflow)
    ast_record = pycparser.parse_file(record_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(record_file))
    task_file = "{}/security/provenance/include/provenance_task_pp.h".format(args.camflow)
    ast_task = pycparser.parse_file(task_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(task_file))
    netfilter_file = "{}/security/provenance/netfilter_pp.c".format(args.camflow)
    ast_netfilter = pycparser.parse_file(netfilter_file)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Read {}".format(netfilter_file))

    # store all function ASTs from all the parsed ASTs into a central dictionary
    funcs = dict()
    funcs.update(core.parse_funcs(ast_hooks))
    funcs.update(core.parse_funcs(ast_inode))
    funcs.update(core.parse_funcs(ast_net))
    funcs.update(core.parse_funcs(ast_record))
    funcs.update(core.parse_funcs(ast_task))
    funcs.update(core.parse_funcs(ast_netfilter))
    logger.info("\x1b[6;30;42m[+]\x1b[0m Parsed {} functions".format(len(funcs)))

    # populate a list of hooks we model
    hooks = list()
    hooks.append('provenance_cred_free')

    # a dictionary that maps each hook to its RTMTree we constructed
    trees = dict()
    # model all the hooks in the list
    for hook in hooks:
        func = funcs[hook]["body"]
        logger.debug(func)
        # Get the location of the hook definition for easy debugging and identification
        func_def = FuncDefVisitor(hook)
        #TODO: hooks from other than ast_hooks are not properly handled
        func_def.visit(ast_hooks)

        # Evaluate the hook (core)
        # Each hook has its own MotifNode map
        nodes = dict()
        _, tree = core.eval_func_body(hook, func, funcs, nodes, dict())
        if tree is None:
            logger.warning("\x1b[6;30;43m[!]\x1b[0m Hook {} has no RTMTress".format(hook))
            continue
        trees[hook] = tree
        logger.info("\x1b[6;30;42m[+]\x1b[0m Hook {} RTMTree is constructed".format(hook))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--camflow", required=True, 
                        help="the top-most directory path of CamFlow code base, which should end with '/camflow-dev/'")
    parser.add_argument("-v", "--verbosity", action="count",
                        help="increase output verbosity")
    parser.add_argument("-l", "--log", default="tinkerbell.log",
                        help="log file path (default to tinkerbell.log)")
    args = parser.parse_args()

    # set up logging
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")
    logger = logging.getLogger()
    # log to log file
    fileHandler = logging.FileHandler(args.log)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)
    # log to console
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)
    # set logging verbosity
    if args.verbosity >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbosity >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Logging configured. Logs are saved to {}".format(args.log))

    main(args)

