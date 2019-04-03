from __future__ import print_function
import sys
import os

from pycparser import c_parser, c_ast, parse_file

from static_analysis.parse import *
from gregex.rtm import visualize_rtm_tree, streamline_rtm
from gregex.graphviz import *
from gregex.converter import *
from gregex.ast import *

import parser
import copy
import match_dfa as mdfa
from multiprocessing import Pool

ast_hooks = parse_file("./camflow-dev/security/provenance/hooks_pp.c")
ast_inode = parse_file("./camflow-dev/security/provenance/include/provenance_inode_pp.h")
ast_net = parse_file("./camflow-dev/security/provenance/include/provenance_net_pp.h")
ast_record = parse_file("./camflow-dev/security/provenance/include/provenance_record_pp.h")
ast_task = parse_file("./camflow-dev/security/provenance/include/provenance_task_pp.h")
ast_netfilter = parse_file("./camflow-dev/security/provenance/netfilter_pp.c")

functions = dict()
list_functions(ast_hooks, functions)
list_functions(ast_inode, functions)
list_functions(ast_net, functions)
list_functions(ast_record, functions)
list_functions(ast_task, functions)
list_functions(ast_netfilter, functions)

# func_body = functions['record_node_name'][1]
# print(func_body)
# exit()


# TODO: NOTE hook `__mq_msgrcv` is a helper function and should not be analyzed as a hook!
hooks = list()
hooks.append('provenance_cred_free')
hooks.append('provenance_cred_alloc_blank')
hooks.append('provenance_cred_prepare')
hooks.append('provenance_cred_transfer')
hooks.append('provenance_task_alloc')
hooks.append('provenance_task_free')
hooks.append('provenance_task_kill')
hooks.append('provenance_inode_alloc_security')
hooks.append('provenance_inode_free_security')
hooks.append('provenance_msg_msg_alloc_security')
hooks.append('provenance_msg_msg_free_security')
hooks.append('provenance_shm_alloc_security')
hooks.append('provenance_shm_free_security')
hooks.append('provenance_sk_alloc_security')
hooks.append('provenance_sb_alloc_security')
hooks.append('provenance_sb_free_security')
hooks.append('provenance_task_fix_setuid')
hooks.append('provenance_task_setpgid')
hooks.append('provenance_task_getpgid')
hooks.append('provenance_inode_create')
hooks.append('provenance_inode_permission')
hooks.append('provenance_inode_link')
hooks.append('provenance_inode_unlink')
hooks.append('provenance_inode_symlink')
hooks.append('provenance_inode_rename')
hooks.append('provenance_inode_setattr')
hooks.append('provenance_inode_getattr')
hooks.append('provenance_inode_readlink')
hooks.append('provenance_inode_setxattr')
hooks.append('provenance_inode_post_setxattr')
hooks.append('provenance_inode_getxattr')
hooks.append('provenance_inode_listxattr')
hooks.append('provenance_inode_removexattr')
hooks.append('provenance_inode_getsecurity')
hooks.append('provenance_inode_listsecurity')
hooks.append('provenance_file_permission')
hooks.append('provenance_mmap_file')
hooks.append('provenance_mmap_munmap')
hooks.append('provenance_file_ioctl')
hooks.append('provenance_file_open')
hooks.append('provenance_file_receive')
hooks.append('provenance_file_lock')
hooks.append('provenance_file_send_sigiotask')
hooks.append('provenance_file_splice_pipe_to_pipe')
hooks.append('provenance_kernel_read_file')
hooks.append('provenance_msg_queue_msgsnd')
hooks.append('provenance_msg_queue_msgrcv')
hooks.append('provenance_shm_shmat')
hooks.append('provenance_shm_shmdt')
hooks.append('provenance_socket_post_create')
hooks.append('provenance_socket_socketpair')
hooks.append('provenance_socket_bind')
hooks.append('provenance_socket_connect')
hooks.append('provenance_socket_listen')
hooks.append('provenance_socket_accept')
hooks.append('provenance_socket_sendmsg_always')
hooks.append('provenance_socket_recvmsg_always')
hooks.append('provenance_mq_timedreceive')
hooks.append('provenance_mq_timedsend')
#
# # The following are the same as provenance_socket_sendmsg_always and provenance_socket_recvmsg_always
# # hooks.append('provenance_socket_sendmsg')
# # hooks.append('provenance_socket_recvmsg')
#
hooks.append('provenance_socket_sock_rcv_skb')
hooks.append('provenance_unix_stream_connect')
hooks.append('provenance_unix_may_send')
hooks.append('provenance_bprm_check_security')
hooks.append('provenance_bprm_set_creds')
hooks.append('provenance_bprm_committing_creds')
hooks.append('provenance_sb_alloc_security')
hooks.append('provenance_sb_free_security')
hooks.append('provenance_sb_kern_mount')

hooks.append('provenance_ipv4_out')

trees = dict()
for hook in hooks:
    print("\x1b[6;30;42m[+]\x1b[0m" + " Evaluating Hook: " + hook)

    motif_node_map = dict()
    # TODO: `prov_machine` occurs in two different places, although they should represent the same machine.
    # TODO: `prov_machine` is hard-coded.
    kernel_node = MotifNode('machine')
    motif_node_map['record_kernel_link.prov_machine'] = [kernel_node]
    motif_node_map['record_influences_kernel.prov_machine'] = motif_node_map['record_kernel_link.prov_machine']

    func_body = functions[hook][1]
    _, tree = eval_function_body(hook, func_body, functions, motif_node_map, dict())
    if tree is None:
        continue
    trees[hook] = tree
    print("\x1b[6;30;42m[+]\x1b[0m" + " Hook: " + hook + " is evaluated...")

# func_body = functions['provenance_task_kill'][1]
# _, tree = eval_function_body('provenance_task_kill', func_body, functions, motif_node_map, {})

print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
print("+ Visualizing RTMT and DFA        +")
print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
dfas = dict()
canonicals = dict()
for hookname, motif in trees.iteritems():
    print("\x1b[6;30;42m" + 'Printing Tree for ' + hookname + '...\x1b[0m')
    g = Graph()
    streamline_rtm(motif)
    visualize_rtm_tree(motif, g)
    dot_str = g.get_graph()
    with open('../dot/' + hookname + '_tree.dot', 'w') as f:
        f.write(dot_str)
    f.close()

    converter = Converter(motif)
    nfa = ast_to_nfa(converter.ast)
    print("\x1b[6;30;42m" + 'Generating NFA for ' + hookname + '...\x1b[0m')
    with open('../dot/' + hookname + '_nfa.dot', 'w') as f:
        nfa.print_graphviz(f)
    f.close()

    dfa = nfa.to_dfa()
    print("\x1b[6;30;42m" + 'Generating DFA for ' + hookname + '...\x1b[0m')
    with open('../dot/' + hookname + '_dfa.dot', 'w') as f:
        dfa.print_graphviz(f)
    dfas[hookname] = dfa
    canonicals[hookname] = converter.canonical
    f.close()

nlm_G = dict()
E_Gs = list()
E_all = list()
parser.parse_nodes("../doc/mmap2.log", nlm_G)
parser.parse_edges("../doc/mmap2.log", nlm_G, E_all)
parser.post_process(E_all, E_Gs)
for E_G in E_Gs:
    print(E_G)
    print("***********")

# pool = Pool(6)
# args = []
hooks2indices = dict()
indices2hooks = dict()
for num, E_G in enumerate(E_Gs):
    print("************************************************ Matching Graph {}".format(num))
    canonicals_copy = copy.deepcopy(canonicals)
    for dfaname, dfa in dfas.iteritems():
        # args.append((dfaname, dfa, E_G))
        mdfa.match_dfa(dfaname, dfa, E_G, canonicals_copy[dfaname], hooks2indices, indices2hooks)

matched = dict()
# Calculate the total size of the graph
total_graph_size = 0
for E_G in E_Gs:
    total_graph_size += len(E_G)
mdfa.match_hooks(total_graph_size, hooks2indices, indices2hooks, matched)

print("Printing the results===============================")
for key, value in matched.iteritems():
    print("{} -> {}".format(key, value))

# pool.map(mdfa.match_dfa_wrapper, args)

# converter = Converter(tree)
# nfa = ast_to_nfa(converter.ast)
# print("\x1b[6;30;42m[+]\x1b[0m" + ' [test] Generating NFA')
# with open('../dot/0''_nfa.dot', 'w') as f:
#     nfa.print_graphviz(f)
# f.close()
#
# dfa = nfa.to_dfa()
# print("\x1b[6;30;42m[+]\x1b[0m" + ' [test] Generating DFA')
# with open('../dot/0' + '_dfa.dot', 'w') as f:
#     dfa.print_graphviz(f)
# f.close()

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