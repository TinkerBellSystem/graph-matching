UNAME_S := $(shell uname -s)

SED:=
ifeq ($(UNAME_S),Linux)
	SED += sed -i
endif
ifeq ($(UNAME_S),Darwin)
	SED += sed -i ''
endif

remedy_hooks:
	$(SED) 's,^#include <linux/slab.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/lsm_hooks.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/msg.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <net/sock.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <net/af_unix.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/binfmts.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/random.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/xattr.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/file.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include <linux/workqueue.h>,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_record.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_net.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_inode.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_task.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_machine.h",//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/hooks.c

	$(SED) "s;container_of(fown, struct file, f_owner);container_of(fown, file, f_owner);" ./camflow-dev/security/provenance/hooks.c
	$(SED) "s,call_provenance_alloc((prov_entry_t\*)\&pckprov),call_provenance_alloc(pckprov)," ./camflow-dev/security/provenance/hooks.c
	$(SED) "s,call_provenance_free((prov_entry_t\*)\&pckprov),call_provenance_free(pckprov)," ./camflow-dev/security/provenance/hooks.c
	$(SED) "s,__lsm_ro_after_init,," ./camflow-dev/security/provenance/hooks.c
	$(SED) "s,__ro_after_init,," ./camflow-dev/security/provenance/hooks.c
	$(SED) 's,^LIST_HEAD,//&,' ./camflow-dev/security/provenance/hooks.c
	$(SED) "s,__init,," ./camflow-dev/security/provenance/hooks.c

	$(SED) "s,#ifdef CONFIG_SECURITY_FLOW_FRIENDLY,#ifndef CONFIG_SECURITY_FLOW_FRIENDLY," ./camflow-dev/security/provenance/hooks.c

preprocess_hooks:
	gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -D'bool=int' -D'uint32_t=int' -D'uint8_t=int' -D'uint16_t=int' -E ./camflow-dev/security/provenance/hooks.c > ./camflow-dev/security/provenance/hooks_pp.c

remedy_record:
	$(SED) 's,^#include "provenance.h",//&,' ./camflow-dev/security/provenance/include/provenance_record.h
	$(SED) 's,^#include "provenance_relay.h",//&,' ./camflow-dev/security/provenance/include/provenance_record.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/include/provenance_record.h

preprocess_record:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -E ./camflow-dev/security/provenance/include/provenance_record.h > ./camflow-dev/security/provenance/include/provenance_record_pp.h

remedy_inode:
	$(SED) 's,^#include <linux/file.h>,//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/fs.h>,//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/namei.h>,//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/xattr.h>,//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_record.h",//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_policy.h",//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_filter.h",//&,' ./camflow-dev/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/include/provenance_inode.h

preprocess_inode:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -E ./camflow-dev/security/provenance/include/provenance_inode.h > ./camflow-dev/security/provenance/include/provenance_inode_pp.h

remedy_net:
	$(SED) 's,^#include <net/sock.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <net/ip.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/netfilter_ipv4.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/netfilter_ipv6.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/ip.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/tcp.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/udp.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/skbuff.h>,//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance.h",//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance_policy.h",//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance_inode.h",//&,' ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/include/provenance_net.h

	$(SED) "s;list_for_each_safe;while;" ./camflow-dev/security/provenance/include/provenance_net.h
	$(SED) "s;list_entry(listentry, struct ipv4_filters, list);list_entry(listentry, ipv4_filters, list);" ./camflow-dev/security/provenance/include/provenance_net.h

preprocess_net:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -E ./camflow-dev/security/provenance/include/provenance_net.h > ./camflow-dev/security/provenance/include/provenance_net_pp.h

remedy_task:
	$(SED) 's,^#include <linux/cred.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/binfmts.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/task.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/mm.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/signal.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/utsname.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/ipc_namespace.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/mnt_namespace.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/mm.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <net/net_namespace.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/pid_namespace.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/cputime.h>,//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "../../../fs/mount.h",//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_relay.h",//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_inode.h",//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_policy.h",//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/include/provenance_task.h
	
	$(SED) "s;min_t(unsigned int, len, PAGE_SIZE - ofs);min_t(len, PAGE_SIZE - ofs);" ./camflow-dev/security/provenance/include/provenance_task.h

preprocess_task:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -D'vm_flags_t=int' -D'pid_t=int' -D'unsigned=' -E ./camflow-dev/security/provenance/include/provenance_task.h > ./camflow-dev/security/provenance/include/provenance_task_pp.h

remedy_netfilter:
	$(SED) 's,^#include <net/net_namespace.h>,//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance.h",//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance_net.h",//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance_task.h",//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,#include "memcpy_ss.h",//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^__initcall,//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^module_init,//&,' ./camflow-dev/security/provenance/netfilter.c
	$(SED) 's,^module_exit,//&,' ./camflow-dev/security/provenance/netfilter.c

preprocess_netfilter:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -D'vm_flags_t=int' -D'pid_t=int' -D'unsigned=' -D'__net_init=' -D'__net_exit=' -D'__init=' -D'__exit=' -E ./camflow-dev/security/provenance/netfilter.c > ./camflow-dev/security/provenance/netfilter_pp.c

analyze:
	cd ../ && mkdir -p dot
	python main.py

all: remedy_hooks preprocess_hooks remedy_record preprocess_record remedy_inode preprocess_inode remedy_net preprocess_net remedy_task preprocess_task remedy_netfilter preprocess_netfilter

draw_all:
	python draw.py
