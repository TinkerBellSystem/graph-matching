UNAME_S := $(shell uname -s)

SED:=
ifeq ($(UNAME_S),Linux)
	SED += sed -i
endif
ifeq ($(UNAME_S),Darwin)
	SED += sed -i ''
endif

CAMFLOW:= ./camflow-dev/

remedy_hooks:
	$(SED) 's,^#include <linux/slab.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/lsm_hooks.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/msg.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <net/sock.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <net/af_unix.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/binfmts.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/random.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/xattr.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/file.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/workqueue.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include <linux/ptrace.h>,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_record.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_net.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_inode.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_task.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "provenance_machine.h",//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/hooks.c

	$(SED) "s;container_of(fown, struct file, f_owner);container_of(fown, file, f_owner);" $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s,call_provenance_alloc((prov_entry_t\*)\&pckprov),call_provenance_alloc(pckprov)," $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s,call_provenance_free((prov_entry_t\*)\&pckprov),call_provenance_free(pckprov)," $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s,__lsm_ro_after_init,," $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s,__ro_after_init,," $(CAMFLOW)/security/provenance/hooks.c
	$(SED) 's,^LIST_HEAD,//&,' $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s,__init,," $(CAMFLOW)/security/provenance/hooks.c

	$(SED) "s,#ifdef CONFIG_SECURITY_FLOW_FRIENDLY,#ifndef CONFIG_SECURITY_FLOW_FRIENDLY," $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s;^DEFINE_LSM(provenance) =;struct lsm_provenance;" $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s!.name = \"provenance\",!int name;!" $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s!.blobs = \&provenance_blob_sizes,!int blobs;!" $(CAMFLOW)/security/provenance/hooks.c
	$(SED) "s!.init = provenance_init,!int init;!" $(CAMFLOW)/security/provenance/hooks.c


preprocess_hooks:
	gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -D'bool=int' -D'uint32_t=int' -D'uint8_t=int' -D'uint16_t=int' -D'spinlock_t=int' -E $(CAMFLOW)/security/provenance/hooks.c > $(CAMFLOW)/security/provenance/hooks_pp.c

remedy_record:
	$(SED) 's,^#include "provenance.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_record.h
	$(SED) 's,^#include "provenance_relay.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_record.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_record.h

preprocess_record:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -E $(CAMFLOW)/security/provenance/include/provenance_record.h > $(CAMFLOW)/security/provenance/include/provenance_record_pp.h

remedy_inode:
	$(SED) 's,^#include <linux/file.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/fs.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/namei.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include <linux/xattr.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_record.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_policy.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "provenance_filter.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_inode.h

preprocess_inode:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -E $(CAMFLOW)/security/provenance/include/provenance_inode.h > $(CAMFLOW)/security/provenance/include/provenance_inode_pp.h

remedy_net:
	$(SED) 's,^#include <net/sock.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <net/ip.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/netfilter_ipv4.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/netfilter_ipv6.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/ip.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/tcp.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/udp.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include <linux/skbuff.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance_policy.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "provenance_inode.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_net.h

	$(SED) "s;list_for_each_safe;while;" $(CAMFLOW)/security/provenance/include/provenance_net.h
	$(SED) "s;list_entry(listentry, struct ipv4_filters, list);list_entry(listentry, ipv4_filters, list);" $(CAMFLOW)/security/provenance/include/provenance_net.h

preprocess_net:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -E $(CAMFLOW)/security/provenance/include/provenance_net.h > $(CAMFLOW)/security/provenance/include/provenance_net_pp.h

remedy_task:
	$(SED) 's,^#include <linux/cred.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/binfmts.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/task.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/mm.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/signal.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/utsname.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/ipc_namespace.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/mnt_namespace.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/mm.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <net/net_namespace.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/pid_namespace.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include <linux/sched/cputime.h>,//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "../../../fs/mount.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_relay.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_inode.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "provenance_policy.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	$(SED) 's,^#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/include/provenance_task.h
	
	$(SED) "s;min_t(unsigned int, len, PAGE_SIZE - ofs);min_t(len, PAGE_SIZE - ofs);" $(CAMFLOW)/security/provenance/include/provenance_task.h

preprocess_task:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -D'vm_flags_t=int' -D'pid_t=int' -D'unsigned=' -E $(CAMFLOW)/security/provenance/include/provenance_task.h > $(CAMFLOW)/security/provenance/include/provenance_task_pp.h

remedy_netfilter:
	$(SED) 's,^#include <net/net_namespace.h>,//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance.h",//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance_net.h",//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^#include "provenance_task.h",//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,#include "memcpy_ss.h",//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^__initcall,//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^module_init,//&,' $(CAMFLOW)/security/provenance/netfilter.c
	$(SED) 's,^module_exit,//&,' $(CAMFLOW)/security/provenance/netfilter.c

preprocess_netfilter:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint16_t=int' -D'uint32_t=int' -D'size_t=int' -D'uint8_t=int' -D'vm_flags_t=int' -D'pid_t=int' -D'unsigned=' -D'__net_init=' -D'__net_exit=' -D'__init=' -D'__exit=' -E $(CAMFLOW)/security/provenance/netfilter.c > $(CAMFLOW)/security/provenance/netfilter_pp.c

venv/bin/activate: requirements.txt
	test -f venv/bin/activate || virtualenv -p $(shell which python) venv
	. venv/bin/activate ; \
	pip install -Ur requirements.txt ; \
	pip freeze | sort > requirements.txt
	touch venv/bin/activate

clean-pyc:
	find . -name '*.pyc' -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete
	find . -name '__pycache__' -type d | xargs rm -fr

analyze: clean-pyc venv/bin/activate
	cd ../ && mkdir -p dot
	. venv/bin/activate ; \
	python model.py --camflow $(CAMFLOW)

debug:
	python model.py --camflow $(CAMFLOW) -vv

prepare: remedy_hooks preprocess_hooks remedy_record preprocess_record remedy_inode preprocess_inode remedy_net preprocess_net remedy_task preprocess_task remedy_netfilter preprocess_netfilter

all: prepare analyze

draw_all:
	python draw.py
