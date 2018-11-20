remedy_hooks:
	sed -i '' 's,^#include <linux/slab.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/lsm_hooks.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/msg.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <net/sock.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <net/af_unix.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/binfmts.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/random.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/xattr.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/file.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include <linux/workqueue.h>,//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance.h",//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance_record.h",//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance_net.h",//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance_inode.h",//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance_task.h",//&,' ../camflow/hooks.c
	sed -i '' 's,^#include "provenance_machine.h",//&,' ../camflow/hooks.c

	sed -i '' "s;container_of(fown, struct file, f_owner);container_of(fown, file, f_owner);" ../camflow/hooks.c
	sed -i '' "s,call_provenance_alloc((prov_entry_t\*)\&pckprov),call_provenance_alloc(pckprov)," ../camflow/hooks.c
	sed -i '' "s,call_provenance_free((prov_entry_t\*)\&pckprov),call_provenance_free(pckprov)," ../camflow/hooks.c
	sed -i '' "s,__lsm_ro_after_init,," ../camflow/hooks.c
	sed -i '' "s,__ro_after_init,," ../camflow/hooks.c
	sed -i '' 's,^LIST_HEAD,//&,' ../camflow/hooks.c
	sed -i '' "s,__init,," ../camflow/hooks.c

	sed -i '' "s,#ifdef CONFIG_SECURITY_FLOW_FRIENDLY,#ifndef CONFIG_SECURITY_FLOW_FRIENDLY," ../camflow/hooks.c

preprocess_hooks:
	gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -D'bool=int' -D'uint32_t=int' -D'uint8_t=int' -D'uint16_t=int' -E ../camflow/hooks.c > ../camflow/hooks_pp.c

remedy_record:
	sed -i '' 's,^#include "provenance.h",//&,' ../camflow/provenance_record.h
	sed -i '' 's,^#include "provenance_relay.h",//&,' ../camflow/provenance_record.h

preprocess_record:
	gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -E ../camflow/provenance_record.h > ../camflow/provenance_record_pp.h

analyze:
	python ast.py

all: remedy_record preprocess_record remedy_hooks preprocess_hooks analyze

