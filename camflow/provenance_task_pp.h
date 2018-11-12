# 1 "provenance_task.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "provenance_task.h" 2
# 43 "provenance_task.h"
static inline int current_cgroupns(void)
{
 int id = 0;
 struct cgroup_namespace *cns;

 task_lock(current);
 if (current->nsproxy) {
  cns = current->nsproxy->cgroup_ns;
  if (cns) {
   get_cgroup_ns(cns);
   id = cns->ns.inum;
   put_cgroup_ns(cns);
  }
 }
 task_unlock(current);
 return id;
}

static inline int current_utsns(void)
{
 int id = 0;
 struct uts_namespace *ns;

 task_lock(current);
 if (current->nsproxy) {
  ns = current->nsproxy->uts_ns;
  if (ns) {
   get_uts_ns(ns);
   id = ns->ns.inum;
   put_uts_ns(ns);
  }
 }
 task_unlock(current);
 return id;
}

static inline int current_ipcns(void)
{
 int id = 0;
 struct ipc_namespace *ns;

 task_lock(current);
 if (current->nsproxy) {
  ns = current->nsproxy->ipc_ns;
  if (ns) {
   get_ipc_ns(ns);
   id = ns->ns.inum;
   put_ipc_ns(ns);
  }
 }
 task_unlock(current);
 return id;
}

static inline int current_mntns(void)
{
 int id = 0;
 struct mnt_namespace *ns;

 task_lock(current);
 if (current->nsproxy) {
  ns = current->nsproxy->mnt_ns;
  if (ns) {
   get_mnt_ns(ns);
   id = ns->ns.inum;
   put_mnt_ns(ns);
  }
 }
 task_unlock(current);
 return id;
}

static inline int current_netns(void)
{
 int id = 0;
 struct net *ns;

 task_lock(current);
 if (current->nsproxy) {
  ns = current->nsproxy->net_ns;
  if (ns) {
   get_net(ns);
   id = ns->ns.inum;
   put_net(ns);
  }
 }
 task_unlock(current);
 return id;
}

static inline int current_pidns(void)
{
 int id = 0;
 struct pid_namespace *ns;

 task_lock(current);
 ns = task_active_pid_ns(current);
 if (ns)
  id = ns->ns.inum;
 task_unlock(current);
 return id;
}
# 168 "provenance_task.h"
static int current_update_shst(struct provenance *cprov, int read)
{
 struct mm_struct *mm = get_task_mm(current);
 struct vm_area_struct *vma;
 struct file *mmapf;
 int flags;
 struct provenance *mmprov;
 int rc = 0;

 if (!mm)
  return rc;
 vma = mm->mmap;
 while (vma) {
  mmapf = vma->vm_file;
  if (mmapf) {
   flags = vma->vm_flags;
   mmprov = file_provenance(mmapf, false);
   if (mmprov) {
    if (((((flags & VM_READ) == VM_READ) || ((flags & VM_EXEC) == VM_EXEC)) && ((flags & (VM_SHARED | VM_MAYSHARE)) != 0)) && read)
     rc = record_relation(RL_SH_READ, prov_entry(mmprov), prov_entry(cprov), mmapf, flags);
    if ((((flags & VM_WRITE) == VM_WRITE) && ((flags & (VM_SHARED | VM_MAYSHARE)) != 0)) && !read)
     rc = record_relation(RL_SH_WRITE, prov_entry(cprov), prov_entry(mmprov), mmapf, flags);
   }
  }
  vma = vma->vm_next;
 }
 mmput_async(mm);
 return rc;
}
# 212 "provenance_task.h"
static inline int record_task_name(struct task_struct *task,
       struct provenance *prov)
{

 struct provenance *fprov;
 struct mm_struct *mm;
 struct file *exe_file;
 char *buffer;
 char *ptr;
 int rc = 0;

 if (provenance_is_name_recorded(prov_elt(prov)) ||
     !provenance_is_recorded(prov_elt(prov)))
  return 0;
 mm = get_task_mm(task);
 if (!mm)
  goto out;
 exe_file = get_mm_exe_file(mm);
 mmput_async(mm);
 if (exe_file) {
  fprov = file_provenance(exe_file, false);
  if (provenance_is_opaque(prov_elt(fprov))) {
   set_opaque(prov_elt(prov));
   goto out;
  }

  buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
  if (!buffer) {
   pr_err("Provenance: could not allocate memory\n");
   fput(exe_file);
   rc = -ENOMEM;
   goto out;
  }
  ptr = file_path(exe_file, buffer, PATH_MAX);
  fput(exe_file);
  rc = record_node_name(prov, ptr, false);
  kfree(buffer);
 }
out:

 return rc;
}
# 262 "provenance_task.h"
static inline void update_proc_perf(struct task_struct *task,
        struct provenance *prov)
{
 struct mm_struct *mm;
 int utime;
 int stime;


 task_cputime_adjusted(task, &utime, &stime);
 prov_elt(prov)->proc_info.utime = div_u64(utime, NSEC_PER_USEC);
 prov_elt(prov)->proc_info.stime = div_u64(stime, NSEC_PER_USEC);


 mm = get_task_mm(task);
 if (mm) {

  prov_elt(prov)->proc_info.vm = mm->total_vm * PAGE_SIZE / 1024;
  prov_elt(prov)->proc_info.rss = get_mm_rss(mm) * PAGE_SIZE / 1024;
  prov_elt(prov)->proc_info.hw_vm = get_mm_hiwater_vm(mm) * PAGE_SIZE / 1024;
  prov_elt(prov)->proc_info.hw_rss = get_mm_hiwater_rss(mm) * PAGE_SIZE / 1024;
  mmput_async(mm);
 }
# 293 "provenance_task.h"
 prov_elt(prov)->proc_info.rbytes = task->ioac.rchar & (~(1024 - 1));
 prov_elt(prov)->proc_info.wbytes = task->ioac.wchar & (~(1024 - 1));
 prov_elt(prov)->proc_info.cancel_wbytes = 0;

}
# 308 "provenance_task.h"
static inline struct provenance *get_cred_provenance(void)
{
 struct provenance *prov = current_provenance();
 unsigned long irqflags;

 if (provenance_is_opaque(prov_elt(prov)))
  goto out;
 record_task_name(current, prov);
 spin_lock_irqsave_nested(prov_lock(prov), irqflags, PROVENANCE_LOCK_PROC);
 prov_elt(prov)->proc_info.tgid = task_tgid_nr(current);
 prov_elt(prov)->proc_info.utsns = current_utsns();
 prov_elt(prov)->proc_info.ipcns = current_ipcns();
 prov_elt(prov)->proc_info.mntns = current_mntns();
 prov_elt(prov)->proc_info.pidns = current_pidns();
 prov_elt(prov)->proc_info.netns = current_netns();
 prov_elt(prov)->proc_info.cgroupns = current_cgroupns();
 prov_elt(prov)->proc_info.uid = __kuid_val(current_uid());
 prov_elt(prov)->proc_info.gid = __kgid_val(current_gid());
 security_task_getsecid(current, &(prov_elt(prov)->proc_info.secid));
 update_proc_perf(current, prov);
 spin_unlock_irqrestore(prov_lock(prov), irqflags);
out:
 return prov;
}
# 343 "provenance_task.h"
static inline struct provenance *get_task_provenance( void )
{
 struct provenance *prov = current->provenance;

 prov_elt(prov)->task_info.pid = task_pid_nr(current);
 prov_elt(prov)->task_info.vpid = task_pid_vnr(current);
 return prov;
}
# 359 "provenance_task.h"
static inline struct provenance *prov_from_vpid(int pid)
{
 struct provenance *tprov;
 struct task_struct *dest = find_task_by_vpid(pid);

 if (!dest)
  return NULL;

 tprov = __task_cred(dest)->provenance;
 if (!tprov)
  return NULL;
 return tprov;
}






static inline void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
 struct mm_struct *mm = current->mm;
 long diff = (long)(pages - bprm->vma_pages);

 if (!mm || !diff)
  return;

 bprm->vma_pages = pages;
 add_mm_counter(mm, MM_ANONPAGES, diff);
}






static inline struct page *get_arg_page(struct linux_binprm *bprm,
     unsigned long pos,
     int write)
{
 struct page *page;
 int ret;
 unsigned int gup_flags = FOLL_FORCE;
# 411 "provenance_task.h"
 if (write)
  gup_flags |= FOLL_WRITE;





 ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
        &page, NULL, NULL);
 if (ret <= 0)
  return NULL;

 if (write) {
  unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
  unsigned long ptr_size;
  struct rlimit *rlim;
# 440 "provenance_task.h"
  ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
  if (ptr_size > ULONG_MAX - size)
   goto fail;
  size += ptr_size;

  acct_arg_size(bprm, size / PAGE_SIZE);





  if (size <= ARG_MAX)
   return page;
# 461 "provenance_task.h"
  rlim = current->signal->rlim;
  if (size > READ_ONCE(rlim[RLIMIT_STACK].rlim_cur) / 4)
   goto fail;
 }

 return page;

fail:
 put_page(page);
 return NULL;
}
# 536 "provenance_task.h"
static int prov_record_arg(struct provenance *prov,
        int vtype,
        int etype,
        const char *arg,
        int len)
{
 union long_prov_elt *aprov;
 int rc = 0;

 aprov = alloc_long_provenance(vtype);
 if (!aprov)
  return -ENOMEM;
 aprov->arg_info.length = len;
 if ( len >= PATH_MAX)
  aprov->arg_info.truncated = PROV_TRUNCATED;
 strlcpy(aprov->arg_info.value, arg, PATH_MAX - 1);

 rc = record_relation(etype, aprov, prov_entry(prov), NULL, 0);
 free_long_provenance(aprov);
 return rc;
}
# 569 "provenance_task.h"
static inline int prov_record_args(struct provenance *prov,
       struct linux_binprm *bprm)
{
 char* argv;
 char* ptr;
 unsigned long len;
 int size;
 int rc = 0;
 int argc;
 int envc;

 if (!provenance_is_tracked(prov_elt(prov)) && !prov_policy.prov_all)
  return 0;
 len = bprm->exec - bprm->p;
 argv = kzalloc(len, GFP_KERNEL);
 if (!argv)
  return -ENOMEM;
 rc = copy_argv_bprm(bprm, argv, len);
 if (rc < 0)
  return -ENOMEM;
 argc = bprm->argc;
 envc = bprm->envc;
 ptr = argv;
 while (argc-- > 0) {
  size = strnlen(ptr, len);
  prov_record_arg(prov, ENT_ARG, RL_ARG, ptr, size);
  ptr += size + 1;
 }
 while (envc-- > 0) {
  size = strnlen(ptr, len);
  prov_record_arg(prov, ENT_ENV, RL_ENV, ptr, size);
  ptr += size + 1;
 }
 kfree(argv);
 return 0;
}
