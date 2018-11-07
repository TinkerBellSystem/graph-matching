# 1 "hooks.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "hooks.c" 2
# 13 "hooks.c"
# 1 "utils/fake_libc_include/linux/slab.h" 1
# 1 "utils/fake_libc_include/_fake_defines.h" 1
# 2 "utils/fake_libc_include/linux/slab.h" 2
# 1 "utils/fake_libc_include/_fake_typedefs.h" 1



typedef int size_t;
typedef int __builtin_va_list;
typedef int __gnuc_va_list;
typedef int va_list;
typedef int __int8_t;
typedef int __uint8_t;
typedef int __int16_t;
typedef int __uint16_t;
typedef int __int_least16_t;
typedef int __uint_least16_t;
typedef int __int32_t;
typedef int __uint32_t;
typedef int __int64_t;
typedef int __uint64_t;
typedef int __int_least32_t;
typedef int __uint_least32_t;
typedef int __s8;
typedef int __u8;
typedef int __s16;
typedef int __u16;
typedef int __s32;
typedef int __u32;
typedef int __s64;
typedef int __u64;
typedef int _LOCK_T;
typedef int _LOCK_RECURSIVE_T;
typedef int _off_t;
typedef int __dev_t;
typedef int __uid_t;
typedef int __gid_t;
typedef int _off64_t;
typedef int _fpos_t;
typedef int _ssize_t;
typedef int wint_t;
typedef int _mbstate_t;
typedef int _flock_t;
typedef int _iconv_t;
typedef int __ULong;
typedef int __FILE;
typedef int ptrdiff_t;
typedef int wchar_t;
typedef int __off_t;
typedef int __pid_t;
typedef int __loff_t;
typedef int u_char;
typedef int u_short;
typedef int u_int;
typedef int u_long;
typedef int ushort;
typedef int uint;
typedef int clock_t;
typedef int time_t;
typedef int daddr_t;
typedef int caddr_t;
typedef int ino_t;
typedef int off_t;
typedef int dev_t;
typedef int uid_t;
typedef int gid_t;
typedef int pid_t;
typedef int key_t;
typedef int ssize_t;
typedef int mode_t;
typedef int nlink_t;
typedef int fd_mask;
typedef int _types_fd_set;
typedef int clockid_t;
typedef int timer_t;
typedef int useconds_t;
typedef int suseconds_t;
typedef int FILE;
typedef int fpos_t;
typedef int cookie_read_function_t;
typedef int cookie_write_function_t;
typedef int cookie_seek_function_t;
typedef int cookie_close_function_t;
typedef int cookie_io_functions_t;
typedef int div_t;
typedef int ldiv_t;
typedef int lldiv_t;
typedef int sigset_t;
typedef int __sigset_t;
typedef int _sig_func_ptr;
typedef int sig_atomic_t;
typedef int __tzrule_type;
typedef int __tzinfo_type;
typedef int mbstate_t;
typedef int sem_t;
typedef int pthread_t;
typedef int pthread_attr_t;
typedef int pthread_mutex_t;
typedef int pthread_mutexattr_t;
typedef int pthread_cond_t;
typedef int pthread_condattr_t;
typedef int pthread_key_t;
typedef int pthread_once_t;
typedef int pthread_rwlock_t;
typedef int pthread_rwlockattr_t;
typedef int pthread_spinlock_t;
typedef int pthread_barrier_t;
typedef int pthread_barrierattr_t;
typedef int jmp_buf;
typedef int rlim_t;
typedef int sa_family_t;
typedef int sigjmp_buf;
typedef int stack_t;
typedef int siginfo_t;
typedef int z_stream;


typedef int int8_t;
typedef int uint8_t;
typedef int int16_t;
typedef int uint16_t;
typedef int int32_t;
typedef int uint32_t;
typedef int int64_t;
typedef int uint64_t;


typedef int int_least8_t;
typedef int uint_least8_t;
typedef int int_least16_t;
typedef int uint_least16_t;
typedef int int_least32_t;
typedef int uint_least32_t;
typedef int int_least64_t;
typedef int uint_least64_t;


typedef int int_fast8_t;
typedef int uint_fast8_t;
typedef int int_fast16_t;
typedef int uint_fast16_t;
typedef int int_fast32_t;
typedef int uint_fast32_t;
typedef int int_fast64_t;
typedef int uint_fast64_t;


typedef int intptr_t;
typedef int uintptr_t;


typedef int intmax_t;
typedef int uintmax_t;


typedef _Bool bool;


typedef void* MirEGLNativeWindowType;
typedef void* MirEGLNativeDisplayType;
typedef struct MirConnection MirConnection;
typedef struct MirSurface MirSurface;
typedef struct MirSurfaceSpec MirSurfaceSpec;
typedef struct MirScreencast MirScreencast;
typedef struct MirPromptSession MirPromptSession;
typedef struct MirBufferStream MirBufferStream;
typedef struct MirPersistentId MirPersistentId;
typedef struct MirBlob MirBlob;
typedef struct MirDisplayConfig MirDisplayConfig;


typedef struct xcb_connection_t xcb_connection_t;
typedef uint32_t xcb_window_t;
typedef uint32_t xcb_visualid_t;
# 3 "utils/fake_libc_include/linux/slab.h" 2
# 14 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/lsm_hooks.h" 1
# 15 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/msg.h" 1
# 16 "hooks.c" 2
# 1 "utils/fake_libc_include/net/sock.h" 1
# 17 "hooks.c" 2
# 1 "utils/fake_libc_include/net/af_unix.h" 1
# 18 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/binfmts.h" 1
# 19 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/random.h" 1
# 20 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/xattr.h" 1
# 21 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/file.h" 1
# 22 "hooks.c" 2
# 1 "utils/fake_libc_include/linux/workqueue.h" 1
# 23 "hooks.c" 2
# 77 "hooks.c"
static inline void queue_save_provenance(struct provenance *provenance,
      struct dentry *dentry)
{
}
# 95 "hooks.c"
static int provenance_task_alloc(struct task_struct *task,
     unsigned long clone_flags)
{
 struct provenance *ntprov = alloc_provenance(ACT_TASK, GFP_KERNEL);
 const struct cred *cred;
 struct task_struct *t = current;
 struct provenance *tprov;
 struct provenance *cprov;

 task->provenance = ntprov;
 if (t != 0) {
  cred = t->real_cred;
  tprov = t->provenance;
  if (cred != 0) {
   cprov = cred->provenance;
   if (tprov != 0 && cprov != 0) {
    uses_two(RL_PROC_READ, cprov, tprov, 0, clone_flags);
    informs(RL_CLONE, tprov, ntprov, 0, clone_flags);
   }
  }
 }
 return 0;
}
# 128 "hooks.c"
static void provenance_task_free(struct task_struct *task)
{
 struct provenance *tprov = task->provenance;
 if (tprov) {
  record_terminate(RL_TERMINATE_TASK, tprov);
  free_provenance(tprov);
 }
 task->provenance = 0;
}
# 146 "hooks.c"
static void cred_init_provenance(void)
{
 struct cred *cred = (struct cred*)current->real_cred;
 struct provenance *prov = alloc_provenance(ENT_PROC, GFP_KERNEL);

 if (!prov)
  panic("Provenance:  Failed to initialize initial task.\n");
 node_uid(prov_elt(prov)) = __kuid_val(cred->euid);
 node_gid(prov_elt(prov)) = __kgid_val(cred->egid);
 cred->provenance = prov;
}
# 170 "hooks.c"
static int provenance_cred_alloc_blank(struct cred *cred, int gfp)
{
 struct provenance *prov = alloc_provenance(ENT_PROC, gfp);

 if (!prov)
  return -ENOMEM;

 node_uid(prov_elt(prov)) = __kuid_val(cred->euid);
 node_gid(prov_elt(prov)) = __kgid_val(cred->egid);
 cred->provenance = prov;
 return 0;
}
# 193 "hooks.c"
static void provenance_cred_free(struct cred *cred)
{
 struct provenance *cprov = cred->provenance;
 if (cprov) {
  record_terminate(RL_TERMINATE_PROC, cprov);
  free_provenance(cprov);
 }
 cred->provenance = 0;
}
# 216 "hooks.c"
static int provenance_cred_prepare(struct cred *new,
       const struct cred *old,
       int gfp)
{
 struct provenance *old_prov = old->provenance;
 struct provenance *nprov = alloc_provenance(ENT_PROC, gfp);
 struct provenance *tprov;
 unsigned long irqflags;
 int rc = 0;

 if (!nprov)
  return -ENOMEM;
 node_uid(prov_elt(nprov)) = __kuid_val(new->euid);
 node_gid(prov_elt(nprov)) = __kgid_val(new->egid);
 spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_PROC);
 if (current != 0) {


  tprov = current->provenance;
  if (tprov != 0) {
   rc = generates(RL_CLONE_MEM, old_prov, tprov, nprov, 0, 0);
  }
 }
 spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
 new->provenance = nprov;
 return rc;
}
# 254 "hooks.c"
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
 const struct provenance *old_prov = old->provenance;
 struct provenance *prov = new->provenance;

 *prov = *old_prov;
}
# 277 "hooks.c"
static int provenance_task_fix_setuid(struct cred *new,
          const struct cred *old,
          int flags)
{
 struct provenance *old_prov = old->provenance;
 struct provenance *nprov = new->provenance;
 struct provenance *tprov = get_task_provenance();
 unsigned long irqflags;
 int rc;

 spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_PROC);
 rc = generates(RL_SETUID, old_prov, tprov, nprov, 0, flags);
 spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
 return rc;
}
# 307 "hooks.c"
static int provenance_task_setpgid(struct task_struct *p, pid_t pgid)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 const struct cred *cred = get_task_cred(p);
 struct provenance *nprov = cred->provenance;
 int rc;

 prov_elt(nprov)->proc_info.gid = pgid;
 rc = generates(RL_SETGID, cprov, tprov, nprov, 0, 0);
 put_cred(cred);
 return rc;
}

static int provenance_task_getpgid(struct task_struct *p)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 const struct cred *cred = get_task_cred(p);
 struct provenance *nprov = cred->provenance;
 int rc;

 rc = uses(RL_GETGID, nprov, tprov, cprov, 0, 0);
 put_cred(cred);
 return rc;
}
# 349 "hooks.c"
static int provenance_task_kill(struct task_struct *p, struct siginfo *info,
    int sig, const struct cred *cred)
{
 return 0;
}
# 369 "hooks.c"
static int provenance_inode_alloc_security(struct inode *inode)
{
 struct provenance *iprov = alloc_provenance(ENT_INODE_UNKNOWN, GFP_KERNEL);
 struct provenance *sprov;

 if (unlikely(!iprov))
  return -ENOMEM;
 sprov = inode->i_sb->s_provenance;
 memcpy(prov_elt(iprov)->inode_info.sb_uuid, prov_elt(sprov)->sb_info.uuid, 16 * sizeof(uint8_t));
 inode->i_provenance = iprov;
 refresh_inode_provenance(inode);
 return 0;
}
# 393 "hooks.c"
static void provenance_inode_free_security(struct inode *inode)
{
 struct provenance *iprov = inode->i_provenance;
 if (iprov) {
  record_terminate(RL_FREED, iprov);
  free_provenance(iprov);
 }
 inode->i_provenance = 0;
}
# 415 "hooks.c"
static int provenance_inode_create(struct inode *dir,
       struct dentry *dentry,
       int mode)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = inode_provenance(dir, 1);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_DIR);
 rc = generates(RL_INODE_CREATE, cprov, tprov, iprov, 0, mode);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 460 "hooks.c"
static int provenance_inode_permission(struct inode *inode, int mask)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 unsigned long irqflags;
 int rc = 0;

 if (!mask)
  return 0;
 if (unlikely(IS_PRIVATE(inode)))
  return 0;
 iprov = inode_provenance(inode, 0);
 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (mask & MAY_EXEC) {
  rc = uses(RL_PERM_EXEC, iprov, tprov, cprov, 0, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_READ) {
  rc = uses(RL_PERM_READ, iprov, tprov, cprov, 0, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_APPEND) {
  rc = uses(RL_PERM_APPEND, iprov, tprov, cprov, 0, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_WRITE) {
  rc = uses(RL_PERM_WRITE, iprov, tprov, cprov, 0, mask);
  if (rc < 0)
   goto out;
 }
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 523 "hooks.c"
static int provenance_inode_link(struct dentry *old_dentry,
     struct inode *dir,
     struct dentry *new_dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 struct provenance *dprov = 0;
 unsigned long irqflags;
 int rc;

 iprov = dentry_provenance(old_dentry, 1);
 if (!iprov)
  return -ENOMEM;

 dprov = inode_provenance(dir, 1);
 if (!dprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_LINK, cprov, tprov, dprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_LINK, cprov, tprov, iprov, 0, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 record_inode_name_from_dentry(new_dentry, iprov, 1);
 return rc;
}







static int provenance_inode_unlink(struct inode *dir, struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 struct provenance *dprov = 0;
 unsigned long irqflags;
 int rc;

 iprov = dentry_provenance(dentry, 1);
 if (!iprov)
  return -ENOMEM;

 dprov = inode_provenance(dir, 1);
 if (!dprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_UNLINK, cprov, tprov, dprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_UNLINK, cprov, tprov, iprov, 0, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 602 "hooks.c"
static int provenance_inode_symlink(struct inode *dir,
        struct dentry *dentry,
        const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 struct provenance *dprov = 0;
 unsigned long irqflags;
 int rc;

 iprov = dentry_provenance(dentry, 1);
 if (!iprov)
  return 0;

 dprov = inode_provenance(dir, 1);
 if (!dprov)
  return 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SYMLINK, cprov, tprov, dprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SYMLINK, cprov, tprov, iprov, 0, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 record_node_name(iprov, name, 1);
 return rc;
}
# 648 "hooks.c"
static int provenance_inode_rename(struct inode *old_dir,
       struct dentry *old_dentry,
       struct inode *new_dir,
       struct dentry *new_dentry)
{
 return provenance_inode_link(old_dentry, new_dir, new_dentry);
}
# 675 "hooks.c"
static int provenance_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov;
 struct provenance *iattrprov;
 unsigned long irqflags;
 int rc;

 iprov = dentry_provenance(dentry, 1);
 if (!iprov)
  return -ENOMEM;
 iattrprov = alloc_provenance(ENT_IATTR, GFP_KERNEL);
 if (!iattrprov)
  return -ENOMEM;

 prov_elt(iattrprov)->iattr_info.valid = iattr->ia_valid;
 prov_elt(iattrprov)->iattr_info.mode = iattr->ia_mode;
 node_uid(prov_elt(iattrprov)) = __kuid_val(iattr->ia_uid);
 node_gid(prov_elt(iattrprov)) = __kgid_val(iattr->ia_gid);
 prov_elt(iattrprov)->iattr_info.size = iattr->ia_size;
 prov_elt(iattrprov)->iattr_info.atime = iattr->ia_atime.tv_sec;
 prov_elt(iattrprov)->iattr_info.mtime = iattr->ia_mtime.tv_sec;
 prov_elt(iattrprov)->iattr_info.ctime = iattr->ia_ctime.tv_sec;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SETATTR, cprov, tprov, iattrprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = derives(RL_SETATTR_INODE, iattrprov, iprov, 0, 0);
out:
 queue_save_provenance(iprov, dentry);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 free_provenance(iattrprov);
 return rc;
}
# 724 "hooks.c"
static int provenance_inode_getattr(const struct path *path)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(path->dentry, 1);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_GETATTR, iprov, tprov, cprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 753 "hooks.c"
static int provenance_inode_readlink(struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(dentry, 1);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_READ_LINK, iprov, tprov, cprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 784 "hooks.c"
static int provenance_inode_setxattr(struct dentry *dentry,
         const char *name,
         const void *value,
         size_t size,
         int flags)
{
 struct provenance *prov;
 union prov_elt *setting;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0) {
  if (size != sizeof(union prov_elt))
   return -ENOMEM;
  prov = dentry_provenance(dentry, 1);
  setting = (union prov_elt*)value;

  if (provenance_is_tracked(setting))
   set_tracked(prov_elt(prov));
  else
   clear_tracked(prov_elt(prov));

  if (provenance_is_opaque(setting))
   set_opaque(prov_elt(prov));
  else
   clear_opaque(prov_elt(prov));

  if (provenance_does_propagate(setting))
   set_propagate(prov_elt(prov));
  else
   clear_propagate(prov_elt(prov));

  prov_bloom_merge(prov_taint(prov_elt(prov)), prov_taint(setting));
 }
 return 0;
}
# 835 "hooks.c"
static void provenance_inode_post_setxattr(struct dentry *dentry,
        const char *name,
        const void *value,
        size_t size,
        int flags)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(dentry, 1);
 unsigned long irqflags;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
  return;

 if (!iprov)
  return;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 record_write_xattr(RL_SETXATTR, iprov, tprov, cprov, name, value, size, flags);
 queue_save_provenance(iprov, dentry);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
# 872 "hooks.c"
static int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(dentry, 1);
 int rc = 0;
 unsigned long irqflags;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
  return 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = record_read_xattr(cprov, tprov, iprov, name);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 904 "hooks.c"
static int provenance_inode_listxattr(struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(dentry, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_LSTXATTR, iprov, tprov, cprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 935 "hooks.c"
static int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = dentry_provenance(dentry, 1);
 unsigned long irqflags;
 int rc = 0;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
  return -EPERM;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = record_write_xattr(RL_RMVXATTR, iprov, tprov, cprov, name, 0, 0, 0);
 queue_save_provenance(iprov, dentry);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 972 "hooks.c"
static int provenance_inode_getsecurity(struct inode *inode,
     const char *name,
     void **buffer,
     bool alloc)
{
 struct provenance *iprov = inode_provenance(inode, 1);

 if (unlikely(!iprov))
  return -ENOMEM;
 if (strcmp(name, XATTR_PROVENANCE_SUFFIX))
  return -EOPNOTSUPP;
 if (!alloc)
  goto out;
 *buffer = kmalloc(sizeof(union prov_elt), GFP_KERNEL);
 memcpy(*buffer, prov_elt(iprov), sizeof(union prov_elt));
out:
 return sizeof(union prov_elt);
}
# 1005 "hooks.c"
static int provenance_inode_listsecurity(struct inode *inode,
      char *buffer,
      size_t buffer_size)
{
 const int len = sizeof(XATTR_NAME_PROVENANCE);

 if (buffer && len <= buffer_size)
  memcpy(buffer, XATTR_NAME_PROVENANCE, len);
 return len;
}
# 1038 "hooks.c"
static int provenance_file_permission(struct file *file, int mask)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(file, 1);
 struct inode *inode = file_inode(file);
 uint32_t perms;
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 perms = file_mask_to_perms(inode->i_mode, mask);
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (is_inode_dir(inode)) {
  if ((perms & (DIR__WRITE)) != 0) {
   rc = generates(RL_WRITE, cprov, tprov, iprov, file, mask);
   if (rc < 0)
    goto out;
  }
  if ((perms & (DIR__READ)) != 0) {
   rc = uses(RL_READ, iprov, tprov, cprov, file, mask);
   if (rc < 0)
    goto out;
  }
  if ((perms & (DIR__SEARCH)) != 0) {
   rc = uses(RL_SEARCH, iprov, tprov, cprov, file, mask);
   if (rc < 0)
    goto out;
  }
 } else if (is_inode_socket(inode)) {
  if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
   rc = generates(RL_SND, cprov, tprov, iprov, file, mask);
   if (rc < 0)
    goto out;
  }
  if ((perms & (FILE__READ)) != 0) {
   rc = uses(RL_RCV, iprov, tprov, cprov, file, mask);
   if (rc < 0)
    goto out;
  }
 } else {
  if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
   rc = generates(RL_WRITE, cprov, tprov, iprov, file, mask);
   if (rc < 0)
    goto out;
  }
  if ((perms & (FILE__READ)) != 0) {
   rc = uses(RL_READ, iprov, tprov, cprov, file, mask);
   if (rc < 0)
    goto out;
  }
  if ((perms & (FILE__EXECUTE)) != 0) {
   if (provenance_is_opaque(prov_elt(iprov)))
    set_opaque(prov_elt(cprov));
   else
    rc = derives(RL_EXEC, iprov, cprov, file, mask);
  }
 }
out:
 queue_save_provenance(iprov, file_dentry(file));
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1116 "hooks.c"
static int provenance_file_splice_pipe_to_pipe(struct file *in, struct file *out)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *inprov = file_provenance(in, 1);
 struct provenance *outprov = file_provenance(out, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!inprov || !outprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(inprov), irqflags, PROVENANCE_LOCK_INODE);
 spin_lock_nested(prov_lock(outprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_SPLICE_IN, inprov, tprov, cprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SPLICE_OUT, cprov, tprov, outprov, 0, 0);
out:
 spin_unlock(prov_lock(outprov));
 spin_unlock_irqrestore(prov_lock(inprov), irqflags);
 return rc;
}
# 1152 "hooks.c"
static int provenance_file_open(struct file *file, const struct cred *cred)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(file, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_OPEN, iprov, tprov, cprov, file, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1180 "hooks.c"
static int provenance_file_receive(struct file *file)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(file, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_FILE_RCV, iprov, tprov, cprov, file, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1206 "hooks.c"
static int provenance_file_lock(struct file *file, unsigned int cmd)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(file, 0);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_FILE_LOCK, cprov, tprov, iprov, file, cmd);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1235 "hooks.c"
static int provenance_file_send_sigiotask(struct task_struct *task,
       struct fown_struct *fown, int signum)
{

 struct provenance *iprov = file_provenance(file, 0);
 struct provenance *tprov = task->provenance;
 struct provenance *cprov = task_cred_xxx(task, provenance);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 if (!signum)
  signum = SIGIO;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_FILE_SIGIO, iprov, tprov, cprov, file, signum);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1285 "hooks.c"
static int provenance_mmap_file(struct file *file,
    unsigned long reqprot,
    unsigned long prot,
    unsigned long flags)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 struct provenance *bprov = 0;
 unsigned long irqflags;
 int rc = 0;

 if (unlikely(!file))
  return rc;
 iprov = file_provenance(file, 1);
 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (provenance_is_opaque(prov_elt(cprov)))
  goto out;
 if ((flags & MAP_TYPE) == MAP_SHARED
     || (flags & MAP_TYPE) == MAP_SHARED_VALIDATE) {
  if ((prot & (PROT_WRITE)) != 0)
   rc = generates(RL_MMAP_WRITE, cprov, tprov, iprov, file, flags);
  if (rc < 0)
   goto out;
  if ((prot & (PROT_READ)) != 0)
   rc = uses(RL_MMAP_READ, iprov, tprov, cprov, file, flags);
  if (rc < 0)
   goto out;
  if ((prot & (PROT_EXEC)) != 0)
   rc = uses(RL_MMAP_EXEC, iprov, tprov, cprov, file, flags);
 } else{
  bprov = branch_mmap(iprov, cprov);
  if (!bprov)
   goto out;
  rc = derives(RL_MMAP, iprov, bprov, file, flags);
  if (rc < 0)
   goto out;
  if ((prot & (PROT_WRITE)) != 0)
   rc = generates(RL_MMAP_WRITE, cprov, tprov, bprov, file, flags);
  if (rc < 0)
   goto out;
  if ((prot & (PROT_READ)) != 0)
   rc = uses(RL_MMAP_READ, bprov, tprov, cprov, file, flags);
  if (rc < 0)
   goto out;
  if ((prot & (PROT_EXEC)) != 0)
   rc = uses(RL_MMAP_EXEC, bprov, tprov, cprov, file, flags);
 }
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 if (bprov)
  free_provenance(bprov);
 return rc;
}
# 1358 "hooks.c"
static void provenance_mmap_munmap(struct mm_struct *mm,
       struct vm_area_struct *vma,
       unsigned long start,
       unsigned long end)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = 0;
 struct file *mmapf;
 unsigned long irqflags;
 int flags = vma->vm_flags;

 if ( vm_mayshare(flags) ) {
  mmapf = vma->vm_file;
  if (mmapf) {
   iprov = file_provenance(mmapf, 0);
   spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
   spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
   generates(RL_MUNMAP, cprov, tprov, iprov, mmapf, flags);
   spin_unlock(prov_lock(iprov));
   spin_unlock_irqrestore(prov_lock(cprov), irqflags);
  }
 }
}
# 1399 "hooks.c"
static int provenance_file_ioctl(struct file *file,
     unsigned int cmd,
     unsigned long arg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(file, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_WRITE_IOCTL, cprov, tprov, iprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = uses(RL_READ_IOCTL, iprov, tprov, cprov, 0, 0);
out:
 queue_save_provenance(iprov, file_dentry(file));
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1439 "hooks.c"
static int provenance_msg_msg_alloc_security(struct msg_msg *msg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *mprov;
 unsigned long irqflags;
 int rc = 0;

 mprov = alloc_provenance(ENT_MSG, GFP_KERNEL);

 if (!mprov)
  return -ENOMEM;
 prov_elt(mprov)->msg_msg_info.type = msg->m_type;
 msg->provenance = mprov;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 rc = generates(RL_MSG_CREATE, cprov, tprov, mprov, 0, 0);
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1468 "hooks.c"
static void provenance_msg_msg_free_security(struct msg_msg *msg)
{
 struct provenance *mprov = msg->provenance;
 if (mprov) {
  record_terminate(RL_FREED, mprov);
  free_provenance(mprov);
 }
 msg->provenance = 0;
}
# 1487 "hooks.c"
static inline int __mq_msgsnd(struct msg_msg *msg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *mprov = msg->provenance;
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
 rc = generates(RL_SND_MSG_Q, cprov, tprov, mprov, 0, 0);
 spin_unlock(prov_lock(mprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1514 "hooks.c"
static int provenance_msg_queue_msgsnd(struct kern_ipc_perm *msq,
           struct msg_msg *msg,
           int msqflg)
{
 return __mq_msgsnd(msg);
}
# 1532 "hooks.c"
static int provenance_mq_timedsend(struct inode *inode, struct msg_msg *msg,
       struct timespec64 *ts)
{
 return __mq_msgsnd(msg);
}
# 1548 "hooks.c"
static inline int __mq_msgrcv(struct provenance *cprov, struct msg_msg *msg)
{
 struct provenance *mprov = msg->provenance;
 struct provenance *tprov = get_task_provenance();
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
 rc = uses(RL_RCV_MSG_Q, mprov, tprov, cprov, 0, 0);
 spin_unlock(prov_lock(mprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1580 "hooks.c"
static int provenance_msg_queue_msgrcv(struct kern_ipc_perm *msq,
           struct msg_msg *msg,
           struct task_struct *target,
           long type,
           int mode)
{
 struct provenance *cprov = target->cred->provenance;

 return __mq_msgrcv(cprov, msg);
}
# 1603 "hooks.c"
static int provenance_mq_timedreceive(struct inode *inode, struct msg_msg *msg,
          struct timespec64 *ts)
{
 struct provenance *cprov = get_cred_provenance();

 return __mq_msgrcv(cprov, msg);
}
# 1627 "hooks.c"
static int provenance_shm_alloc_security(struct kern_ipc_perm *shp)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *sprov = alloc_provenance(ENT_SHM, GFP_KERNEL);
 unsigned long irqflags;
 int rc = 0;

 if (!sprov)
  return -ENOMEM;
 prov_elt(sprov)->shm_info.mode = shp->mode;
 shp->provenance = sprov;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 rc = generates(RL_SH_CREATE_READ, sprov, tprov, cprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SH_CREATE_WRITE, cprov, tprov, sprov, 0, 0);
out:
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return 0;
}
# 1657 "hooks.c"
static void provenance_shm_free_security(struct kern_ipc_perm *shp)
{
 struct provenance *sprov = shp->provenance;
 if (sprov) {
  record_terminate(RL_FREED, sprov);
  free_provenance(sprov);
 }
 shp->provenance = 0;
}
# 1685 "hooks.c"
static int provenance_shm_shmat(struct kern_ipc_perm *shp, char int *shmaddr, int shmflg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *sprov = shp->provenance;
 unsigned long irqflags;
 int rc = 0;

 if (!sprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(sprov), PROVENANCE_LOCK_SHM);
 if (shmflg & SHM_RDONLY)
  rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, 0, shmflg);
 else {
  rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, 0, shmflg);
  if (rc < 0)
   goto out;
  rc = uses(RL_SH_ATTACH_WRITE, cprov, tprov, sprov, 0, shmflg);
 }
out:
 spin_unlock(prov_lock(sprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1721 "hooks.c"
static void provenance_shm_shmdt(struct kern_ipc_perm *shp)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *sprov = shp->provenance;
 unsigned long irqflags;

 if (!sprov)
  return;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(sprov), PROVENANCE_LOCK_SHM);
 generates(RL_SHMDT, cprov, tprov, sprov, 0, 0);
 spin_unlock(prov_lock(sprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
# 1750 "hooks.c"
static int provenance_sk_alloc_security(struct sock *sk,
     int family,
     int priority)
{
 struct provenance *skprov = get_cred_provenance();

 if (!skprov)
  return -ENOMEM;
 sk->sk_provenance = skprov;
 return 0;
}
# 1786 "hooks.c"
static int provenance_socket_post_create(struct socket *sock,
      int family,
      int type,
      int protocol,
      int kern)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 if (kern)
  return 0;
 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_CREATE, cprov, tprov, iprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}

static int provenance_socket_socketpair(struct socket *socka, struct socket *sockb) {
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprova = socket_inode_provenance(socka);
 struct provenance *iprovb = socket_inode_provenance(sockb);
 unsigned long irqflags;
 int rc = 0;

 if (!iprova)
  return -ENOMEM;
 if (!iprovb)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprova, 0, 0);
 spin_unlock(prov_lock(iprova));
 if (rc < 0)
  goto out;
 spin_lock_nested(prov_lock(iprovb), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprovb, 0, 0);
 spin_unlock(prov_lock(iprovb));
out:
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1855 "hooks.c"
static int provenance_socket_bind(struct socket *sock,
      struct sockaddr *address,
      int addrlen)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 struct sockaddr_in *ipv4_addr;
 uint8_t op;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;

 if (provenance_is_opaque(prov_elt(cprov)))
  return rc;

 if (address->sa_family == PF_INET) {
  if (addrlen < sizeof(struct sockaddr_in))
   return -EINVAL;
  ipv4_addr = (struct sockaddr_in*)address;
  op = prov_ipv4_ingressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
  if ((op & PROV_SET_TRACKED) != 0) {
   set_tracked(prov_elt(iprov));
   set_tracked(prov_elt(cprov));
  }
  if ((op & PROV_SET_PROPAGATE) != 0) {
   set_propagate(prov_elt(iprov));
   set_propagate(prov_elt(cprov));
  }
  if ((op & PROV_SET_RECORD) != 0)
   set_record_packet(prov_elt(iprov));
 }
 rc = provenance_record_address(address, addrlen, iprov);
 if (rc < 0)
  return rc;
 rc = generates(RL_BIND, cprov, tprov, iprov, 0, 0);
 return rc;
}
# 1908 "hooks.c"
static int provenance_socket_connect(struct socket *sock,
         struct sockaddr *address,
         int addrlen)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 struct sockaddr_in *ipv4_addr;
 unsigned long irqflags;
 uint8_t op;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (provenance_is_opaque(prov_elt(cprov)))
  goto out;

 if (address->sa_family == PF_INET) {
  if (addrlen < sizeof(struct sockaddr_in)) {
   rc = -EINVAL;
   goto out;
  }
  ipv4_addr = (struct sockaddr_in*)address;
  op = prov_ipv4_egressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
  if ((op & PROV_SET_TRACKED) != 0) {
   set_tracked(prov_elt(iprov));
   set_tracked(prov_elt(cprov));
  }
  if ((op & PROV_SET_PROPAGATE) != 0) {
   set_propagate(prov_elt(iprov));
   set_propagate(prov_elt(cprov));
  }
  if ((op & PROV_SET_RECORD) != 0)
   set_record_packet(prov_elt(iprov));
 }
 rc = provenance_record_address(address, addrlen, iprov);
 if (rc < 0)
  goto out;
 rc = generates(RL_CONNECT, cprov, tprov, iprov, 0, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1966 "hooks.c"
static int provenance_socket_listen(struct socket *sock, int backlog)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_LISTEN, cprov, tprov, iprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2001 "hooks.c"
static int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 struct provenance *niprov = socket_inode_provenance(newsock);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = derives(RL_ACCEPT_SOCKET, iprov, niprov, 0, 0);
 if (rc < 0)
  goto out;
 rc = uses(RL_ACCEPT, niprov, tprov, cprov, 0, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2039 "hooks.c"
static int provenance_socket_sendmsg_always(struct socket *sock,
         struct msghdr *msg,
         int size) {}
static int provenance_socket_sendmsg(struct socket *sock,
         struct msghdr *msg,
         int size)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprova = socket_inode_provenance(sock);
 struct provenance *iprovb = 0;
 struct sock *peer = 0;
 unsigned long irqflags;
 int rc = 0;

 if (!iprova)
  return -ENOMEM;
 if (sock->sk->sk_family == PF_UNIX &&
     sock->sk->sk_type != SOCK_DGRAM) {
  peer = unix_peer_get(sock->sk);
  if (peer) {
   iprovb = sk_inode_provenance(peer);
   if (iprovb == cprov)
    iprovb = 0;
  }
 }
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_SOCKET);
 rc = generates(RL_SND_MSG, cprov, tprov, iprova, 0, 0);
 if (rc < 0)
  goto out;
 if (iprovb)
  rc = derives(RL_RCV_UNIX, iprova, iprovb, 0, 0);
out:
 spin_unlock(prov_lock(iprova));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 if (peer)
  sock_put(peer);
 return rc;
}
# 2097 "hooks.c"
static int provenance_socket_recvmsg_always(struct socket *sock,
         struct msghdr *msg,
         int size,
         int flags) {}
static int provenance_socket_recvmsg(struct socket *sock,
         struct msghdr *msg,
         int size,
         int flags)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = socket_inode_provenance(sock);
 struct provenance *pprov = 0;
 struct sock *peer = 0;
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 if (sock->sk->sk_family == PF_UNIX &&
     sock->sk->sk_type != SOCK_DGRAM) {
  peer = unix_peer_get(sock->sk);
  if (peer) {
   pprov = sk_provenance(peer);
   if (pprov == cprov)
    pprov = 0;
  }
 }
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (pprov) {
  rc = derives(RL_SND_UNIX, pprov, iprov, 0, flags);
  if (rc < 0)
   goto out;
 }
 rc = uses(RL_RCV_MSG, iprov, tprov, cprov, 0, flags);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 if (peer)
  sock_put(peer);
 return rc;
}
# 2158 "hooks.c"
static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
 struct provenance *iprov;
 struct provenance pckprov;
 uint16_t family = sk->sk_family;
 unsigned long irqflags;
 int rc = 0;

 if (family != PF_INET)
  return 0;
 iprov = sk_inode_provenance(sk);
 if (!iprov)
  return -ENOMEM;
 if (provenance_is_tracked(prov_elt(iprov))) {
  memset(&pckprov, 0, sizeof(struct provenance));
  provenance_parse_skb_ipv4(skb, prov_elt((&pckprov)));

  if (provenance_records_packet(prov_elt(iprov)))
   provenance_packet_content(skb, &pckprov);

  spin_lock_irqsave(prov_lock(iprov), irqflags);

  rc = derives(RL_RCV_PACKET, &pckprov, iprov, 0, 0);

  spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 }
 return rc;
}
# 2202 "hooks.c"
static int provenance_unix_stream_connect(struct sock *sock,
       struct sock *other,
       struct sock *newsk)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = sk_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_CONNECT, cprov, tprov, iprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2231 "hooks.c"
static int provenance_unix_may_send(struct socket *sock,
        struct socket *other)
{
 struct provenance *iprov = socket_provenance(sock);
 struct provenance *oprov = socket_inode_provenance(other);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_SOCKET);
 spin_lock_nested(prov_lock(oprov), PROVENANCE_LOCK_SOCK);
 rc = derives(RL_SND_UNIX, iprov, oprov, 0, 0);
 spin_unlock(prov_lock(oprov));
 spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 return rc;
}
# 2264 "hooks.c"
static int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *iprov = file_provenance(bprm->file, 1);
 unsigned long irqflags;
 int rc = 0;

 if (!nprov)
  return -ENOMEM;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  return 0;
 }
 spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_INODE);
 rc = derives(RL_EXEC, iprov, nprov, 0, 0);
 spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 return rc;
}
# 2298 "hooks.c"
static int provenance_bprm_check_security(struct linux_binprm *bprm)
{
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = file_provenance(bprm->file, 0);

 if (!nprov)
  return -ENOMEM;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  set_opaque(prov_elt(tprov));
  return 0;
 }
 return prov_record_args(nprov, bprm);
}
# 2337 "hooks.c"
static void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *iprov = file_provenance(bprm->file, 1);
 unsigned long irqflags;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  set_opaque(prov_elt(tprov));
  return;
 }
 record_node_name(cprov, bprm->interp, 0);
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 derives(RL_EXEC_TASK, cprov, nprov, 0, 0);
 derives(RL_EXEC, iprov, nprov, 0, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
# 2371 "hooks.c"
static int provenance_sb_alloc_security(struct super_block *sb)
{
 struct provenance *sbprov = alloc_provenance(ENT_SBLCK, GFP_KERNEL);

 if (!sbprov)
  return -ENOMEM;
 sb->s_provenance = sbprov;
 return 0;
}
# 2389 "hooks.c"
static void provenance_sb_free_security(struct super_block *sb)
{
 if (sb->s_provenance)
  free_provenance(sb->s_provenance);
 sb->s_provenance = 0;
}
# 2408 "hooks.c"
static int provenance_sb_kern_mount(struct super_block *sb,
        int flags,
        void *data)
{
 int i;
 uint8_t c = 0;
 struct provenance *sbprov = sb->s_provenance;

 for (i = 0; i < 16; i++) {
  prov_elt(sbprov)->sb_info.uuid[i] = sb->s_uuid.b[i];
  c |= sb->s_uuid.b[i];
 }
 if (c == 0)
  get_random_bytes(prov_elt(sbprov)->sb_info.uuid, 16 * sizeof(uint8_t));
 return 0;
}
