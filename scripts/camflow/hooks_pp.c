# 1 "./camflow/hooks.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "./camflow/hooks.c" 2
# 78 "./camflow/hooks.c"
static inline void queue_save_provenance(struct provenance *provenance,
      struct dentry *dentry)
{
}
# 96 "./camflow/hooks.c"
static int provenance_task_alloc(struct task_struct *task,
     unsigned long clone_flags)
{
 struct provenance *ntprov = alloc_provenance(ACT_TASK, GFP_KERNEL);
 const struct cred *cred;
 struct task_struct *t = current;
 struct provenance *tprov;
 struct provenance *cprov;

 task->provenance = ntprov;
 if (t != NULL) {
  cred = t->real_cred;
  tprov = t->provenance;
  if (cred != NULL) {
   cprov = cred->provenance;
   if (tprov != NULL && cprov != NULL) {
    uses_two(RL_PROC_READ, cprov, tprov, NULL, clone_flags);
    informs(RL_CLONE, tprov, ntprov, NULL, clone_flags);
   }
  }
 }
 return 0;
}
# 129 "./camflow/hooks.c"
static void provenance_task_free(struct task_struct *task)
{
 struct provenance *tprov = task->provenance;
 if (tprov) {
  record_terminate(RL_TERMINATE_TASK, tprov);
  free_provenance(tprov);
 }
 task->provenance = NULL;
}
# 147 "./camflow/hooks.c"
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
# 171 "./camflow/hooks.c"
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
# 194 "./camflow/hooks.c"
static void provenance_cred_free(struct cred *cred)
{
 struct provenance *cprov = cred->provenance;
 if (cprov) {
  record_terminate(RL_TERMINATE_PROC, cprov);
  free_provenance(cprov);
 }
 cred->provenance = NULL;
}
# 217 "./camflow/hooks.c"
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
 if (current != NULL) {


  tprov = current->provenance;
  if (tprov != NULL) {
   rc = generates(RL_CLONE_MEM, old_prov, tprov, nprov, NULL, 0);
  }
 }
 spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
 new->provenance = nprov;
 return rc;
}
# 255 "./camflow/hooks.c"
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
 const struct provenance *old_prov = old->provenance;
 struct provenance *prov = new->provenance;

 *prov = *old_prov;
}
# 278 "./camflow/hooks.c"
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
 rc = generates(RL_SETUID, old_prov, tprov, nprov, NULL, flags);
 spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
 return rc;
}
# 308 "./camflow/hooks.c"
static int provenance_task_setpgid(struct task_struct *p, int pgid)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 const struct cred *cred = get_task_cred(p);
 struct provenance *nprov = cred->provenance;
 int rc;

 prov_elt(nprov)->proc_info.gid = pgid;
 rc = generates(RL_SETGID, cprov, tprov, nprov, NULL, 0);
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

 rc = uses(RL_GETGID, nprov, tprov, cprov, NULL, 0);
 put_cred(cred);
 return rc;
}
# 350 "./camflow/hooks.c"
static int provenance_task_kill(struct task_struct *p, struct siginfo *info,
    int sig, const struct cred *cred)
{
 return 0;
}
# 370 "./camflow/hooks.c"
static int provenance_inode_alloc_security(struct inode *inode)
{
 struct provenance *iprov = alloc_provenance(ENT_INODE_UNKNOWN, GFP_KERNEL);
 struct provenance *sprov;

 if (unlikely(!iprov))
  return -ENOMEM;
 sprov = inode->i_sb->s_provenance;
 memcpy(prov_elt(iprov)->inode_info.sb_uuid, prov_elt(sprov)->sb_info.uuid, 16 * sizeof(int));
 inode->i_provenance = iprov;
 refresh_inode_provenance(inode, iprov);
 return 0;
}
# 394 "./camflow/hooks.c"
static void provenance_inode_free_security(struct inode *inode)
{
 struct provenance *iprov = inode->i_provenance;
 if (iprov) {
  record_terminate(RL_FREED, iprov);
  free_provenance(iprov);
 }
 inode->i_provenance = NULL;
}
# 416 "./camflow/hooks.c"
static int provenance_inode_create(struct inode *dir,
       struct dentry *dentry,
       int mode)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_inode_provenance(dir, true);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_DIR);
 rc = generates(RL_INODE_CREATE, cprov, tprov, iprov, NULL, mode);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 461 "./camflow/hooks.c"
static int provenance_inode_permission(struct inode *inode, int mask)
{
 struct provenance *cprov = NULL;
 struct provenance *tprov = NULL;
 struct provenance *iprov = NULL;
 unsigned long irqflags;
 int rc = 0;

 if (!mask)
  return 0;
 if (unlikely(IS_PRIVATE(inode)))
  return 0;
 cprov = get_cred_provenance();
 tprov = get_task_provenance();
 iprov = get_inode_provenance(inode, false);
 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (mask & MAY_EXEC) {
  rc = uses(RL_PERM_EXEC, iprov, tprov, cprov, NULL, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_READ) {
  rc = uses(RL_PERM_READ, iprov, tprov, cprov, NULL, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_APPEND) {
  rc = uses(RL_PERM_APPEND, iprov, tprov, cprov, NULL, mask);
  if (rc < 0)
   goto out;
 }
 if (mask & MAY_WRITE) {
  rc = uses(RL_PERM_WRITE, iprov, tprov, cprov, NULL, mask);
  if (rc < 0)
   goto out;
 }
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 526 "./camflow/hooks.c"
static int provenance_inode_link(struct dentry *old_dentry,
     struct inode *dir,
     struct dentry *new_dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = NULL;
 struct provenance *dprov = NULL;
 unsigned long irqflags;
 int rc;

 iprov = get_dentry_provenance(old_dentry, true);
 if (!iprov)
  return -ENOMEM;

 dprov = get_inode_provenance(dir, true);
 if (!dprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_LINK, cprov, tprov, dprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_LINK, cprov, tprov, iprov, NULL, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 record_inode_name_from_dentry(new_dentry, iprov, true);
 return rc;
}







static int provenance_inode_unlink(struct inode *dir, struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = NULL;
 struct provenance *dprov = NULL;
 unsigned long irqflags;
 int rc;

 iprov = get_dentry_provenance(dentry, true);
 if (!iprov)
  return -ENOMEM;

 dprov = get_inode_provenance(dir, true);
 if (!dprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_UNLINK, cprov, tprov, dprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_UNLINK, cprov, tprov, iprov, NULL, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 605 "./camflow/hooks.c"
static int provenance_inode_symlink(struct inode *dir,
        struct dentry *dentry,
        const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = NULL;
 struct provenance *dprov = NULL;
 unsigned long irqflags;
 int rc;

 iprov = get_dentry_provenance(dentry, true);
 if (!iprov)
  return 0;

 dprov = get_inode_provenance(dir, true);
 if (!dprov)
  return 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SYMLINK, cprov, tprov, dprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SYMLINK, cprov, tprov, iprov, NULL, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock(prov_lock(dprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 record_node_name(iprov, name, true);
 return rc;
}
# 651 "./camflow/hooks.c"
static int provenance_inode_rename(struct inode *old_dir,
       struct dentry *old_dentry,
       struct inode *new_dir,
       struct dentry *new_dentry)
{
 return provenance_inode_link(old_dentry, new_dir, new_dentry);
}
# 678 "./camflow/hooks.c"
static int provenance_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov;
 struct provenance *iattrprov;
 unsigned long irqflags;
 int rc;

 iprov = get_dentry_provenance(dentry, true);
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
 rc = generates(RL_SETATTR, cprov, tprov, iattrprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = derives(RL_SETATTR_INODE, iattrprov, iprov, NULL, 0);
out:
 queue_save_provenance(iprov, dentry);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 free_provenance(iattrprov);
 return rc;
}
# 727 "./camflow/hooks.c"
static int provenance_inode_getattr(const struct path *path)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(path->dentry, true);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_GETATTR, iprov, tprov, cprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 756 "./camflow/hooks.c"
static int provenance_inode_readlink(struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(dentry, true);
 unsigned long irqflags;
 int rc;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_READ_LINK, iprov, tprov, cprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 787 "./camflow/hooks.c"
static int provenance_inode_setxattr(struct dentry *dentry,
         const char *name,
         const void *value,
         int size,
         int flags)
{
 struct provenance *prov;
 union prov_elt *setting;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0) {
  if (size != sizeof(union prov_elt))
   return -ENOMEM;
  prov = get_dentry_provenance(dentry, true);
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
# 838 "./camflow/hooks.c"
static void provenance_inode_post_setxattr(struct dentry *dentry,
        const char *name,
        const void *value,
        int size,
        int flags)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(dentry, true);
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
# 875 "./camflow/hooks.c"
static int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(dentry, true);
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
# 907 "./camflow/hooks.c"
static int provenance_inode_listxattr(struct dentry *dentry)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(dentry, true);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_LSTXATTR, iprov, tprov, cprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 938 "./camflow/hooks.c"
static int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_dentry_provenance(dentry, true);
 unsigned long irqflags;
 int rc = 0;

 if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
  return -EPERM;

 if (!iprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = record_write_xattr(RL_RMVXATTR, iprov, tprov, cprov, name, NULL, 0, 0);
 queue_save_provenance(iprov, dentry);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 975 "./camflow/hooks.c"
static int provenance_inode_getsecurity(struct inode *inode,
     const char *name,
     void **buffer,
     int alloc)
{
 struct provenance *iprov = get_inode_provenance(inode, true);

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
# 1008 "./camflow/hooks.c"
static int provenance_inode_listsecurity(struct inode *inode,
      char *buffer,
      int buffer_size)
{
 const int len = sizeof(XATTR_NAME_PROVENANCE);

 if (buffer && len <= buffer_size)
  memcpy(buffer, XATTR_NAME_PROVENANCE, len);
 return len;
}
# 1041 "./camflow/hooks.c"
static int provenance_file_permission(struct file *file, int mask)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, true);
 struct inode *inode = file_inode(file);
 int perms;
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
# 1120 "./camflow/hooks.c"
static int provenance_file_splice_pipe_to_pipe(struct file *in, struct file *out)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *inprov = get_file_provenance(in, true);
 struct provenance *outprov = get_file_provenance(out, true);
 unsigned long irqflags;
 int rc = 0;

 if (!inprov || !outprov)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(inprov), irqflags, PROVENANCE_LOCK_INODE);
 spin_lock_nested(prov_lock(outprov), PROVENANCE_LOCK_INODE);
 rc = uses(RL_SPLICE_IN, inprov, tprov, cprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SPLICE_OUT, cprov, tprov, outprov, NULL, 0);
out:
 spin_unlock(prov_lock(outprov));
 spin_unlock_irqrestore(prov_lock(inprov), irqflags);
 return rc;
}


static int provenance_kernel_read_file(struct file *file
                      , enum kernel_read_file_id id)
{
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, true);
 unsigned long irqflags;
 int rc = 0;

 if(!iprov)
  return 0;
 if(id!=READING_MODULE)
  return 0;
 spin_lock_irqsave_nested(prov_lock(tprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = influences_kernel(RL_LOAD_MODULE, iprov, tprov, file);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(tprov), irqflags);
 return rc;
}
# 1177 "./camflow/hooks.c"
static int provenance_file_open(struct file *file)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, true);
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
# 1205 "./camflow/hooks.c"
static int provenance_file_receive(struct file *file)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, true);
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
# 1231 "./camflow/hooks.c"
static int provenance_file_lock(struct file *file, unsigned int cmd)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, false);
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
# 1260 "./camflow/hooks.c"
static int provenance_file_send_sigiotask(struct task_struct *task,
       struct fown_struct *fown, int signum)
{
 struct file *file = container_of(fown, file, f_owner);
 struct provenance *iprov = get_file_provenance(file, false);
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
# 1310 "./camflow/hooks.c"
static int provenance_mmap_file(struct file *file,
    unsigned long reqprot,
    unsigned long prot,
    unsigned long flags)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = NULL;
 struct provenance *bprov = NULL;
 unsigned long irqflags;
 int rc = 0;

 if (unlikely(!file))
  return rc;
 iprov = get_file_provenance(file, true);
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
# 1384 "./camflow/hooks.c"
static void provenance_mmap_munmap(struct mm_struct *mm,
       struct vm_area_struct *vma,
       unsigned long start,
       unsigned long end)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = NULL;
 struct file *mmapf;
 unsigned long irqflags;
 int flags = vma->vm_flags;

 if ( vm_mayshare(flags) ) {
  mmapf = vma->vm_file;
  if (mmapf) {
   iprov = get_file_provenance(mmapf, false);
   spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
   spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
   generates(RL_MUNMAP, cprov, tprov, iprov, mmapf, flags);
   spin_unlock(prov_lock(iprov));
   spin_unlock_irqrestore(prov_lock(cprov), irqflags);
  }
 }
}
# 1426 "./camflow/hooks.c"
static int provenance_file_ioctl(struct file *file,
     unsigned int cmd,
     unsigned long arg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(file, true);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_WRITE_IOCTL, cprov, tprov, iprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = uses(RL_READ_IOCTL, iprov, tprov, cprov, NULL, 0);
out:
 queue_save_provenance(iprov, file_dentry(file));
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1466 "./camflow/hooks.c"
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
 rc = generates(RL_MSG_CREATE, cprov, tprov, mprov, NULL, 0);
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1495 "./camflow/hooks.c"
static void provenance_msg_msg_free_security(struct msg_msg *msg)
{
 struct provenance *mprov = msg->provenance;
 if (mprov) {
  record_terminate(RL_FREED, mprov);
  free_provenance(mprov);
 }
 msg->provenance = NULL;
}
# 1514 "./camflow/hooks.c"
static inline int __mq_msgsnd(struct msg_msg *msg)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *mprov = msg->provenance;
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
 rc = generates(RL_SND_MSG_Q, cprov, tprov, mprov, NULL, 0);
 spin_unlock(prov_lock(mprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1541 "./camflow/hooks.c"
static int provenance_msg_queue_msgsnd(struct kern_ipc_perm *msq,
           struct msg_msg *msg,
           int msqflg)
{
 return __mq_msgsnd(msg);
}
# 1560 "./camflow/hooks.c"
static int provenance_mq_timedsend(struct inode *inode, struct msg_msg *msg,
       struct timespec64 *ts)
{
 return __mq_msgsnd(msg);
}
# 1577 "./camflow/hooks.c"
static inline int __mq_msgrcv(struct provenance *cprov, struct msg_msg *msg)
{
 struct provenance *mprov = msg->provenance;
 struct provenance *tprov = get_task_provenance();
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
 rc = uses(RL_RCV_MSG_Q, mprov, tprov, cprov, NULL, 0);
 spin_unlock(prov_lock(mprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1609 "./camflow/hooks.c"
static int provenance_msg_queue_msgrcv(struct kern_ipc_perm *msq,
           struct msg_msg *msg,
           struct task_struct *target,
           long type,
           int mode)
{
 struct provenance *cprov = target->cred->provenance;

 return __mq_msgrcv(cprov, msg);
}
# 1633 "./camflow/hooks.c"
static int provenance_mq_timedreceive(struct inode *inode, struct msg_msg *msg,
          struct timespec64 *ts)
{
 struct provenance *cprov = get_cred_provenance();

 return __mq_msgrcv(cprov, msg);
}
# 1658 "./camflow/hooks.c"
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
 rc = generates(RL_SH_CREATE_READ, cprov, tprov, sprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = generates(RL_SH_CREATE_WRITE, cprov, tprov, sprov, NULL, 0);
out:
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return 0;
}
# 1688 "./camflow/hooks.c"
static void provenance_shm_free_security(struct kern_ipc_perm *shp)
{
 struct provenance *sprov = shp->provenance;
 if (sprov) {
  record_terminate(RL_FREED, sprov);
  free_provenance(sprov);
 }
 shp->provenance = NULL;
}
# 1716 "./camflow/hooks.c"
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
  rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, NULL, shmflg);
 else {
  rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, NULL, shmflg);
  if (rc < 0)
   goto out;
  rc = generates(RL_SH_ATTACH_WRITE, cprov, tprov, sprov, NULL, shmflg);
 }
out:
 spin_unlock(prov_lock(sprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1753 "./camflow/hooks.c"
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
 generates(RL_SHMDT, cprov, tprov, sprov, NULL, 0);
 spin_unlock(prov_lock(sprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
# 1783 "./camflow/hooks.c"
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
# 1819 "./camflow/hooks.c"
static int provenance_socket_post_create(struct socket *sock,
      int family,
      int type,
      int protocol,
      int kern)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 if (kern)
  return 0;
 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_CREATE, cprov, tprov, iprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}

static int provenance_socket_socketpair(struct socket *socka, struct socket *sockb) {
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprova = get_socket_inode_provenance(socka);
 struct provenance *iprovb = get_socket_inode_provenance(sockb);
 unsigned long irqflags;
 int rc = 0;

 if (!iprova)
  return -ENOMEM;
 if (!iprovb)
  return -ENOMEM;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprova, NULL, 0);
 spin_unlock(prov_lock(iprova));
 if (rc < 0)
  goto out;
 spin_lock_nested(prov_lock(iprovb), PROVENANCE_LOCK_INODE);
 rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprovb, NULL, 0);
 spin_unlock(prov_lock(iprovb));
out:
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1888 "./camflow/hooks.c"
static int provenance_socket_bind(struct socket *sock,
      struct sockaddr *address,
      int addrlen)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 struct sockaddr_in *ipv4_addr;
 int op;
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
 rc = record_address(address, addrlen, iprov);
 if (rc < 0)
  return rc;
 rc = generates(RL_BIND, cprov, tprov, iprov, NULL, 0);
 return rc;
}
# 1941 "./camflow/hooks.c"
static int provenance_socket_connect(struct socket *sock,
         struct sockaddr *address,
         int addrlen)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 struct sockaddr_in *ipv4_addr;
 unsigned long irqflags;
 int op;
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
 rc = record_address(address, addrlen, iprov);
 if (rc < 0)
  goto out;
 rc = generates(RL_CONNECT, cprov, tprov, iprov, NULL, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 1999 "./camflow/hooks.c"
static int provenance_socket_listen(struct socket *sock, int backlog)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_LISTEN, cprov, tprov, iprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2034 "./camflow/hooks.c"
static int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 struct provenance *niprov = get_socket_inode_provenance(newsock);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = derives(RL_ACCEPT_SOCKET, iprov, niprov, NULL, 0);
 if (rc < 0)
  goto out;
 rc = uses(RL_ACCEPT, niprov, tprov, cprov, NULL, 0);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2073 "./camflow/hooks.c"
static int provenance_socket_sendmsg_always(struct socket *sock,
         struct msghdr *msg,
         int size)





{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprova = get_socket_inode_provenance(sock);
 struct provenance *iprovb = NULL;
 struct sock *peer = NULL;
 unsigned long irqflags;
 int rc = 0;

 if (!iprova)
  return -ENOMEM;
 if (sock->sk->sk_family == PF_UNIX &&
     sock->sk->sk_type != SOCK_DGRAM) {
  peer = unix_peer_get(sock->sk);
  if (peer) {
   iprovb = get_sk_inode_provenance(peer);
   if (iprovb == cprov)
    iprovb = NULL;
  }
 }
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_SOCKET);
 rc = generates(RL_SND_MSG, cprov, tprov, iprova, NULL, 0);
 if (rc < 0)
  goto out;
 if (iprovb)
  rc = derives(RL_RCV_UNIX, iprova, iprovb, NULL, 0);
out:
 spin_unlock(prov_lock(iprova));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 if (peer)
  sock_put(peer);
 return rc;
}
# 2134 "./camflow/hooks.c"
static int provenance_socket_recvmsg_always(struct socket *sock,
         struct msghdr *msg,
         int size,
         int flags)






{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_socket_inode_provenance(sock);
 struct provenance *pprov = NULL;
 struct sock *peer = NULL;
 unsigned long irqflags;
 int rc = 0;

 if (!iprov)
  return -ENOMEM;
 if (sock->sk->sk_family == PF_UNIX &&
     sock->sk->sk_type != SOCK_DGRAM) {
  peer = unix_peer_get(sock->sk);
  if (peer) {
   pprov = get_sk_provenance(peer);
   if (pprov == cprov)
    pprov = NULL;
  }
 }
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 if (pprov) {
  rc = derives(RL_SND_UNIX, pprov, iprov, NULL, flags);
  if (rc < 0)
   goto out;
 }
 rc = uses(RL_RCV_MSG, iprov, tprov, cprov, NULL, flags);
out:
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 if (peer)
  sock_put(peer);
 return rc;
}
# 2197 "./camflow/hooks.c"
static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
 struct provenance *iprov;
 struct provenance pckprov;
 int family = sk->sk_family;
 unsigned long irqflags;
 int rc = 0;

 if (family != PF_INET)
  return 0;
 iprov = get_sk_inode_provenance(sk);
 if (!iprov)
  return -ENOMEM;
 if (provenance_is_tracked(prov_elt(iprov))) {
  memset(&pckprov, 0, sizeof(struct provenance));
  provenance_parse_skb_ipv4(skb, prov_elt((&pckprov)));

  if (provenance_records_packet(prov_elt(iprov)))
   record_packet_content(skb, &pckprov);

  spin_lock_irqsave(prov_lock(iprov), irqflags);
  call_provenance_alloc(pckprov);
  rc = derives(RL_RCV_PACKET, &pckprov, iprov, NULL, 0);
  call_provenance_free(pckprov);
  spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 }
 return rc;
}
# 2241 "./camflow/hooks.c"
static int provenance_unix_stream_connect(struct sock *sock,
       struct sock *other,
       struct sock *newsk)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_sk_inode_provenance(sock);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 rc = generates(RL_CONNECT, cprov, tprov, iprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
 return rc;
}
# 2270 "./camflow/hooks.c"
static int provenance_unix_may_send(struct socket *sock,
        struct socket *other)
{
 struct provenance *iprov = get_socket_provenance(sock);
 struct provenance *oprov = get_socket_inode_provenance(other);
 unsigned long irqflags;
 int rc = 0;

 spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_SOCKET);
 spin_lock_nested(prov_lock(oprov), PROVENANCE_LOCK_SOCK);
 rc = derives(RL_SND_UNIX, iprov, oprov, NULL, 0);
 spin_unlock(prov_lock(oprov));
 spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 return rc;
}
# 2303 "./camflow/hooks.c"
static int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *iprov = get_file_provenance(bprm->file, true);
 unsigned long irqflags;
 int rc = 0;

 if (!nprov)
  return -ENOMEM;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  return 0;
 }
 spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_INODE);
 rc = derives(RL_EXEC, iprov, nprov, NULL, 0);
 spin_unlock_irqrestore(prov_lock(iprov), irqflags);
 return rc;
}
# 2337 "./camflow/hooks.c"
static int provenance_bprm_check_security(struct linux_binprm *bprm)
{
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *tprov = get_task_provenance();
 struct provenance *iprov = get_file_provenance(bprm->file, false);

 if (!nprov)
  return -ENOMEM;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  set_opaque(prov_elt(tprov));
  return 0;
 }
 return record_args(nprov, bprm);
}
# 2376 "./camflow/hooks.c"
static void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
 struct provenance *cprov = get_cred_provenance();
 struct provenance *tprov = get_task_provenance();
 struct provenance *nprov = bprm->cred->provenance;
 struct provenance *iprov = get_file_provenance(bprm->file, true);
 unsigned long irqflags;

 if (provenance_is_opaque(prov_elt(iprov))) {
  set_opaque(prov_elt(nprov));
  set_opaque(prov_elt(tprov));
  return;
 }
 record_node_name(cprov, bprm->interp, false);
 spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
 spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
 derives(RL_EXEC_TASK, cprov, nprov, NULL, 0);
 derives(RL_EXEC, iprov, nprov, NULL, 0);
 spin_unlock(prov_lock(iprov));
 spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
# 2410 "./camflow/hooks.c"
static int provenance_sb_alloc_security(struct super_block *sb)
{
 struct provenance *sbprov = alloc_provenance(ENT_SBLCK, GFP_KERNEL);

 if (!sbprov)
  return -ENOMEM;
 sb->s_provenance = sbprov;
 return 0;
}
# 2428 "./camflow/hooks.c"
static void provenance_sb_free_security(struct super_block *sb)
{
 if (sb->s_provenance)
  free_provenance(sb->s_provenance);
 sb->s_provenance = NULL;
}
# 2447 "./camflow/hooks.c"
static int provenance_sb_kern_mount(struct super_block *sb,
        int flags,
        void *data)
{
 int i;
 int c = 0;
 struct provenance *sbprov = sb->s_provenance;

 for (i = 0; i < 16; i++) {
  prov_elt(sbprov)->sb_info.uuid[i] = sb->s_uuid.b[i];
  c |= sb->s_uuid.b[i];
 }
 if (c == 0)
  get_random_bytes(prov_elt(sbprov)->sb_info.uuid, 16 * sizeof(int));
 return 0;
}




static struct security_hook_list provenance_hooks[] = {

 LSM_HOOK_INIT(cred_free, provenance_cred_free),
 LSM_HOOK_INIT(cred_alloc_blank, provenance_cred_alloc_blank),
 LSM_HOOK_INIT(cred_prepare, provenance_cred_prepare),
 LSM_HOOK_INIT(cred_transfer, provenance_cred_transfer),
 LSM_HOOK_INIT(task_alloc, provenance_task_alloc),
 LSM_HOOK_INIT(task_free, provenance_task_free),
 LSM_HOOK_INIT(task_fix_setuid, provenance_task_fix_setuid),
 LSM_HOOK_INIT(task_setpgid, provenance_task_setpgid),
 LSM_HOOK_INIT(task_getpgid, provenance_task_getpgid),
 LSM_HOOK_INIT(task_kill, provenance_task_kill),


 LSM_HOOK_INIT(inode_alloc_security, provenance_inode_alloc_security),
 LSM_HOOK_INIT(inode_create, provenance_inode_create),
 LSM_HOOK_INIT(inode_free_security, provenance_inode_free_security),
 LSM_HOOK_INIT(inode_permission, provenance_inode_permission),
 LSM_HOOK_INIT(inode_link, provenance_inode_link),
 LSM_HOOK_INIT(inode_unlink, provenance_inode_unlink),
 LSM_HOOK_INIT(inode_symlink, provenance_inode_symlink),
 LSM_HOOK_INIT(inode_rename, provenance_inode_rename),
 LSM_HOOK_INIT(inode_setattr, provenance_inode_setattr),
 LSM_HOOK_INIT(inode_getattr, provenance_inode_getattr),
 LSM_HOOK_INIT(inode_readlink, provenance_inode_readlink),
 LSM_HOOK_INIT(inode_setxattr, provenance_inode_setxattr),
 LSM_HOOK_INIT(inode_post_setxattr, provenance_inode_post_setxattr),
 LSM_HOOK_INIT(inode_getxattr, provenance_inode_getxattr),
 LSM_HOOK_INIT(inode_listxattr, provenance_inode_listxattr),
 LSM_HOOK_INIT(inode_removexattr, provenance_inode_removexattr),
 LSM_HOOK_INIT(inode_getsecurity, provenance_inode_getsecurity),
 LSM_HOOK_INIT(inode_listsecurity, provenance_inode_listsecurity),


 LSM_HOOK_INIT(file_permission, provenance_file_permission),
 LSM_HOOK_INIT(mmap_file, provenance_mmap_file),

 LSM_HOOK_INIT(mmap_munmap, provenance_mmap_munmap),

 LSM_HOOK_INIT(file_ioctl, provenance_file_ioctl),
 LSM_HOOK_INIT(file_open, provenance_file_open),
 LSM_HOOK_INIT(file_receive, provenance_file_receive),
 LSM_HOOK_INIT(file_lock, provenance_file_lock),
 LSM_HOOK_INIT(file_send_sigiotask, provenance_file_send_sigiotask),

 LSM_HOOK_INIT(file_splice_pipe_to_pipe, provenance_file_splice_pipe_to_pipe),

 LSM_HOOK_INIT(kernel_read_file, provenance_kernel_read_file),


 LSM_HOOK_INIT(msg_msg_alloc_security, provenance_msg_msg_alloc_security),
 LSM_HOOK_INIT(msg_msg_free_security, provenance_msg_msg_free_security),
 LSM_HOOK_INIT(msg_queue_msgsnd, provenance_msg_queue_msgsnd),
 LSM_HOOK_INIT(msg_queue_msgrcv, provenance_msg_queue_msgrcv),


 LSM_HOOK_INIT(shm_alloc_security, provenance_shm_alloc_security),
 LSM_HOOK_INIT(shm_free_security, provenance_shm_free_security),
 LSM_HOOK_INIT(shm_shmat, provenance_shm_shmat),
 LSM_HOOK_INIT(shm_shmdt, provenance_shm_shmdt),


 LSM_HOOK_INIT(sk_alloc_security, provenance_sk_alloc_security),
 LSM_HOOK_INIT(socket_post_create, provenance_socket_post_create),
 LSM_HOOK_INIT(socket_socketpair, provenance_socket_socketpair),
 LSM_HOOK_INIT(socket_bind, provenance_socket_bind),
 LSM_HOOK_INIT(socket_connect, provenance_socket_connect),
 LSM_HOOK_INIT(socket_listen, provenance_socket_listen),
 LSM_HOOK_INIT(socket_accept, provenance_socket_accept),

 LSM_HOOK_INIT(socket_sendmsg_always, provenance_socket_sendmsg_always),
 LSM_HOOK_INIT(socket_recvmsg_always, provenance_socket_recvmsg_always),
 LSM_HOOK_INIT(mq_timedreceive, provenance_mq_timedreceive),
 LSM_HOOK_INIT(mq_timedsend, provenance_mq_timedsend),




 LSM_HOOK_INIT(socket_sock_rcv_skb, provenance_socket_sock_rcv_skb),
 LSM_HOOK_INIT(unix_stream_connect, provenance_unix_stream_connect),
 LSM_HOOK_INIT(unix_may_send, provenance_unix_may_send),


 LSM_HOOK_INIT(bprm_check_security, provenance_bprm_check_security),
 LSM_HOOK_INIT(bprm_set_creds, provenance_bprm_set_creds),
 LSM_HOOK_INIT(bprm_committing_creds, provenance_bprm_committing_creds),


 LSM_HOOK_INIT(sb_alloc_security, provenance_sb_alloc_security),
 LSM_HOOK_INIT(sb_free_security, provenance_sb_free_security),
 LSM_HOOK_INIT(sb_kern_mount, provenance_sb_kern_mount)
};

struct kmem_cache *provenance_cache ;
struct kmem_cache *long_provenance_cache ;

struct prov_boot_buffer *boot_buffer;
struct prov_long_boot_buffer *long_boot_buffer;
# 2575 "./camflow/hooks.c"
struct capture_policy prov_policy;

int prov_machine_id;
int prov_boot_id;
int epoch;
# 2600 "./camflow/hooks.c"
void provenance_add_hooks(void)
{
 prov_policy.prov_enabled = true;



 prov_policy.prov_all = false;

 prov_policy.prov_written = false;
 prov_policy.should_duplicate = false;
 prov_policy.should_compress_node = true;
 prov_policy.should_compress_edge = true;
 prov_machine_id = 0;
 prov_boot_id = 0;
 epoch = 1;
 provenance_cache = kmem_cache_create("provenance_struct",
          sizeof(struct provenance),
          0, SLAB_PANIC, NULL);
 if (unlikely(!provenance_cache))
  panic("Provenance: could not allocate provenance_cache.");
 long_provenance_cache = kmem_cache_create("long_provenance_struct",
        sizeof(union long_prov_elt),
        0, SLAB_PANIC, NULL);
 if (unlikely(!long_provenance_cache))
  panic("Provenance: could not allocate long_provenance_cache.");
 boot_buffer = kzalloc(sizeof(struct prov_boot_buffer), GFP_KERNEL);
 if (unlikely(!boot_buffer))
  panic("Provenance: could not allocate boot_buffer.");
 long_boot_buffer = kzalloc(sizeof(struct prov_long_boot_buffer), GFP_KERNEL);
 if (unlikely(!long_boot_buffer))
  panic("Provenance: could not allocate long_boot_buffer.");





 relay_ready = false;
 cred_init_provenance();
 init_prov_machine();
 print_prov_machine();
 security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks), "provenance");
 pr_info("Provenance: hooks ready.\n");
}
