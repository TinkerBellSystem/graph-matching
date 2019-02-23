# 1 "./camflow/provenance_inode.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "./camflow/provenance_inode.h" 2
# 45 "./camflow/provenance_inode.h"
static inline void update_inode_type(int mode, struct provenance *prov)
{
 union prov_elt old_prov;
 int type = ENT_INODE_UNKNOWN;
 unsigned long irqflags;

 if (S_ISBLK(mode))
  type = ENT_INODE_BLOCK;
 else if (S_ISCHR(mode))
  type = ENT_INODE_CHAR;
 else if (S_ISDIR(mode))
  type = ENT_INODE_DIRECTORY;
 else if (S_ISFIFO(mode))
  type = ENT_INODE_PIPE;
 else if (S_ISLNK(mode))
  type = ENT_INODE_LINK;
 else if (S_ISREG(mode))
  type = ENT_INODE_FILE;
 else if (S_ISSOCK(mode))
  type = ENT_INODE_SOCKET;
 spin_lock_irqsave_nested(prov_lock(prov), irqflags, PROVENANCE_LOCK_INODE);
 if (prov_elt(prov)->inode_info.mode != 0
     && prov_elt(prov)->inode_info.mode != mode
     && provenance_is_recorded(prov_elt(prov))) {
  memcpy(&old_prov, prov_elt(prov), sizeof(old_prov));

  prov_elt(prov)->inode_info.mode = mode;
  prov_type(prov_elt(prov)) = type;
  node_identifier(prov_elt(prov)).version++;
  clear_recorded(prov_elt(prov));


  __write_relation(RL_VERSION, &old_prov, prov_elt(prov), NULL, 0);
  clear_has_outgoing(prov_elt(prov));
  clear_saved(prov_elt(prov));
 }
 prov_elt(prov)->inode_info.mode = mode;
 prov_type(prov_elt(prov)) = type;
 spin_unlock_irqrestore(prov_lock(prov), irqflags);
}

static inline void provenance_mark_as_opaque_dentry(const struct dentry *dentry)
{
 struct provenance *prov;

 if (IS_ERR(dentry))
  return;
 prov = dentry->d_inode->i_provenance;
 if (prov)
  set_opaque(prov_elt(prov));
}
# 105 "./camflow/provenance_inode.h"
static inline void provenance_mark_as_opaque(const char *name)
{
 struct path path;

 if (kern_path(name, LOOKUP_FOLLOW, &path)) {
  pr_err("Provenance: Failed file look up (%s).", name);
  return;
 }
 provenance_mark_as_opaque_dentry(path.dentry);
}
# 130 "./camflow/provenance_inode.h"
static inline int record_inode_name_from_dentry(struct dentry *dentry,
      struct provenance *prov,
      int force)
{
 char *buffer;
 char *ptr;
 int rc;

 if (provenance_is_name_recorded(prov_elt(prov)) ||
     !provenance_is_recorded(prov_elt(prov)))
  return 0;

 buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
 if (!buffer)
  return -ENOMEM;
 ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
 if (IS_ERR(ptr))
  return PTR_ERR(ptr);
 rc = record_node_name(prov, ptr, force);
 kfree(buffer);
 return rc;
}
# 165 "./camflow/provenance_inode.h"
static inline int record_inode_name(struct inode *inode, struct provenance *prov)
{
 struct dentry *dentry;
 int rc;

 if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
  return 0;
 dentry = d_find_alias(inode);
 if (!dentry)
  return 0;
 rc = record_inode_name_from_dentry(dentry, prov, false);
 dput(dentry);
 return rc;
}
# 193 "./camflow/provenance_inode.h"
static void refresh_inode_provenance(struct inode *inode,
           struct provenance *prov)
{
 if (provenance_is_opaque(prov_elt(prov)))
  return;
 record_inode_name(inode, prov);
 prov_elt(prov)->inode_info.ino = inode->i_ino;
 node_uid(prov_elt(prov)) = __kuid_val(inode->i_uid);
 node_gid(prov_elt(prov)) = __kgid_val(inode->i_gid);
 security_inode_getsecid(inode, &(prov_elt(prov)->inode_info.secid));
 update_inode_type(inode->i_mode, prov);
}
# 218 "./camflow/provenance_inode.h"
static inline int inode_init_provenance(struct inode *inode,
     struct dentry *opt_dentry,
     struct provenance *prov)
{
 union prov_elt *buf;
 struct dentry *dentry;
 int rc = 0;

 if (provenance_is_initialized(prov_elt(prov)))
  return 0;
 spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_INODE);
 if (provenance_is_initialized(prov_elt(prov))) {
  spin_unlock(prov_lock(prov));
  return 0;
 } else
  set_initialized(prov_elt(prov));
 spin_unlock(prov_lock(prov));
 update_inode_type(inode->i_mode, prov);
 if (!(inode->i_opflags & IOP_XATTR))
  return 0;
 if (opt_dentry)
  dentry = dget(opt_dentry);
 else
  dentry = d_find_alias(inode);
 if (!dentry)
  return 0;
 buf = kmalloc(sizeof(union prov_elt), GFP_NOFS);
 if (!buf) {
  clear_initialized(prov_elt(prov));
  dput(dentry);
  return -ENOMEM;
 }
 rc = __vfs_getxattr(dentry, inode, XATTR_NAME_PROVENANCE, buf, sizeof(union prov_elt));
 dput(dentry);
 if (rc < 0) {
  if (rc != -ENODATA && rc != -EOPNOTSUPP) {
   clear_initialized(prov_elt(prov));
   goto free_buf;
  } else {
   rc = 0;
   goto free_buf;
  }
 }
 memcpy(prov_elt(prov), buf, sizeof(union prov_elt));
 rc = 0;
free_buf:
 kfree(buf);
 return rc;
}
# 280 "./camflow/provenance_inode.h"
static struct provenance *get_inode_provenance(struct inode *inode, int may_sleep)
{
 struct provenance *iprov = inode->i_provenance;

 might_sleep_if(may_sleep);
 if (!provenance_is_initialized(prov_elt(iprov)) && may_sleep)
  inode_init_provenance(inode, NULL, iprov);
 if (may_sleep)
  refresh_inode_provenance(inode, iprov);
 return iprov;
}
# 302 "./camflow/provenance_inode.h"
static struct provenance *get_dentry_provenance(struct dentry *dentry, int may_sleep)
{
 struct inode *inode = d_backing_inode(dentry);

 if (!inode)
  return NULL;
 return get_inode_provenance(inode, may_sleep);
}
# 321 "./camflow/provenance_inode.h"
static struct provenance *get_file_provenance(struct file *file, int may_sleep)
{
 struct inode *inode = file_inode(file);

 if (!inode)
  return NULL;
 return get_inode_provenance(inode, may_sleep);
}

static inline void save_provenance(struct dentry *dentry)
{
 struct provenance *prov;
 union prov_elt buf;

 if (!dentry)
  return;
 prov = get_dentry_provenance(dentry, false);
 if (!prov)
  return;
 spin_lock(prov_lock(prov));

 if (!provenance_is_initialized(prov_elt(prov))
     || provenance_is_saved(prov_elt(prov))) {
  spin_unlock(prov_lock(prov));
  return;
 }
 memcpy(&buf, prov_elt(prov), sizeof(union prov_elt));
 set_saved(prov_elt(prov));
 spin_unlock(prov_lock(prov));
 clear_recorded(&buf);
 clear_name_recorded(&buf);
 if (!dentry)
  return;
 __vfs_setxattr_noperm(dentry, XATTR_NAME_PROVENANCE, &buf, sizeof(union prov_elt), 0);
}
# 382 "./camflow/provenance_inode.h"
static int record_write_xattr(int type,
           struct provenance *iprov,
           struct provenance *tprov,
           struct provenance *cprov,
           const char *name,
           const void *value,
           int size,
           const int flags)
{
 union long_prov_elt *xattr;
 int rc = 0;

 if (!provenance_is_tracked(prov_elt(iprov))
     && !provenance_is_tracked(prov_elt(tprov))
     && !provenance_is_tracked(prov_elt(cprov))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(type, prov_entry(cprov), prov_entry(iprov)))
  return 0;
 xattr = alloc_long_provenance(ENT_XATTR);
 if (!xattr)
  return -ENOMEM;
 memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
 xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';
 if (value) {
  if (size < PROV_XATTR_VALUE_SIZE) {
   xattr->xattr_info.size = size;
   memcpy(xattr->xattr_info.value, value, size);
  } else{
   xattr->xattr_info.size = PROV_XATTR_VALUE_SIZE;
   memcpy(xattr->xattr_info.value, value, PROV_XATTR_VALUE_SIZE);
  }
 }
 rc = record_relation(RL_PROC_READ, prov_entry(cprov), prov_entry(tprov), NULL, 0);
 if (rc < 0)
  goto out;
 rc = record_relation(type, prov_entry(tprov), xattr, NULL, flags);
 if (rc < 0)
  goto out;
 if (type == RL_SETXATTR)
  rc = record_relation(RL_SETXATTR_INODE, xattr, prov_entry(iprov), NULL, flags);
 else
  rc = record_relation(RL_RMVXATTR_INODE, xattr, prov_entry(iprov), NULL, flags);
out:
 free_long_provenance(xattr);
 return rc;
}
# 448 "./camflow/provenance_inode.h"
static int record_read_xattr(struct provenance *cprov,
          struct provenance *tprov,
          struct provenance *iprov,
          const char *name)
{
 union long_prov_elt *xattr;
 int rc = 0;

 if (!provenance_is_tracked(prov_elt(iprov))
     && !provenance_is_tracked(prov_elt(tprov))
     && !provenance_is_tracked(prov_elt(cprov))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(RL_GETXATTR, prov_entry(iprov), prov_entry(cprov)))
  return 0;
 xattr = alloc_long_provenance(ENT_XATTR);
 if (!xattr) {
  rc = -ENOMEM;
  goto out;
 }
 memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
 xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

 rc = record_relation(RL_GETXATTR_INODE, prov_entry(iprov), xattr, NULL, 0);
 if (rc < 0)
  goto out;
 rc = record_relation(RL_GETXATTR, xattr, prov_entry(tprov), NULL, 0);
 if (rc < 0)
  goto out;
 rc = record_relation(RL_PROC_WRITE, prov_entry(tprov), prov_entry(cprov), NULL, 0);
out:
 free_long_provenance(xattr);
 return rc;
}
# 499 "./camflow/provenance_inode.h"
static inline int file_mask_to_perms(int mode, unsigned int mask)
{
 int av = 0;

 if (!S_ISDIR(mode)) {
  if (mask & MAY_EXEC)
   av |= 0x00000001UL;
  if (mask & MAY_READ)
   av |= 0x00000002UL;
  if (mask & MAY_APPEND)
   av |= 0x00000004UL;
  else if (mask & MAY_WRITE)
   av |= 0x00000008UL;
 } else {
  if (mask & MAY_EXEC)
   av |= 0x00000010UL;
  if (mask & MAY_WRITE)
   av |= 0x00000020UL;
  if (mask & MAY_READ)
   av |= 0x00000040UL;
 }

 return av;
}
