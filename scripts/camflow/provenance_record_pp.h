# 1 "./camflow/provenance_record.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "./camflow/provenance_record.h" 2
# 39 "./camflow/provenance_record.h"
static int __update_version(const int type,
         int *prov)
{
 union prov_elt old_prov;
 int rc = 0;

 if (!provenance_has_outgoing(prov) && prov_policy.should_compress_node)
  return 0;

 if (filter_update_node(type))
  return 0;

 memcpy(&old_prov, prov, sizeof(union prov_elt));

 node_identifier(prov).version++;
 clear_recorded(prov);


 if (node_identifier(prov).type == ACT_TASK)
  rc = __write_relation(RL_VERSION_TASK, &old_prov, prov, NULL, 0);
 else
  rc = __write_relation(RL_VERSION, &old_prov, prov, NULL, 0);
 clear_has_outgoing(prov);
 clear_saved(prov);
 return rc;
}
# 88 "./camflow/provenance_record.h"
static int record_relation(const int type,
        int *from,
        int *to,
        const struct file *file,
        const int flags)
{
 int rc = 0;

 BUILD_BUG_ON(!prov_type_is_relation(type));

 if (prov_policy.should_compress_edge) {
  if (node_previous_id(to) == node_identifier(from).id
      && node_previous_type(to) == type)
   return 0;
  else {
   node_previous_id(to) = node_identifier(from).id;
   node_previous_type(to) = type;
  }
 }

 rc = __update_version(type, to);
 if (rc < 0)
  return rc;
 set_has_outgoing(from);
 rc = __write_relation(type, from, to, file, flags);
 return rc;
}
# 129 "./camflow/provenance_record.h"
static int record_terminate(int type, struct provenance *prov)
{
 union prov_elt old_prov;
 int rc;

 BUILD_BUG_ON(!prov_is_close(type));

 if (!provenance_is_recorded(prov_elt(prov)) && !prov_policy.prov_all)
  return 0;
 if (filter_node(prov_entry(prov)))
  return 0;
 memcpy(&old_prov, prov_elt(prov), sizeof(old_prov));
 node_identifier(prov_elt(prov)).version++;
 clear_recorded(prov_elt(prov));

 rc = __write_relation(type, &old_prov, prov_elt(prov), NULL, 0);
 clear_has_outgoing(prov_elt(prov));
 return rc;
}
# 166 "./camflow/provenance_record.h"
static inline int record_node_name(struct provenance *node,
       const char *name,
       int force)
{
 union long_prov_elt *fname_prov;
 int rc;

 if (provenance_is_opaque(prov_elt(node)))
  return 0;

 if ( (provenance_is_name_recorded(prov_elt(node)) && !force)
      || !provenance_is_recorded(prov_elt(node)))
  return 0;

 fname_prov = alloc_long_provenance(ENT_PATH);
 if (!fname_prov)
  return -ENOMEM;

 strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
 fname_prov->file_name_info.length = strnlen(fname_prov->file_name_info.name, PATH_MAX);


 spin_lock(prov_lock(node));
 if (prov_type(prov_elt(node)) == ACT_TASK) {
  rc = record_relation(RL_NAMED_PROCESS, fname_prov, prov_entry(node), NULL, 0);
  set_name_recorded(prov_elt(node));
 } else{
  rc = record_relation(RL_NAMED, fname_prov, prov_entry(node), NULL, 0);
  set_name_recorded(prov_elt(node));
 }
 spin_unlock(prov_lock(node));
 free_long_provenance(fname_prov);
 return rc;
}

static int record_kernel_link(int *node)
{
 int rc;

 if (provenance_is_kernel_recorded(node) ||
     !provenance_is_recorded(node))
  return 0;
 else {
  rc = record_relation(RL_RAN_ON, prov_machine, node, NULL, 0);
  set_kernel_recorded(node);
  return rc;
 }
}

static int current_update_shst(struct provenance *cprov, int read);
# 237 "./camflow/provenance_record.h"
static int uses(const int type,
    struct provenance *entity,
    struct provenance *activity,
    struct provenance *activity_mem,
    const struct file *file,
    const int flags)
{
 int rc;

 BUILD_BUG_ON(!prov_is_used(type));


 apply_target(prov_elt(entity));
 apply_target(prov_elt(activity));
 apply_target(prov_elt(activity_mem));

 if (provenance_is_opaque(prov_elt(entity))
     || provenance_is_opaque(prov_elt(activity))
     || provenance_is_opaque(prov_elt(activity_mem)))
  return 0;

 if (!provenance_is_tracked(prov_elt(entity))
     && !provenance_is_tracked(prov_elt(activity))
     && !provenance_is_tracked(prov_elt(activity_mem))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(type, prov_entry(entity), prov_entry(activity)))
  return 0;

 rc = record_relation(type, prov_entry(entity), prov_entry(activity), file, flags);
 if (rc < 0)
  return rc;
 rc = record_kernel_link(prov_entry(activity));
 if (rc < 0)
  return rc;
 rc = record_relation(RL_PROC_WRITE, prov_entry(activity), prov_entry(activity_mem), NULL, 0);
 if (rc < 0)
  return rc;
 return current_update_shst(activity_mem, false);
}
# 291 "./camflow/provenance_record.h"
static int uses_two(const int type,
        struct provenance *entity,
        struct provenance *activity,
        const struct file *file,
        const int flags)
{
 int rc;

 BUILD_BUG_ON(!prov_is_used(type));

 apply_target(prov_elt(entity));
 apply_target(prov_elt(activity));

 if (provenance_is_opaque(prov_elt(entity))
     || provenance_is_opaque(prov_elt(activity)))
  return 0;

 if (!provenance_is_tracked(prov_elt(entity))
     && !provenance_is_tracked(prov_elt(activity))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(type, prov_entry(entity), prov_entry(activity)))
  return 0;
 rc = record_relation(type, prov_entry(entity), prov_entry(activity), file, flags);
 if (rc < 0)
  return rc;
 return record_kernel_link(prov_entry(activity));
}
# 340 "./camflow/provenance_record.h"
static int generates(const int type,
         struct provenance *activity_mem,
         struct provenance *activity,
         struct provenance *entity,
         const struct file *file,
         const int flags)
{
 int rc;

 BUILD_BUG_ON(!prov_is_generated(type));

 apply_target(prov_elt(activity_mem));
 apply_target(prov_elt(activity));
 apply_target(prov_elt(entity));

 if (provenance_is_tracked(prov_elt(activity_mem)))
  set_tracked(prov_elt(activity));

 if (provenance_is_opaque(prov_elt(activity_mem)))
  set_opaque(prov_elt(activity));

 if (provenance_is_opaque(prov_elt(entity))
     || provenance_is_opaque(prov_elt(activity))
     || provenance_is_opaque(prov_elt(activity_mem)))
  return 0;

 if (!provenance_is_tracked(prov_elt(activity_mem))
     && !provenance_is_tracked(prov_elt(activity))
     && !provenance_is_tracked(prov_elt(entity))
     && !prov_policy.prov_all)
  return 0;

 if (!should_record_relation(type, prov_entry(activity), prov_entry(entity)))
  return 0;

 rc = current_update_shst(activity_mem, true);
 if (rc < 0)
  return rc;
 rc = record_relation(RL_PROC_READ, prov_entry(activity_mem), prov_entry(activity), NULL, 0);
 if (rc < 0)
  return rc;
 rc = record_kernel_link(prov_entry(activity));
 if (rc < 0)
  return rc;
 rc = record_relation(type, prov_entry(activity), prov_entry(entity), file, flags);
 return rc;
}
# 404 "./camflow/provenance_record.h"
static int derives(const int type,
       struct provenance *from,
       struct provenance *to,
       const struct file *file,
       const int flags)
{
 BUILD_BUG_ON(!prov_is_derived(type));

 apply_target(prov_elt(from));
 apply_target(prov_elt(to));

 if (provenance_is_opaque(prov_elt(from))
     || provenance_is_opaque(prov_elt(to)))
  return 0;

 if (!provenance_is_tracked(prov_elt(from))
     && !provenance_is_tracked(prov_elt(to))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
  return 0;

 return record_relation(type, prov_entry(from), prov_entry(to), file, flags);
}
# 445 "./camflow/provenance_record.h"
static int informs(const int type,
       struct provenance *from,
       struct provenance *to,
       const struct file *file,
       const int flags)
{
 int rc;

 BUILD_BUG_ON(!prov_is_informed(type));

 apply_target(prov_elt(from));
 apply_target(prov_elt(to));

 if (provenance_is_opaque(prov_elt(from))
     || provenance_is_opaque(prov_elt(to)))
  return 0;

 if (!provenance_is_tracked(prov_elt(from))
     && !provenance_is_tracked(prov_elt(to))
     && !prov_policy.prov_all)
  return 0;
 if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
  return 0;
 rc = record_kernel_link(prov_entry(from));
 if (rc < 0)
  return rc;
 rc = record_kernel_link(prov_entry(to));
 if (rc < 0)
  return rc;
 return record_relation(type, prov_entry(from), prov_entry(to), file, flags);
}

static int record_influences_kernel(const int type,
          struct provenance *entity,
          struct provenance *activity,
          const struct file *file)
{
 int rc;

 BUILD_BUG_ON(!prov_is_influenced(type));

 apply_target(prov_elt(entity));
 apply_target(prov_elt(activity));

 if (provenance_is_opaque(prov_elt(entity))
     || provenance_is_opaque(prov_elt(activity)))
  return 0;
 if (!provenance_is_tracked(prov_elt(entity))
     && !provenance_is_tracked(prov_elt(activity))
   && !prov_policy.prov_all)
  return 0;
 rc = record_relation(RL_LOAD_FILE, prov_entry(entity), prov_entry(activity), file, 0);
 if (rc < 0)
  goto out;
 rc = record_relation(type, prov_entry(activity), prov_machine, NULL, 0);
out:
 return rc;
}

static void record_machine(void)
{
 pr_info("Provenance: recording machine node...");
 __write_node(prov_machine);
}
