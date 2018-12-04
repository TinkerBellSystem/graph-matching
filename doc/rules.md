### Rules
The followings are hook-level rules.

1. `var = alloc_provenance(TYPE, ...);` in `assignment`:
	- `var` is a new `MotifNode` of type `TYPE`.
	- `var` usually corresponds to a new provenance node at runtime. 
- `var = get_task_provenance();` in `assignment`:
	- `var` is a new `MotifNode` of type `task`.
	- `var` usually corresponds to an existing task-typed provenance node at runtime.
- `var = get_cred_provenance();` in `assignment`:
	- `get_cred_provenance()` function itself creates motif edges and therefore motif tree nodes.
	- `var` must be a new `MotifNode` of type `process_memory`.
	- `var` usually corresponds to an existing provenance node at runtime.
- `var = task_cred_xxx();` generates a new `MotifNode` of type `process_memory`. 
- `var = branch_mmap();` generates a new `MotifNode` of type `mmaped_file`.
- `var = sk_provenance();` generates a new `MotifNode` of type `process_memory`. (`sk_provenance()` call itself does not generate any provenance edges.)
- Provenance declaration signifies a `MotifNode` as well:
	- For example: `struct provenance *var;`
	- Type must be of `provenance`.
	- Each variable `var` represents a new `MotifNode`.
	- These `MotifNode`s usually correspond to provenance nodes that already exist at runtime.
	- We can use variable names `var` to identify their types.
- Provenance assignment can also signifies a `MotifNode`:
	- For example: `struct provenance *var=task->provenance;`
	- Each variable `var` represents a new `MotifNode`.
	- These `MotifNode`s usually correspond to provenance nodes that already exist at runtime.
	- We can use variable names `var` to identify their types.
- All provenance declarations and assignments must exist before they are used in edge-generating subroutines within each hook, so that we can match them accordingly.
- Edge-generating functions that can be either in an `assignment` or a `declaration` or even in `return`:
	- `uses_two`
	- `informs`
	- `record_terminate`
	- `generates`
	- `uses`
	- `refresh_inode_provenance`
	- `inode_provenance` (sometimes used in `assignment` to create a new `MotifNode` of type `inode` as well.)
	- `dentry_provenance` (sometimes used in `assignment` to create a new `MotifNode` of type `inode` as well.)
	- `file_provenance` (sometimes used in `assignment` to create a new `MotifNode` of type `inode` as well.)
	- `record_inode_name_from_dentry`
	- `record_node_name`
	- `derives`
	- `record_write_xattr`
	- `record_read_xattr`
	- `influences_kernel`
	- `socket_inode_provenance` (sometimes used in `assignment` to create a new `MotifNode` of type `inode` as well.)
	- `provenance_record_address`
	- `sk_inode_provenance` (sometimes used in `assignment` to create a new `MotifNode` of type `inode` as well.)
	- `prov_record_args()`
- `if` conditions:
	- We do not check `null pointer` condition in `if` statements.
- Same variable name `var` may be reassigned, so they should refer to the same object:
	- For example, in `provenance_inode_permission()` hook, we have first: `struct provenance *iprov = NULL;`, and then `iprov = inode_provenance(inode, false);`
	- Also in `provenance_inode_link()` hook
	- Also in `provenance_inode_setattr()` hook
	- Also in `provenance_msg_msg_alloc_security()` hook
	- Also in `provenance_socket_sendmsg()` hook
- `provenance_inode_permission()` hook function's `if` statement needs to be checked for various cases.
- `provenance_inode_rename()` hook has the same model as `provenance_inode_link()` hook.
- `provenance_msg_queue_msgsnd()` and `provenance_mq_timedsend()` hooks have the same model as `__mq_msgsnd()`.
- `provenance_msg_queue_msgrcv()` and `provenance_mq_timedreceive()` hooks have the same model as `__mq_msgrcv()`.
- `provenance_socket_sendmsg_always()` hook has the same model as `provenance_socket_sendmsg()` hook.
- `provenance_socket_recvmsg_always()` hook has the same model as `provenance_socket_recvmsg()` hook.
- We can already know based on CamFlow setting some value of functions, such as `provenance_is_opaque()`, `provenance_records_packet()`. If they are used as conditions in `if` statements, we know that the branch should not be taken.
- In some hook functions, a provenance node may be passed in from hook's parameter list. Always parse parameters in the list with `struct provenance*` type.

### Issues:
1. 	`refresh_inode_provenance(struct inode*)` takes `struct inode*` as argument, it will be easier to take `struct provenance *` instead.
2. `inode_provenance(struct inode*, ...)` returns a `struct provenance *` object in hook functions. But the same object was first created in `inode_provenance(struct inode*, ...)` code. We need to make sure the two objects, which refer to the same object, can be correlated easily. The same is for `dentry_provenance(struct dentry *)`, `file_provenance(struct file*)`, `socket_inode_provenance(struct socket*)`, `sk_inode_provenance(struct sock*)`.
3. How do we differentiate places where we want the `or` operator because the `if` statement is checking some valid conditions and places where we ignore the `if` statement because it is simply error checking?
4. If a hook function fails a check and create no provenance subgraph, it is OK. What if it fails halfway through and creates a partial provenance subgraph? Then we actually do need to check failure checking code (such as those `if` statements.) Example hook: `provenance_file_permission()`
5. Complicated cases:
	- `provenance_socket_recvmsg()`: in `if` statement `pprov==cprov` needs to be checked.