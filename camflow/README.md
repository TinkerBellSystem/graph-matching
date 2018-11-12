## Parse `hooks.c` file

Our goal is to generate an AST for each hook function defined in `hooks.c` file.

To parse `camflow-dev/security/provenance/hooks.c` file, we need to first pre-process this file:

* We remove all the dependencies we define: `#include "provenance.h"`, `#include "provenance_record.h"`, `#include "provenance_net.h"`, `#include "provenance_inode.h"`, `#include "provenance_task.h"`. They are not relevant to our analysis but complicate AST parsing.
* We remove all `#ifdef`s related to hook functions to include all code in the analysis.
* We comment out `struct file *file = container_of(fown, struct file, f_owner);` in `provenance_file_send_sigiotask`. It does not change the resuts of our analysis but causes `pycparser` to fail.
* We comment out `call_provenance_alloc((prov_entry_t*)&pckprov);` and `call_provenance_free((prov_entry_t*)&pckprov);` in `provenance_socket_sock_rcv_skb` function. They do not change the results of our analysis but cause `pycparser` to fail.
* We can safely remove `static struct security_hook_list provenance_hooks[] __lsm_ro_after_init` structure definition, and any definitions afterwards, and the `void __init provenance_add_hooks(void)` function, because they are out of our concern, and some causes `pycparser` to fail.
* We add empty function body `{}` to functions `provenance_socket_sendmsg_always` and `provenance_socket_recvmsg_always`.

Additionally, we include `utils` from `pycparser` to replace real system headers in `hooks.c` with fake system header files because they are not relevant to our analysis and C parser does not need to know semantics. We include some more fake system files in `utils` to meet our needs.

We must then preprocess the source file before providing the code to `pycparser`:
```
gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -E -Iutils/fake_libc_include hooks.c > hooks_pp.c
``` 
We define away some types not recognized by `pycparser`.
Those fake definitions are okay since they are not relevant to our analysis.

`hooks_pp.c` is then ready to be parsed by `pycparser`.

## Parse 'provenance_record.h' file

To parse `camflow-dev/security/provenance/include/provenance_record.h` file, we need to first pre-process this file:
* We remove all the dependencies we define: `#include "provenance.h"`, `#include "provenance_relay.h"`.

We must then preprocess the file before providing the code to `pycparser`:
```
gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -E -Iutils/fake_libc_include provenance_record.h > provenance_record_pp.h
``` 
We define away some types not recognized by `pycparser`.
Those fake definitions are okay since they are not relevant to our analysis.

`provenance_record_pp.h` is then ready to be parsed by `pycparser`.

## Parse 'provenance_task.h' file
To parse `camflow-dev/security/provenance/include/provenance_task.h` file, we need to first pre-process this file:
* We remove all the dependencies.
* We remove the definition of `copy_argv_bprm` function.

We must then preprocess the file before providing the code to `pycparser`:
```
gcc -D'__always_inline=' -D'uint64_t=int' -D'prov_entry_t=int' -D'bool=int' -D'uint32_t=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -E -Iutils/fake_libc_include provenance_task.h > provenance_task_pp.h
```
We define away some types not recognized by `pycparser`.
Those fake definitions are okay since they are not relevant to our analysis.

`provenance_task_pp.h` is then ready to be parsed by `pycparser`.
