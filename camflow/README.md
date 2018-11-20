## Parse `hooks.c` file

Our goal is to generate an AST for each hook function defined in `hooks.c` file.
We must preprocess the source file before providing the code to `pycparser`:
```
gcc -D'gfp_t=int' -D'umode_t=int' -D'__user=int' -D'vm_flags_t=int' -D'pid_t=int' -D'size_t=int' -D'bool=int' -D'uint32_t=int' -D'uint8_t=int' -D'uint16_t=int' -E ../camflow/hooks.c > ../camflow/hooks_pp.c
``` 
We define away some types not recognized by `pycparser`.
Those fake definitions are okay since they are not relevant to our analysis.
`hooks_pp.c` is then ready to be parsed by `pycparser`.

This process is automated in `Makefile` in `scripts`.


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
