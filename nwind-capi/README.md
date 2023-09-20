# nwind C API - shadow stack

A simple C API wrapper around the unwind crate written in rust.

Example usage:

```
int use_shadow_stack = 1;

/* the address space can be reused across threads */
nwind_address_space* address_space = nwind_create_address_space(use_shadow_stack);

/* you need to reload the address space whenever it changes, e.g. after `dlopen` or `mmap` */
nwind_reload_address_space(address_space);

/* the unwind context should be thread local */
nwind_unwind_context* unwind_context = nwind_create_unwind_context();

/* unwind into an existing buffer, note that this can be done multiple times, reusing a
   central address space and a thread specific unwind context */
int buffer_size = 64;
void **buffer[buffer_size] = {0};
int stack_size = nwind_backtrace(address_space, unwind_context, buffer, buffer_size);

/* cleanup resources */
nwind_free_unwind_context(unwind_context);
nwind_free_address_space(unwind_context);
```
