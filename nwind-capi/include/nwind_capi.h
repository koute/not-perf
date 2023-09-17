/* SPDX-License-Identifier: MIT */

#ifndef NWIND_CAPI_H_
#define NWIND_CAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle for a local address space */
typedef struct nwind_local_address_space_ nwind_local_address_space;

/* Opaque handle for a local unwind context */
typedef struct nwind_local_unwind_context_ nwind_local_unwind_context;

/**
 * Create a local address space to use for unwinding.
 *
 * This type can be reused across threads, as long as the address space stays
 * the same. When dlopen is called or the address space is otherwise mutated,
 * @c nwind_reload_local_address_space needs to be called before using the
 * address space for unwinding again.
 *
 * @sa nwind_free_local_address_space, nwind_reload_local_address_space
 * @sa nwind_create_local_unwind_context, nwind_local_backtrace
 * @sa nwind_local_address_space_is_shadow_stack_enabled
 * @sa nwind_local_address_space_use_shadow_stack
 */
nwind_local_address_space *nwind_create_local_address_space();

/**
 * Free the memory associated with the address space.
 *
 * @sa nwind_create_local_address_space
 */
void nwind_free_local_address_space(nwind_local_address_space *address_space);

/**
 * @return 1 when the shadow stack should be used for unwinding and 0 otherwise
 * @sa nwind_create_local_address_space
 */
int nwind_local_address_space_is_shadow_stack_enabled(
    nwind_local_address_space *address_space);

/**
 * @param use_shadow_stack set to 1 when the shadow stack should be used for
 * unwinding and 0 otherwise
 * @sa nwind_create_local_address_space
 */
void nwind_local_address_space_use_shadow_stack(
    nwind_local_address_space *address_space, int use_shadow_stack);

/**
 * Reload the local address space to re-read the mapping.
 *
 * When dlopen is called or the address space is otherwise mutated, the address
 * space needs to be reloaded.
 *
 * @sa nwind_create_local_address_space
 */
nwind_local_address_space *
nwind_reload_local_address_space(nwind_local_address_space *address_space);

/**
 * Create a unwind context to use for unwinding.
 *
 * This type can be cached within a single thread and reused across repeated
 * calls to @c nwind_local_backtrace.
 *
 * @sa nwind_free_local_unwind_context, nwind_create_local_address_space
 * @sa nwind_local_backtrace
 */
nwind_local_unwind_context *nwind_create_local_unwind_context(void);

/**
 * Free the memory associated with the unwind context.
 *
 * @sa nwind_create_local_unwind_context
 */
void nwind_free_local_unwind_context(
    nwind_local_unwind_context *unwind_local_context);

/**
 * Unwind the stack and return up to @p size frames in the backtrace @p buffer.
 *
 * @param address_space the local address space to use
 * @param unwind_local_context the unwind context to use
 * @param buffer the output buffer in which the backtrace will be stored
 * @param size the maximum number of frames that will be stored into the buffer
 * @return the number of frames written to the output @p buffer.
 *
 * @sa nwind_create_local_address_space, nwind_create_local_unwind_context
 * @sa nwind_reload_local_address_space
 */
size_t nwind_local_backtrace(nwind_local_address_space *address_space,
                             nwind_local_unwind_context *unwind_local_context,
                             void **buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif // NWIND_CAPI_H_
