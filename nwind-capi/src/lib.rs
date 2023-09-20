#[cfg(feature = "env_logger")]
extern crate env_logger;

use nwind::{LocalAddressSpace, LocalAddressSpaceOptions, LocalUnwindContext, UnwindControl};

use core::ffi::{c_int, c_void};

#[no_mangle]
pub unsafe extern "C" fn nwind_create_local_address_space() -> *mut LocalAddressSpace {
    #[cfg(feature = "env_logger")]
    let _ = env_logger::try_init();
    let opts = LocalAddressSpaceOptions::new().should_load_symbols(false);
    let address_space = LocalAddressSpace::new_with_opts(opts).unwrap();

    Box::into_raw(Box::new(address_space))
}

#[no_mangle]
pub unsafe extern "C" fn nwind_free_local_address_space(address_space: *mut LocalAddressSpace) {
    drop(Box::from_raw(address_space))
}

#[no_mangle]
pub unsafe extern "C" fn nwind_local_address_space_is_shadow_stack_enabled(
    address_space: *mut LocalAddressSpace,
) -> c_int {
    (*address_space).is_shadow_stack_enabled() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn nwind_local_address_space_use_shadow_stack(
    address_space: *mut LocalAddressSpace,
    use_shadow_stack: c_int,
) {
    (*address_space).use_shadow_stack(use_shadow_stack == 1);
}

#[no_mangle]
pub unsafe extern "C" fn nwind_reload_local_address_space(address_space: *mut LocalAddressSpace) {
    (*address_space).reload().unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn nwind_create_local_unwind_context() -> *mut LocalUnwindContext {
    Box::into_raw(Box::new(LocalUnwindContext::new()))
}

#[no_mangle]
pub unsafe extern "C" fn nwind_free_local_unwind_context(
    local_unwind_context: *mut LocalUnwindContext,
) {
    drop(Box::from_raw(local_unwind_context))
}

#[no_mangle]
pub unsafe extern "C" fn nwind_local_backtrace(
    address_space: *mut LocalAddressSpace,
    unwind_context: *mut LocalUnwindContext,
    buffer: *mut *mut c_void,
    size: c_int,
) -> c_int {
    if size <= 0 {
        return 0;
    }

    let size = size as usize;

    let buffer = core::slice::from_raw_parts_mut(buffer, size);

    let mut first = true;
    let mut ret: usize = 0;
    (*address_space).unwind(unwind_context.as_mut().unwrap(), |address| {
        if first {
            // skip the first frame as that would point at nwind_backtrace
            first = false;
            return UnwindControl::Continue;
        }

        buffer[ret] = address as *mut c_void;
        ret += 1;

        if ret == size {
            UnwindControl::Stop
        } else {
            UnwindControl::Continue
        }
    });

    ret as c_int
}
