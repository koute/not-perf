use std::io;
use std::fs;
use std::ptr;
use std::marker::PhantomData;
use std::mem;
use std::slice;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::sync::Arc;

use libc;
use proc_maps;

use crate::address_space::{BinaryHandle, BinaryRegion, MemoryReader, Frame, reload};
use crate::binary::BinaryData;
use crate::range_map::RangeMap;
use crate::arch::{self, LocalRegs, Architecture};
use crate::unwind_context::{InitializeRegs, UnwindContext};
use crate::types::BinaryId;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum UnwindControl {
    Continue,
    Stop
}

struct LocalMemory< 'a > {
    regions: &'a RangeMap< BinaryRegion< arch::native::Arch > >
}

impl< 'a > MemoryReader< arch::native::Arch > for LocalMemory< 'a > {
    fn get_region_at_address( &self, address: u64 ) -> Option< &BinaryRegion< arch::native::Arch > > {
        self.regions.get_value( address )
    }

    #[inline(always)]
    fn get_pointer_at_address( &self, address: <arch::native::Arch as Architecture>::RegTy ) -> Option< <arch::native::Arch as Architecture>::RegTy > {
        let value = unsafe { *(address as usize as *const usize) };
        Some( value as _ )
    }

    fn is_stack_address( &self, _: u64 ) -> bool {
        false
    }
}

extern "C" {
    pub fn nwind_ret_trampoline();
}

#[cold]
#[inline(never)]
fn on_failed_to_fetch_shadow_stack_tls() -> ! {
    error!( "Failed to fetch shadow stack TLS!" );
    unsafe {
        libc::abort();
    }
}

#[cold]
#[inline(never)]
fn on_shadow_stack_underflow() -> ! {
    error!( "Shadow stack underflow!" );
    unsafe {
        libc::abort();
    }
}

#[cold]
#[inline(never)]
fn on_shadow_stack_no_entry_found( stack_pointer: usize, expected_index: usize, tls: &mut ShadowStackTls ) -> ! {
    error!( "Failed to find a matching trampoline entry for stack pointer = 0x{:016X}", stack_pointer );
    for index in 0..=expected_index {
        let entry = tls.slice()[ index ];
        error!( "Shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );
    }

    unsafe {
        libc::abort();
    }
}

#[cold]
#[inline(never)]
unsafe fn unwind_shadow_stack( tls: &mut ShadowStackTls, stack_pointer: usize, expected_index: usize ) -> Option< usize > {
    loop {
        if tls.tail == 0 {
            return None;
        }

        tls.entries_popped_since_last_unwind += 1;
        tls.tail -= 1;

        let index = tls.tail;
        if tls.slice().get_unchecked( index ).stack_pointer == stack_pointer {
            warn!( "Found matching trampoline entry for stack pointer = 0x{:016X} at index #{} instead of at #{}; was `longjmp` used here?", stack_pointer, index, expected_index );
            return Some( index );
        }
    }
}

#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn nwind_on_ret_trampoline( stack_pointer: usize ) -> usize {
    debug!( "Unwinding of trampoline triggered at 0x{:016X} on the stack", stack_pointer );

    let stack = if let Some( stack ) = ShadowStack::get() {
        stack
    } else {
        on_failed_to_fetch_shadow_stack_tls();
    };

    let tls = &mut *stack.tls;
    tls.entries_popped_since_last_unwind += 1;

    if tls.tail == 0 {
        on_shadow_stack_underflow();
    }

    tls.tail -= 1;
    let expected_index = tls.tail;
    let index =
        if tls.slice().get_unchecked( expected_index ).stack_pointer == stack_pointer {
            Some( expected_index )
        } else {
            unwind_shadow_stack( tls, stack_pointer, expected_index )
        };

    if let Some( index ) = index {
        let entry = tls.slice().get_unchecked( index );
        debug!( "Found trampoline entry at index #{}", index );
        debug!( "Clearing shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );

        return entry.return_address;
    } else {
        on_shadow_stack_no_entry_found( stack_pointer, expected_index, tls );
    }
}

#[allow(non_camel_case_types)]
mod unwind {
    pub type _Unwind_Reason_Code = u32;
    pub type _Unwind_Action = u32;
    pub type _Unwind_Exception_Class = u64;
    pub enum _Unwind_Exception {}
    pub enum _Unwind_Context {}

    extern {
        pub fn _Unwind_SetIP( ctx: *const _Unwind_Context, ip: usize );
        pub fn _Unwind_GetIP( ctx: *const _Unwind_Context ) -> usize;
        pub fn _Unwind_Resume( exception: *const _Unwind_Exception );
        pub fn _Unwind_SetGR( ctx: *const _Unwind_Context, reg: u32, value: usize );
        pub fn _Unwind_GetGR( ctx: *const _Unwind_Context, reg: u32 ) -> usize;
    }

    pub const _URC_HANDLER_FOUND: _Unwind_Reason_Code = 6;
    pub const _URC_INSTALL_CONTEXT: _Unwind_Reason_Code = 7;
    pub const _URC_CONTINUE_UNWIND: _Unwind_Reason_Code = 8;

    pub const _UA_SEARCH_PHASE: _Unwind_Action = 1;
}

use self::unwind::*;

#[link(name = "stdc++")]
extern {
    fn __gxx_personality_v0(
        _version: _Unwind_Reason_Code,
        _action: _Unwind_Action,
        _exception_class: _Unwind_Exception_Class,
        _exception: *const _Unwind_Exception,
        ctx: *const _Unwind_Context
    ) -> _Unwind_Reason_Code;
}

#[cfg(rust_nightly)]
#[doc(hidden)]
#[allow(non_snake_case)]
#[unwind(allowed)]
#[no_mangle]
pub unsafe fn _Unwind_RaiseException( ctx: *mut libc::c_void ) -> libc::c_int {
    debug!( "Exception raised!" );

    let mut stack = ShadowStack::get().unwrap();
    stack.reset();

    union Union {
        raw_ptr: *const libc::c_void,
        function: unsafe extern fn( *mut libc::c_void ) -> libc::c_int
    }

    let ptr = libc::dlsym( libc::RTLD_NEXT, b"_Unwind_RaiseException\0".as_ptr() as *const libc::c_char );
    (Union { raw_ptr: ptr }.function)( ctx )
}

#[cfg(rust_nightly)]
#[doc(hidden)]
#[unwind(allowed)]
#[no_mangle]
pub unsafe fn __cxa_throw( obj: *mut libc::c_void, tinfo: *mut libc::c_void, cb: extern "C" fn( *mut libc::c_void ) ) {
    debug!( "__cxa_throw called" );

    union Union {
        raw_ptr: *const libc::c_void,
        function: unsafe extern fn( *mut libc::c_void, *mut libc::c_void, extern "C" fn( *mut libc::c_void ) )
    }

    let ptr = libc::dlsym( libc::RTLD_NEXT, b"__cxa_throw\0".as_ptr() as *const libc::c_char );
    (Union { raw_ptr: ptr }.function)( obj, tinfo, cb )
}

#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn nwind_ret_trampoline_personality(
    version: _Unwind_Reason_Code,
    action: _Unwind_Action,
    exception_class: _Unwind_Exception_Class,
    exception: *const _Unwind_Exception,
    ctx: *const _Unwind_Context
) -> _Unwind_Reason_Code {
    warn!( "Personality called!" );

    let mut stack = ShadowStack::get().unwrap();
    stack.reset();

    // TODO: This will most likely crash and burn since the instruction pointer
    // in the unwind context still points to the trampoline.
    //
    // It'd be nice to figure out how to make this work, however since we hook
    // into the `_Unwind_RaiseException` it's unlikely that we'll end up here.
    __gxx_personality_v0( version, action, exception_class, exception, ctx )
}

struct ShadowStackIter< 'a > {
    slice: &'a [ShadowEntry],
    index: usize
}

impl< 'a > Iterator for ShadowStackIter< 'a > {
    type Item = usize;

    #[inline]
    fn next( &mut self ) -> Option< Self::Item > {
        if self.index == 0 {
            return None;
        }

        self.index -= 1;
        let entry = self.slice[ self.index ];
        debug!( "Read cached address from shadow stack at index #{}: 0x{:016X}", self.index, entry.return_address );

        Some( entry.return_address )
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ShadowEntry {
    return_address: usize,
    location: usize,
    stack_pointer: usize
}

#[repr(C)]
struct ShadowStackTls {
    length: usize,
    tail: usize,
    entries_popped_since_last_unwind: usize,
    last_unwind_address: usize,
    is_enabled: usize
}

impl ShadowStackTls {
    #[inline]
    fn slice( &mut self ) -> &mut [ShadowEntry] {
        let length = self.length;
        debug_assert_ne!( length, 0 );
        unsafe {
            let ptr = (self as *mut ShadowStackTls).add( 1 ) as *mut ShadowEntry;
            slice::from_raw_parts_mut( ptr, length )
        }
    }

    #[cold]
    unsafe fn alloc( length: usize ) -> *mut ShadowStackTls {
        use std::alloc::{Layout, alloc};

        let total_size = mem::size_of::< ShadowStackTls >() + length * mem::size_of::< ShadowEntry >();
        let layout = Layout::from_size_align_unchecked( total_size, 8 );

        let tls = alloc( layout ) as *mut ShadowStackTls;
        *tls = ShadowStackTls {
            length,
            tail: 0,
            entries_popped_since_last_unwind: 0,
            last_unwind_address: 0,
            is_enabled: 0
        };

        tls
    }

    #[cold]
    unsafe fn dealloc( tls: *mut ShadowStackTls ) {
        use std::alloc::{Layout, dealloc};
        if tls == ptr::null_mut() {
            return;
        }

        let length = (*tls).length;
        let total_size = mem::size_of::< ShadowStackTls >() + length * mem::size_of::< ShadowEntry >();
        let layout = Layout::from_size_align_unchecked( total_size, 8 );
        dealloc( tls as *mut u8, layout );
    }

    #[cold]
    unsafe fn grow( tls_p: &mut *mut ShadowStackTls ) -> usize {
        let tls = *tls_p;

        let length = (*tls).length;
        let new_length = length * 2;
        let extra_space = new_length - length;
        info!( "Growing the shadow stack from {} elements to {} elements", length, new_length );

        let new_tls = Self::alloc( new_length );
        debug_assert_eq!( (*new_tls).slice().len(), new_length );

        *new_tls = ShadowStackTls {
            length: new_length,
            ..(*tls)
        };

        {
            let tls = &mut *tls;
            let new_tls = &mut *new_tls;
            let tail = tls.tail;
            let src = tls.slice();
            let dst = new_tls.slice();

            dst[ ..tail ].copy_from_slice( &src[ ..tail ] );
            dst[ tail + extra_space.. ].copy_from_slice( &src[ tail.. ] );
        }

        ShadowStackTls::dealloc( tls );
        *tls_p = new_tls;

        extra_space
    }
}

struct ShadowStackTlsPtr {
    tls: UnsafeCell< *mut ShadowStackTls >
}

impl ShadowStackTlsPtr {
    #[inline]
    fn get( &self ) -> *mut ShadowStackTls {
        unsafe {
            *self.tls.get()
        }
    }

    #[inline]
    unsafe fn set( &self, ptr: *mut ShadowStackTls ) {
        *self.tls.get() = ptr;
    }
}

fn reset_tls( tls: *mut ShadowStackTls ) {
    debug!( "Clearing shadow stack..." );
    let tls = unsafe { &mut *tls };
    while tls.tail > 0 {
        tls.tail -= 1;
        let index = tls.tail;
        let entry = tls.slice()[ index ];

        debug!( "Clearing shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );
        unsafe {
            if cfg!( debug_assertions ) {
                if !ShadowStack::is_trampoline_set( entry.location ) {
                    warn!( "Slot 0x{:016X} contains 0x{:016X} instead of the trampoline address", entry.location, *(entry.location as *mut usize) );
                }
            }
            *(entry.location as *mut usize) = entry.return_address;
        }
    }

    tls.is_enabled = 0;
    tls.entries_popped_since_last_unwind = 0;
    tls.last_unwind_address = 0;
}

impl Drop for ShadowStackTlsPtr {
    fn drop( &mut self ) {
        let tls = self.get();
        unsafe {
            reset_tls( tls );
            ShadowStackTls::dealloc( tls );
        }
    }
}

#[cfg(not(test))]
const SHADOW_STACK_DEFAULT_LENGTH: usize = 256;

#[cfg(test)]
const SHADOW_STACK_DEFAULT_LENGTH: usize = 1;

thread_local! {
    static SHADOW_STACK_TLS_PTR: ShadowStackTlsPtr = {
        unsafe {
            let tls = ShadowStackTls::alloc( SHADOW_STACK_DEFAULT_LENGTH );
            ShadowStackTlsPtr {
                tls: UnsafeCell::new( tls )
            }
        }
    };
}

struct ShadowStack {
    tls: *mut ShadowStackTls,
    index: usize
}

impl Drop for ShadowStack {
    #[inline]
    fn drop( &mut self ) {
        unsafe {
            let tls = &mut *self.tls;

            let src = self.index;
            let dst = tls.tail;
            let len = tls.slice().len() - self.index;

            if len == 0 {
                return;
            }

            debug!( "Copying shadow stack from #{}..#{} into #{}..#{} (length={})", src, src + len, dst, dst + len, len );
            if cfg!( debug_assertions ) && dst + len > src {
                error!( "Assertion failed: #{}..#{} overlaps with #{}..#{}", src, src + len, dst, dst + len );
                libc::abort();
            }

            ptr::copy_nonoverlapping(
                tls.slice().as_ptr().offset( src as isize ),
                tls.slice().as_mut_ptr().offset( dst as isize ),
                len
            );

            let original_tail = tls.tail;
            tls.tail += len;

            let mut index = 0;
            while index < tls.tail {
                let entry = tls.slice()[ index ];
                let kind = if index < original_tail { "old" } else { "new" };
                debug!( "Shadow stack ({}) #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", kind, index, entry.return_address, entry.location, entry.stack_pointer );
                index += 1;
            }
        }
    }
}

impl ShadowStack {
    #[inline]
    fn get() -> Option< Self > {
        let mut tls = ptr::null_mut();
        SHADOW_STACK_TLS_PTR.try_with( |tls_ptr| {
            tls = tls_ptr.get();
        }).ok()?;

        let stack = ShadowStack {
            tls: tls,
            index: unsafe { (*tls).slice().len() }
        };

        Some( stack )
    }

    #[inline]
    fn tls( &mut self ) -> &mut ShadowStackTls {
        unsafe { &mut *self.tls }
    }

    #[inline]
    fn is_trampoline_set( address_location: usize ) -> bool {
        let slot = unsafe { &mut *(address_location as *mut usize) };
        *slot == nwind_ret_trampoline as usize
    }

    #[inline]
    fn push( &mut self, stack_pointer: usize, address_location: usize ) -> Option< ShadowStackIter > {
        let slot = unsafe { &mut *(address_location as *mut usize) };
        if *slot == nwind_ret_trampoline as usize {
            debug!( "Found already set trampoline at slot 0x{:016X}", address_location );

            let tls = self.tls();
            let index = tls.tail - 1;
            let entry = &tls.slice()[ index ];
            if entry.location != address_location {
                debug!( "The address of the slot (0x{:016X}) doesn't match the slot address from the shadow stack (0x{:016X}) for shadow stack entry #{}", address_location, entry.location, index );
                debug!( "Shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );
            }

            if entry.stack_pointer != stack_pointer {
                error!( "The stack pointer (0x{:016X}) doesn't match the stack pointer from the shadow stack (0x{:016X}) for shadow stack entry #{}", stack_pointer, entry.stack_pointer, index );
                error!( "Shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );

                unsafe {
                    libc::abort();
                }
            }

            debug!( "Found shadow stack entry at #{} matching the trampoline", index );

            let tail = tls.tail;
            return Some( ShadowStackIter { slice: &tls.slice()[..], index: tail } );
        }

        let capacity = self.tls().slice().len();
        let tail = self.tls().tail;
        let available_space = self.index - tail;
        let space_required = capacity - self.index + 2;
        if available_space < space_required {
            warn!(
                "Shadow stack overflow: capacity = {}, used = {} + {}, available = {}, required = {}",
                capacity,
                tail,
                capacity - self.index,
                available_space,
                space_required
            );

            let extra_space = unsafe {
                ShadowStackTls::grow( &mut self.tls )
            };

            SHADOW_STACK_TLS_PTR.with( |tls_ptr| {
                unsafe {
                    tls_ptr.set( self.tls );
                }
            });

            self.index += extra_space;
        }

        self.index -= 1;

        debug!( "Saving to shadow stack: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", *slot, address_location, stack_pointer );
        let index = self.index;
        self.tls().slice()[ index ] = ShadowEntry {
            return_address: *slot,
            location: address_location,
            stack_pointer
        };

        if cfg!( debug_assertions ) {
            let src = self.index;
            let dst = self.tls().tail;
            let len = self.tls().slice().len() - self.index;

            if dst + len > src {
                error!( "Assertion failed: #{}..#{} will overlap with #{}..#{}", src, src + len, dst, dst + len );
                unsafe {
                    libc::abort();
                }
            }
        }

        *slot = nwind_ret_trampoline as usize;
        None
    }

    fn reset( &mut self ) {
        reset_tls( self.tls );
    }
}

fn unwind_cached< F: FnMut( usize ) -> UnwindControl >( iter: ShadowStackIter, mut callback: F ) {
    for address in iter {
        match callback( address ).into() {
            UnwindControl::Continue => {},
            UnwindControl::Stop => break
        }
    }
}

pub struct LocalUnwindContext {
    inner: UnwindContext< arch::native::Arch >,
    reload_count: usize
}

impl LocalUnwindContext {
    pub fn new() -> Self {
        LocalUnwindContext {
            inner: UnwindContext::new(),
            reload_count: 0
        }
    }
}

pub struct LocalAddressSpace {
    regions: RangeMap< BinaryRegion< arch::native::Arch > >,
    binary_map: HashMap< BinaryId, BinaryHandle< arch::native::Arch > >,
    use_shadow_stack: bool,
    should_load_symbols: bool,
    reload_count: usize
}

struct LocalRegsInitializer< A: Architecture >( PhantomData< A > );

impl< A: Architecture > Default for LocalRegsInitializer< A > {
    #[inline]
    fn default() -> Self {
        LocalRegsInitializer( PhantomData )
    }
}

impl< A: Architecture > InitializeRegs< A > for LocalRegsInitializer< A > where A::Regs: LocalRegs {
    #[inline(always)]
    fn initialize_regs( self, regs: &mut A::Regs ) {
        regs.get_local_regs();
    }
}

#[cfg(not(target_arch = "mips64"))]
unsafe fn patch_trampoline_impl() {}

#[cfg(target_arch = "mips64")]
unsafe fn patch_trampoline_impl() {
    use std::slice;

    extern {
        fn nwind_ret_trampoline_start();
    }

    static MIPS64_TRAMPOLINE_PATCH_PATTERN: [u32; 6] = [
       0x3c191234, //        lui     t9,0x1234
       0x37395678, //        ori     t9,t9,0x5678
       0x0019cc38, //        dsll    t9,t9,0x10
       0x3739abcd, //        ori     t9,t9,0xabcd
       0x0019cc38, //        dsll    t9,t9,0x10
       0x3739ef00, //        ori     t9,t9,0xef00
    ];

    let address = nwind_ret_trampoline_start as usize;
    assert_eq!( address % 4096, 0 );

    let offset = {
        let page = slice::from_raw_parts( address as *const u32, 4096 / mem::size_of::< u32 >() );
        match page.windows( MIPS64_TRAMPOLINE_PATCH_PATTERN.len() ).position( |window| window == MIPS64_TRAMPOLINE_PATCH_PATTERN ) {
            Some( offset ) => {
                let byte_offset = offset * mem::size_of::< u32 >();
                debug!( "Found snippet for patching at 0x{:016X} (0x{:016X} + {})", address + byte_offset, address, byte_offset );
                offset
            },
            None => {
                panic!( "Cannot find trampoline snippet to patch" );
            }
        }
    };

    let t = nwind_on_ret_trampoline as usize;
    let code: [u32; 6] = [
        0x3c190000 | ((t >> 48) & 0xFFFF) as u32,
        0x37390000 | ((t >> 32) & 0xFFFF) as u32,
        0x0019cc38,
        0x37390000 | ((t >> 16) & 0xFFFF) as u32,
        0x0019cc38,
        0x37390000 | ((t >>  0) & 0xFFFF) as u32
    ];

    debug!( "Unprotecting 0x{:016X}...", address );
    if libc::mprotect( address as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC ) < 0 {
        panic!( "Failed to unprotect the trampoline!" );
    }

    debug!( "Patching trampoline..." );
    {
        let page = slice::from_raw_parts_mut( address as *mut u32, 4096 / mem::size_of::< u32 >() );
        page[ offset..offset + code.len() ].copy_from_slice( &code[..] );
    }

    debug!( "Protecting 0x{:016X}...", address );
    if libc::mprotect( address as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_EXEC ) < 0 {
        panic!( "Failed to protect the trampoline!" );
    }

    debug!( "Trampoline successfully patched!" );
}

fn patch_trampoline() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once( || {
        debug!( "Trampoline address: 0x{:016X}", nwind_ret_trampoline as usize );
        unsafe {
            patch_trampoline_impl();
        }
    });
}

#[derive(Debug)]
pub struct LocalAddressSpaceOptions {
    should_load_symbols: bool
}

impl LocalAddressSpaceOptions {
    pub fn new() -> Self {
        LocalAddressSpaceOptions {
            should_load_symbols: true
        }
    }

    pub fn should_load_symbols( mut self, value: bool ) -> Self {
        self.should_load_symbols = value;
        self
    }
}

pub struct AddressSpaceUpdate {
    pub maps: String,
    pub new_binaries: Vec< Arc< BinaryData > >
}

impl LocalAddressSpace {
    pub fn new() -> Result< Self, io::Error > {
        Self::new_with_opts( LocalAddressSpaceOptions::new() )
    }

    pub fn new_with_opts( opts: LocalAddressSpaceOptions ) -> Result< Self, io::Error > {
        debug!( "Initializing local address space..." );

        patch_trampoline();

        let mut address_space = LocalAddressSpace {
            regions: RangeMap::new(),
            binary_map: HashMap::new(),
            use_shadow_stack: false,
            should_load_symbols: opts.should_load_symbols,
            reload_count: 0
        };

        if !cfg!( rust_nightly ) {
            warn!( "The profiler was not compiled with Rust nightly; shadow stack based unwinding will be disabled" );
        }

        address_space.use_shadow_stack( true );
        address_space.reload()?;

        Ok( address_space )
    }

    pub fn reload( &mut self ) -> Result< AddressSpaceUpdate, io::Error > {
        trace!( "Loading maps..." );
        let maps = fs::read( "/proc/self/maps" )?;
        let maps = String::from_utf8_lossy( &maps );
        trace!( "Parsing maps..." );
        let regions = proc_maps::parse( &maps );
        let should_load_symbols = self.should_load_symbols;

        self.reload_count += 1;
        let mut new_binaries = Vec::new();
        reload( &mut self.binary_map, &mut self.regions, regions, &mut |region, handle| {
            handle.should_load_debug_frame( false );
            handle.should_load_symbols( should_load_symbols );

            if region.name == "[vdso]" {
                return;
            }

            if let Ok( data ) = BinaryData::load_from_fs( &region.name ) {
                let data: Arc< BinaryData > = data.into();
                new_binaries.push( data.clone() );
                handle.set_binary( data );
            }
        });

        let update = AddressSpaceUpdate {
            maps: maps.into_owned(),
            new_binaries
        };

        Ok( update )
    }

    fn is_shadow_stack_supported() -> bool {
        cfg!( rust_nightly )
    }

    pub fn use_shadow_stack( &mut self, value: bool ) {
        if !Self::is_shadow_stack_supported() {
            return;
        }

        self.use_shadow_stack = value;
    }

    pub fn is_shadow_stack_enabled( &self ) -> bool {
        self.use_shadow_stack
    }

    fn clear_cache_if_necessary( &self, ctx: &mut LocalUnwindContext ) {
        if ctx.reload_count != self.reload_count {
            ctx.inner.clear_cache();
            ctx.reload_count = self.reload_count;
        }
    }

    #[inline(always)]
    pub fn unwind< F: FnMut( usize ) -> UnwindControl >( &self, ctx: &mut LocalUnwindContext, mut callback: F ) {
        self.clear_cache_if_necessary( ctx );

        let memory = LocalMemory {
            regions: &self.regions
        };

        let use_shadow_stack = self.is_shadow_stack_enabled();
        let mut ctx = ctx.inner.start( &memory, LocalRegsInitializer::default() );
        let mut shadow_stack = ShadowStack::get();

        if let Some( shadow_stack ) = shadow_stack.as_mut() {
            unsafe {
                (*shadow_stack.tls).entries_popped_since_last_unwind = 0;
                (*shadow_stack.tls).last_unwind_address = ctx.current_address() as usize;
                if ((*shadow_stack.tls).is_enabled == 1) != use_shadow_stack {
                    if !use_shadow_stack {
                        shadow_stack.reset();
                    } else {
                        (*shadow_stack.tls).is_enabled = 1;
                    }
                }
            }
        }

        if !use_shadow_stack {
            mem::forget( shadow_stack.take() );
        }

        loop {
            let mut shadow_stack_iter = None;
            if let Some( shadow_stack ) = shadow_stack.as_mut() {
                if let Some( next_address_location ) = ctx.next_address_location() {
                    let stack_pointer = ctx.next_stack_pointer();
                    shadow_stack_iter = shadow_stack.push( stack_pointer as usize, next_address_location as usize )
                }
            }

            let address = ctx.current_address() as usize;
            match callback( address ).into() {
                UnwindControl::Continue => {},
                UnwindControl::Stop => break
            }

            if let Some( iter ) = shadow_stack_iter {
                unwind_cached( iter, callback );
                return;
            }

            if ctx.unwind( &memory ) == false {
                return;
            }
        }
    }

    /// Unwinds only through frames which changed since the last unwind.
    ///
    /// This only works when the shadow stack is enabled; when it is
    /// disabled it will unwind through the whole stack trace.
    ///
    /// Returns the number of frames from the last unwind on this thread
    /// from which the code returned from, or `None` in case this is
    /// a completely fresh stack trace.
    #[inline(always)]
    pub fn unwind_through_fresh_frames< F: FnMut( usize ) -> UnwindControl >( &self, ctx: &mut LocalUnwindContext, mut callback: F ) -> Option< usize > {
        self.clear_cache_if_necessary( ctx );

        let memory = LocalMemory {
            regions: &self.regions
        };

        let use_shadow_stack = self.is_shadow_stack_enabled();
        let mut ctx = ctx.inner.start( &memory, LocalRegsInitializer::default() );
        let mut shadow_stack = ShadowStack::get();
        let mut entries_popped_since_last_unwind = 0;
        let mut last_unwind_address = 0;
        if let Some( shadow_stack ) = shadow_stack.as_mut() {
            unsafe {
                entries_popped_since_last_unwind = mem::replace( &mut (*shadow_stack.tls).entries_popped_since_last_unwind, 0 );
                last_unwind_address = mem::replace( &mut (*shadow_stack.tls).last_unwind_address, ctx.current_address() as usize );

                if ((*shadow_stack.tls).is_enabled == 1) != use_shadow_stack {
                    if !use_shadow_stack {
                        shadow_stack.reset();
                    } else {
                        (*shadow_stack.tls).is_enabled = 1;
                    }
                }
            }
        }

        if !use_shadow_stack {
            mem::forget( shadow_stack.take() );
        }

        if entries_popped_since_last_unwind == 0 && last_unwind_address == ctx.current_address() as usize {
            if let Some( next_address_location ) = ctx.next_address_location() {
                if ShadowStack::is_trampoline_set( next_address_location as usize ) {
                    // The stack trace is exactly the same.
                    return Some( 0 );
                }
            }
        }

        loop {
            let mut is_end_of_fresh_frames = false;
            if let Some( shadow_stack ) = shadow_stack.as_mut() {
                if let Some( next_address_location ) = ctx.next_address_location() {
                    let stack_pointer = ctx.next_stack_pointer();
                    is_end_of_fresh_frames = shadow_stack.push( stack_pointer as usize, next_address_location as usize ).is_some();
                }
            }

            let address = ctx.current_address() as usize;
            let stop = match callback( address ).into() {
                UnwindControl::Continue => false,
                UnwindControl::Stop => true
            };

            if is_end_of_fresh_frames {
                return Some( entries_popped_since_last_unwind + 1 );
            }

            if stop || ctx.unwind( &memory ) == false {
                return None;
            }
        }
    }

    pub fn decode_symbol_once( &self, address: usize ) -> Frame {
        let address = address as u64;
        if let Some( region ) = self.regions.get_value( address ) {
            region.binary().decode_symbol_once( address )
        } else {
            Frame::from_address( address, address )
        }
    }
}

// This is used to make sure that the compiler
// won't make the functions which we've marked
// as `#[inline(never)]` into tail recursive ones.
#[cfg(test)]
fn dummy_volatile_read() {
    let local = 0;
    unsafe {
        std::ptr::read_volatile( &local );
    }
}

#[test]
fn test_self_unwind() {
    let _ = ::env_logger::try_init();

    let address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();
    let mut frames = Vec::new();
    address_space.unwind( &mut ctx, |frame| {
        frames.push( frame.clone() );
        UnwindControl::Continue
    });
    assert!( frames.len() > 3 );

    let mut addresses = Vec::new();
    let mut symbols = Vec::new();
    for &address in frames.iter() {
        if let Some( symbol ) = address_space.decode_symbol_once( address ).name {
            symbols.push( symbol.to_owned() );
        }

        addresses.push( address );
    }

    assert!( symbols.iter().next().unwrap().contains( "test_self_unwind" ) );
    assert_ne!( addresses[ addresses.len() - 1 ], addresses[ addresses.len() - 2 ] );

    ShadowStack::get().unwrap().reset();
}

#[test]
fn test_unwind_twice() {
    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize > ) {
        address_space.unwind( ctx, |address| {
            output.push( address );
            UnwindControl::Continue
        });
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize > ) {
        func_1( address_space, ctx, output );
        dummy_volatile_read();
    }

    address_space.use_shadow_stack( false );

    let mut trace_1 = Vec::new();
    func_1( &mut address_space, &mut ctx, &mut trace_1 );

    let mut trace_2 = Vec::new();
    func_2( &mut address_space, &mut ctx, &mut trace_2 );

    assert_eq!( &trace_1[ 0 ], &trace_2[ 0 ] );
    assert_ne!( &trace_1[ 1 ], &trace_2[ 2 ] );
    assert_eq!( &trace_1[ 2.. ], &trace_2[ 3.. ] );

    address_space.use_shadow_stack( true );

    let mut trace_3 = Vec::new();
    func_1( &mut address_space, &mut ctx, &mut trace_3 );

    let mut trace_4 = Vec::new();
    func_2( &mut address_space, &mut ctx, &mut trace_4 );

    assert_eq!( &trace_3[ 0 ], &trace_1[ 0 ] );
    assert_ne!( &trace_3[ 1 ], &trace_1[ 1 ] );
    assert_eq!( &trace_3[ 2.. ], &trace_1[ 2.. ] );

    assert_eq!( &trace_4[ 0..2 ], &trace_2[ 0..2 ] );
    assert_ne!( &trace_4[ 2 ], &trace_2[ 2 ] );
    assert_eq!( &trace_4[ 3.. ], &trace_2[ 3.. ] );

    ShadowStack::get().unwrap().reset();
}

#[cfg(test)]
fn clear_tls() {
    // Make sure we clear the TLS data from any tests which might
    // have had been previously launched on this thread.

    SHADOW_STACK_TLS_PTR.with( |tls_ptr| {
        unsafe {
            let new_tls = ShadowStackTls::alloc( SHADOW_STACK_DEFAULT_LENGTH );

            ShadowStackTls::dealloc( tls_ptr.get() );
            tls_ptr.set( new_tls );
        }
    });
}

#[cfg_attr(not(rust_nightly), ignore)]
#[test]
fn test_unwind_through_fresh_frames() {
    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();

    #[inline(never)]
    fn func_normal_unwind( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize > ) {
        address_space.unwind( ctx, |address| {
            output.push( address );
            UnwindControl::Continue
        });
    }

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut [&mut Vec< usize >], counts: &mut Vec< Option< usize > > ) {
        for output in output {
            let count = address_space.unwind_through_fresh_frames( ctx, |address| {
                output.push( address );
                UnwindControl::Continue
            });

            counts.push( count );
        }
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut [&mut Vec< usize >], counts: &mut Vec< Option< usize > > ) {
        func_1( address_space, ctx, output, counts );
        dummy_volatile_read();
    }

    clear_tls();
    address_space.use_shadow_stack( true );

    {
        let mut trace_1 = Vec::new();
        let mut trace_2 = Vec::new();
        let mut counts = Vec::new();
        func_1( &mut address_space, &mut ctx, &mut [&mut trace_1, &mut trace_2], &mut counts );

        // The stack was unwound two times from exactly the same place,
        // hence the second time nothing was collected.
        assert_ne!( trace_1.len(), 0 );
        assert_eq!( trace_2.len(), 0 );
        assert_eq!( counts, &[None, Some( 0 )] );
    }
    {
        let mut trace = Vec::new();
        let mut counts = Vec::new();
        func_1( &mut address_space, &mut ctx, &mut [&mut trace], &mut counts );

        // We got out of `func_1`, and the instruction pointer in this function changed,
        // hence counts equals 2.
        //
        // The instruction pointer in this function changed, we went into `func_1`,
        // hence we have 2 frames.
        assert_eq!( trace.len(), 2 );
        assert_eq!( counts, &[Some( 2 )] );
    }
    {
        let mut trace = Vec::new();
        let mut counts = Vec::new();
        func_2( &mut address_space, &mut ctx, &mut [&mut trace], &mut counts );

        // We got out of `func_1` and the instruction pointer in this function changed,
        // hence counts equals 2.
        //
        // The instruction pointer in this function changed, we went into `func_2`,
        // and then we went into `func_1`, hence we have 3 frames.
        assert_eq!( trace.len(), 3 );
        assert_eq!( counts, &[Some( 2 )] );
    }
    {
        let mut trace = Vec::new();
        let mut counts = Vec::new();
        func_1( &mut address_space, &mut ctx, &mut [&mut trace], &mut counts );

        // We got out of `func_1`, then out of `func_1`, and then the instruction
        // pointer in this function changed, hence counts equals 3.
        //
        // The instruction pointer in this function changed and we went into `func_1`,
        // hence we have 2 frames.
        assert_eq!( trace.len(), 2 );
        assert_eq!( counts, &[Some( 3 )] );
    }
    {
        let mut trace_1 = Vec::new();
        let mut trace_2 = Vec::new();
        let mut counts = Vec::new();
        func_normal_unwind( &mut address_space, &mut ctx, &mut trace_1 );
        func_1( &mut address_space, &mut ctx, &mut [&mut trace_2], &mut counts );

        // We got out of `func_normal_unwind` and the instruction pointer in this function changed,
        // hence counts equals 2.
        //
        // The instruction pointer in this function changed and we went into `func_1`,
        // hence we have 2 frames.
        assert_eq!( counts, &[Some( 2 )] );
        assert_eq!( trace_2.len(), 2 );
    }
    {
        address_space.use_shadow_stack( false );

        let mut trace_1 = Vec::new();
        let mut trace_2 = Vec::new();
        let mut counts = Vec::new();
        func_1( &mut address_space, &mut ctx, &mut [&mut trace_1], &mut counts );
        func_normal_unwind( &mut address_space, &mut ctx, &mut trace_2 );

        // We disabled the shadow stack hence we'll always get full stack traces.
        assert_eq!( counts, &[None] );
        assert_eq!( trace_1.len(), trace_2.len() );
    }

    ShadowStack::get().unwrap().reset();
}

#[test]
fn test_double_unwind_through_fresh_frames() {
    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();

    #[inline(never)]
    fn func_twice(
        address_space: &mut LocalAddressSpace,
        ctx: &mut LocalUnwindContext,
        output_1: &mut Vec< usize >,
        output_2: &mut Vec< usize >,
        count_1: &mut Option< usize >,
        count_2: &mut Option< usize >
    ) {
        *count_1 = address_space.unwind_through_fresh_frames( ctx, |address| {
            output_1.push( address );
            UnwindControl::Continue
        });

        *count_2 = address_space.unwind_through_fresh_frames( ctx, |address| {
            output_2.push( address );
            UnwindControl::Continue
        });
    }

    clear_tls();
    address_space.use_shadow_stack( true );

    let mut trace_1 = Vec::new();
    let mut trace_2 = Vec::new();
    let mut count_1 = None;
    let mut count_2 = None;
    func_twice( &mut address_space, &mut ctx, &mut trace_1, &mut trace_2, &mut count_1, &mut count_2 );

    if LocalAddressSpace::is_shadow_stack_supported() {
        assert_ne!( trace_1.len(), 0 );
        assert_eq!( count_1, None );
        assert_eq!( trace_2.len(), 1 );
        assert_eq!( count_2, Some( 1 ) );
    } else {
        assert_ne!( trace_1.len(), 0 );
        assert_eq!( count_1, None );
        assert_eq!( trace_1.len(), trace_2.len() );
        assert_eq!( count_2, None );
    }
}

#[test]
fn test_unwind_multiple_contexts_and_address_spaces() {
    let _ = ::env_logger::try_init();

    #[inline(never)]
    fn func_1() -> (usize, usize, usize) {
        let mut count_1 = 0;
        let address_space = LocalAddressSpace::new().unwrap();
        let mut ctx = LocalUnwindContext::new();
        address_space.unwind_through_fresh_frames( &mut ctx, |_| {
            count_1 += 1;
            UnwindControl::Continue
        });

        mem::drop( address_space );

        let mut count_2 = 0;
        let address_space = LocalAddressSpace::new().unwrap();
        address_space.unwind_through_fresh_frames( &mut ctx, |_| {
            count_2 += 1;
            UnwindControl::Continue
        });

        let mut count_3 = 0;
        let address_space_2 = LocalAddressSpace::new().unwrap();
        let mut ctx_2 = LocalUnwindContext::new();
        address_space_2.unwind( &mut ctx_2, |_| {
            count_3 += 1;
            UnwindControl::Continue
        });

        (count_1, count_2, count_3)
    }

    let (count_1, count_2, count_3) = func_1();
    ShadowStack::get().unwrap().reset();

    if LocalAddressSpace::is_shadow_stack_supported() {
        assert_eq!( count_1, count_3 );
        assert_ne!( count_1, count_2 );
        assert_eq!( count_2, 1 );
    } else {
        assert_eq!( count_1, count_2 );
        assert_eq!( count_2, count_3 );
    }
}

#[test]
fn test_unwind_with_panic_1() {
    use std::panic;

    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize >, should_panic: bool ) {
        address_space.unwind( ctx, |address| {
            output.push( address );
            UnwindControl::Continue
        });

        if should_panic {
            panic!();
        }
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize >, should_panic: bool ) {
        func_1( address_space, ctx, output, should_panic );
    }

    address_space.use_shadow_stack( true );

    let mut trace_1 = Vec::new();
    let _ = panic::catch_unwind( panic::AssertUnwindSafe( || {
        func_2( &mut address_space, &mut ctx, &mut trace_1, true );
    }));

    let mut trace_2 = Vec::new();
    func_2( &mut address_space, &mut ctx, &mut trace_2, false );

    assert_eq!( &trace_1.last().unwrap(), &trace_2.last().unwrap() );

    ShadowStack::get().unwrap().reset();
}

#[test]
fn test_unwind_with_panic_2() {
    use std::panic;

    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut ctx = LocalUnwindContext::new();

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize >, should_panic: bool ) {
        address_space.unwind( ctx, |address| {
            output.push( address );
            UnwindControl::Continue
        });

        if should_panic {
            panic!();
        }
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, ctx: &mut LocalUnwindContext, output: &mut Vec< usize >, should_panic: bool ) {
        func_1( address_space, ctx, output, should_panic );
    }

    address_space.use_shadow_stack( false );

    let mut trace_1 = Vec::new();
    func_2( &mut address_space, &mut ctx, &mut trace_1, false );

    address_space.use_shadow_stack( true );

    let mut trace_2 = Vec::new();
    let _ = panic::catch_unwind( panic::AssertUnwindSafe( || {
        func_2( &mut address_space, &mut ctx, &mut trace_2, true );
    }));

    let mut trace_3 = Vec::new();
    func_2( &mut address_space, &mut ctx, &mut trace_3, false );

    assert_eq!( &trace_1[ 0 ], &trace_2[ 0 ] );
    assert_eq!( &trace_1[ 0 ], &trace_3[ 0 ] );
    assert_eq!( &trace_1.last().unwrap(), &trace_2.last().unwrap() );
    assert_eq!( &trace_1.last().unwrap(), &trace_3.last().unwrap() );

    ShadowStack::get().unwrap().reset();
}
