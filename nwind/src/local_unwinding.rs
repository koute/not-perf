use std::io;
use std::fs;
use std::ptr;
use std::marker::PhantomData;
use std::mem;

use libc;
use proc_maps;

use address_space::{IAddressSpace, AddressSpace, BinaryRegion, MemoryReader, Frame};
use binary::BinaryData;
use range_map::RangeMap;
use types::{Endianness, UserFrame};
use arch::{self, LocalRegs, Architecture};
use unwind_context::InitializeRegs;

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

    fn get_u32_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u32 > {
        let value = unsafe { *(address as usize as *const u32) };
        let value = if endianness.conversion_necessary() {
            value.swap_bytes()
        } else {
            value
        };

        Some( value )
    }

    fn get_u64_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u64 > {
        let value = unsafe { *(address as usize as *const u64) };
        let value = if endianness.conversion_necessary() {
            value.swap_bytes()
        } else {
            value
        };

        Some( value )
    }

    fn is_stack_address( &self, _: u64 ) -> bool {
        false
    }
}

extern "C" {
    pub fn nwind_get_shadow_stack() -> *mut usize;
    pub fn nwind_ret_trampoline();
}

#[doc(hidden)]
#[no_mangle]
pub extern fn nwind_on_ret_trampoline( stack_pointer: usize ) -> usize {
    debug!( "Unwinding of trampoline triggered at 0x{:016X} on the stack", stack_pointer );

    let stack = ShadowStack::get();
    let tls = unsafe { &mut *stack.tls };

    tls.tail -= 1;
    let index = tls.tail;
    let entry = tls.slice[ index ];
    if entry.stack_pointer == stack_pointer {
       debug!( "Found trampoline entry at index #{}", index );
       debug!( "Clearing shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );

       return entry.return_address;
    }

    error!( "Failed to find a matching trampoline entry" );
    panic!( "Failed to find a matching trampoline entry" );
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

#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn nwind_on_raise_exception() {
    debug!( "Exception raised!" );

    let mut stack = ShadowStack::get();
    stack.reset();
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
    debug!( "Personality called!" );

    let ip = _Unwind_GetIP( ctx );
    assert_eq!( ip, nwind_ret_trampoline as usize );

    let stack = ShadowStack::get();
    let tls = &mut *stack.tls;

    if tls.tail == 0 {
        error!( "Shadow stack underrun!" );
        loop {}
    }

    {
        let address = tls.slice[ tls.tail - 1 ].return_address;
        _Unwind_SetIP( ctx, address as usize );
    }

    while tls.tail > 0 {
        tls.tail -= 1;
        let entry = tls.slice[ tls.tail ];
        *(entry.location as *mut usize) = entry.return_address;
    }

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

const SHADOW_STACK_SIZE: usize = mem::size_of::< usize >() * 16384;

#[repr(C)]
#[derive(Copy, Clone)]
struct ShadowEntry {
    return_address: usize,
    location: usize,
    stack_pointer: usize
}

#[repr(C)]
struct ShadowStackTls {
    tail: usize,
    is_enabled: usize,
    slice: [ShadowEntry; (SHADOW_STACK_SIZE - mem::size_of::< usize >() * 2) / mem::size_of::< ShadowEntry >()]
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
            let len = tls.slice.len() - self.index;

            if len == 0 {
                return;
            }

            debug!( "Copying shadow stack into #{}..#{} (length={})", dst, dst + len, len );

            ptr::copy_nonoverlapping(
                tls.slice.as_ptr().offset( src as isize ),
                tls.slice.as_mut_ptr().offset( dst as isize ),
                len
            );

            let original_tail = tls.tail;
            tls.tail += len;

            let mut index = 0;
            while index < tls.tail {
                let entry = tls.slice[ index ];
                let kind = if index < original_tail { "old" } else { "new" };
                debug!( "Shadow stack ({}) #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", kind, index, entry.return_address, entry.location, entry.stack_pointer );
                index += 1;
            }
        }
    }
}

impl ShadowStack {
    #[inline]
    fn get() -> Self {
        let tls = unsafe { nwind_get_shadow_stack() } as *mut ShadowStackTls;
        let stack = ShadowStack {
            tls: tls,
            index: unsafe { (*tls).slice.len() }
        };

        stack
    }

    #[inline]
    fn push( &mut self, stack_pointer: usize, address_location: usize ) -> Option< ShadowStackIter > {
        let slot = unsafe { &mut *(address_location as *mut usize) };
        let tls = unsafe { &mut *self.tls };

        if *slot == nwind_ret_trampoline as usize {
            debug!( "Found already set trampoline at slot 0x{:016X}", address_location );

            let index = tls.tail - 1;
            let entry = &tls.slice[ index ];
            if entry.location != address_location {
                debug!( "The address of the slot (0x{:016X}) doesn't match the slot address from the shadow stack (0x{:016X}) for shadow stack entry #{}", address_location, entry.location, index );
                debug!( "Shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );
            }

            if entry.stack_pointer != stack_pointer {
                error!( "The stack pointer (0x{:016X}) doesn't match the stack pointer from the shadow stack (0x{:016X}) for shadow stack entry #{}", stack_pointer, entry.stack_pointer, index );
                error!( "Shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );

                panic!( "The stack pointer doesn't match the stack pointer from the shadow stack" );
            }

            debug!( "Found shadow stack entry at #{} matching the trampoline", index );
            return Some( ShadowStackIter { slice: &tls.slice[..], index: tls.tail } );
        }

        if self.index == tls.tail {
            error!(
                "Shadow stack overflow: has space for only {} entries, contains {} entries from the previous unwind and {} entries from the current one",
                tls.slice.len(),
                tls.tail,
                tls.slice.len() - self.index
            );
            panic!( "Shadow stack overflow!" );
        }

        self.index -= 1;

        debug!( "Saving to shadow stack: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", *slot, address_location, stack_pointer );
        tls.slice[ self.index ] = ShadowEntry {
            return_address: *slot,
            location: address_location,
            stack_pointer
        };

        *slot = nwind_ret_trampoline as usize;
        None
    }

    fn reset( &mut self ) {
        debug!( "Clearing shadow stack..." );
        let tls = unsafe { &mut *self.tls };
        while tls.tail > 0 {
            tls.tail -= 1;
            let index = tls.tail;
            let entry = tls.slice[ index ];

            debug!( "Clearing shadow stack #{}: return address = 0x{:016X}, slot = 0x{:016X}, stack pointer = 0x{:016X}", index, entry.return_address, entry.location, entry.stack_pointer );
            unsafe {
                *(entry.location as *mut usize) = entry.return_address;
            }
        }
    }
}

fn unwind_cached< F: FnMut( &UserFrame ) -> UnwindControl >( iter: ShadowStackIter, mut callback: F ) {
    for address in iter {
        let address = address as u64;
        let frame = UserFrame {
            address,
            initial_address: None // TODO: Remove this field?
        };

        match callback( &frame ).into() {
            UnwindControl::Continue => {},
            UnwindControl::Stop => break
        }
    }
}

pub struct LocalAddressSpace {
    inner: AddressSpace< arch::native::Arch >,
    use_shadow_stack: bool
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
unsafe fn patch_trampoline() {}

#[cfg(target_arch = "mips64")]
unsafe fn patch_trampoline() {
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

impl LocalAddressSpace {
    pub fn new() -> Result< Self, io::Error > {
        debug!( "Initializing local address space..." );
        debug!( "Trampoline address: 0x{:016X}", nwind_ret_trampoline as usize );

        let mut address_space = LocalAddressSpace {
            inner: AddressSpace::new(),
            use_shadow_stack: true
        };

        address_space.reload()?;
        unsafe {
            patch_trampoline();
        }

        Ok( address_space )
    }

    pub fn reload( &mut self ) -> Result< (), io::Error > {
        trace!( "Loading maps..." );
        let data = fs::read( "/proc/self/maps" )?;
        let data = String::from_utf8_lossy( &data );
        trace!( "Parsing maps..." );
        let regions = proc_maps::parse( &data );

        self.inner.reload( regions, &mut |region, handle| {
            if region.name == "[vdso]" {
                return;
            }

            if let Ok( data ) = BinaryData::load_from_fs( &region.name ) {
                handle.set_binary( data.into() );
            }
        });
        Ok(())
    }

    pub fn use_shadow_stack( &mut self, value: bool ) {
        self.use_shadow_stack = value;
    }

    pub fn is_shadow_stack_enabled( &self ) -> bool {
        self.use_shadow_stack
    }

    #[inline(always)]
    pub fn unwind< F: FnMut( &UserFrame ) -> UnwindControl >( &mut self, mut callback: F ) {
        let memory = LocalMemory {
            regions: &self.inner.regions
        };

        let mut ctx = self.inner.ctx.start( &memory, LocalRegsInitializer::default() );
        let mut shadow_stack = ShadowStack::get();

        unsafe {
            if ((*shadow_stack.tls).is_enabled == 1) != self.use_shadow_stack {
                (*shadow_stack.tls).is_enabled = if self.use_shadow_stack { 1 } else { 0 };
                if !self.use_shadow_stack {
                    shadow_stack.reset();
                }
            }
        }

        loop {
            let mut shadow_stack_iter = None;
            if self.use_shadow_stack {
                if let Some( next_address_location ) = ctx.next_address_location() {
                    let stack_pointer = ctx.next_stack_pointer();
                    shadow_stack_iter = shadow_stack.push( stack_pointer as usize, next_address_location as usize )
                }
            }

            let frame = UserFrame {
                address: ctx.current_address(),
                initial_address: ctx.current_initial_address()
            };

            match callback( &frame ).into() {
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

    pub fn decode_symbol_once( &self, address: u64 ) -> Frame {
        self.inner.decode_symbol_once( address )
    }
}

#[test]
fn test_self_unwind() {
    let _ = ::env_logger::try_init();

    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut frames = Vec::new();
    address_space.unwind( |frame| {
        frames.push( frame.clone() );
        UnwindControl::Continue
    });
    assert!( frames.len() > 3 );

    let mut addresses = Vec::new();
    let mut symbols = Vec::new();
    for frame in frames.iter() {
        if let Some( symbol ) = address_space.decode_symbol_once( frame.address ).name {
            symbols.push( symbol.to_owned() );
        }

        addresses.push( frame.address );
    }

    assert!( symbols.iter().next().unwrap().contains( "test_self_unwind" ) );
    assert_ne!( addresses[ addresses.len() - 1 ], addresses[ addresses.len() - 2 ] );
}

#[test]
fn test_unwind_twice() {
    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, output: &mut Vec< u64 > ) {
        address_space.unwind( |frame| {
            output.push( frame.address );
            UnwindControl::Continue
        });
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, output: &mut Vec< u64 > ) {
        func_1( address_space, output );
    }

    address_space.use_shadow_stack( false );

    let mut trace_1 = Vec::new();
    func_1( &mut address_space, &mut trace_1 );

    let mut trace_2 = Vec::new();
    func_2( &mut address_space, &mut trace_2 );

    assert_eq!( &trace_1[ 0 ], &trace_2[ 0 ] );
    assert_ne!( &trace_1[ 1 ], &trace_2[ 2 ] );
    assert_eq!( &trace_1[ 2.. ], &trace_2[ 3.. ] );

    address_space.use_shadow_stack( true );

    let mut trace_3 = Vec::new();
    func_1( &mut address_space, &mut trace_3 );

    let mut trace_4 = Vec::new();
    func_2( &mut address_space, &mut trace_4 );

    assert_eq!( &trace_3[ 0 ], &trace_1[ 0 ] );
    assert_ne!( &trace_3[ 1 ], &trace_1[ 1 ] );
    assert_eq!( &trace_3[ 2.. ], &trace_1[ 2.. ] );

    assert_eq!( &trace_4[ 0..2 ], &trace_2[ 0..2 ] );
    assert_ne!( &trace_4[ 2 ], &trace_2[ 2 ] );
    assert_eq!( &trace_4[ 3.. ], &trace_2[ 3.. ] );
}

#[test]
fn test_unwind_with_panic() {
    use std::panic;

    let _ = ::env_logger::try_init();
    let mut address_space = LocalAddressSpace::new().unwrap();

    #[inline(never)]
    fn func_1( address_space: &mut LocalAddressSpace, output: &mut Vec< u64 >, should_panic: bool ) {
        address_space.unwind( |frame| {
            output.push( frame.address );
            UnwindControl::Continue
        });

        if should_panic {
            panic!();
        }
    }

    #[inline(never)]
    fn func_2( address_space: &mut LocalAddressSpace, output: &mut Vec< u64 >, should_panic: bool ) {
        func_1( address_space, output, should_panic );
    }

    address_space.use_shadow_stack( false );

    let mut trace_1 = Vec::new();
    func_2( &mut address_space, &mut trace_1, false );

    address_space.use_shadow_stack( true );

    let mut trace_2 = Vec::new();
    let _ = panic::catch_unwind( panic::AssertUnwindSafe( || {
        func_2( &mut address_space, &mut trace_2, true );
    }));

    let mut trace_3 = Vec::new();
    func_2( &mut address_space, &mut trace_3, false );

    assert_eq!( &trace_1[ 0 ], &trace_2[ 0 ] );
    assert_eq!( &trace_1[ 0 ], &trace_3[ 0 ] );
    assert_eq!( &trace_1.last().unwrap(), &trace_2.last().unwrap() );
    assert_eq!( &trace_1.last().unwrap(), &trace_3.last().unwrap() );
}
