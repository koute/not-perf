use std::io;
use std::fs;
use std::marker::PhantomData;

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

pub struct LocalAddressSpace {
    inner: AddressSpace< arch::native::Arch >
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

impl LocalAddressSpace {
    pub fn new() -> Result< Self, io::Error > {
        debug!( "Initializing local address space..." );
        let mut address_space = LocalAddressSpace {
            inner: AddressSpace::new()
        };

        address_space.reload()?;
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

    #[inline(always)]
    pub fn unwind< F: FnMut( &UserFrame ) -> UnwindControl >( &mut self, mut callback: F ) {
        let memory = LocalMemory {
            regions: &self.inner.regions
        };

        let mut ctx = self.inner.ctx.start( &memory, LocalRegsInitializer::default() );

        loop {
            let frame = UserFrame {
                address: ctx.current_address(),
                initial_address: ctx.current_initial_address()
            };

            match callback( &frame ).into() {
                UnwindControl::Continue => {},
                UnwindControl::Stop => break
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

    let mut trace_1 = Vec::new();
    func_1( &mut address_space, &mut trace_1 );

    let mut trace_2 = Vec::new();
    func_2( &mut address_space, &mut trace_2 );

    assert_eq!( &trace_1[ 0 ], &trace_2[ 0 ] );
    assert_ne!( &trace_1[ 1 ], &trace_2[ 2 ] );
    assert_eq!( &trace_1[ 2.. ], &trace_2[ 3.. ] );
}
