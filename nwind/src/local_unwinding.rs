use std::io;
use std::fs;

use proc_maps;

use address_space::{IAddressSpace, AddressSpace, BinaryRegion, MemoryReader, Frame};
use binary::BinaryData;
use range_map::RangeMap;
use types::{Endianness, UserFrame};
use arch::{self, LocalRegs};

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

    pub fn unwind< F: FnMut( &UserFrame ) -> UnwindControl >( &mut self, mut callback: F ) {
        let memory = LocalMemory {
            regions: &self.inner.regions
        };

        let mut ctx = self.inner.ctx.start( &memory, |regs| {
            regs.get_local_regs();
        });

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

    assert!( symbols.iter().find( |symbol| symbol.contains( "LocalAddressSpace" ) && symbol.contains( "unwind" ) ).is_some() );
    assert_ne!( addresses[ addresses.len() - 1 ], addresses[ addresses.len() - 2 ] );
}
