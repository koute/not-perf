use std::path::Path;
use std::collections::HashMap;
use std::io;
use std::fs;

use address_space::{IAddressSpace, AddressSpace, BinaryRegion, BinarySource, MemoryReader};
use range_map::RangeMap;
use types::{Endianness, UserFrame, BinaryId};
use dwarf_regs::DwarfRegs;
use arch;
use maps;

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
    inner: AddressSpace< arch::native::Arch >,
    dwarf_regs: DwarfRegs
}

impl LocalAddressSpace {
    pub fn new() -> Result< Self, io::Error > {
        debug!( "Initializing local address space..." );
        let mut address_space = LocalAddressSpace {
            inner: AddressSpace::new(),
            dwarf_regs: DwarfRegs::new()
        };

        address_space.reload()?;
        Ok( address_space )
    }

    pub fn reload( &mut self ) -> Result< (), io::Error > {
        trace!( "Loading maps..." );
        let data = fs::read( "/proc/self/maps" )?;
        let data = String::from_utf8_lossy( &data );
        trace!( "Parsing maps..." );
        let regions = maps::parse( &data );
        trace!( "Processing maps..." );
        let mut binaries = HashMap::new();
        for region in &regions {
            if region.is_executable && region.inode != 0 {
                let id = BinaryId {
                    inode: region.inode,
                    dev_major: region.major,
                    dev_minor: region.minor
                };

                // TODO: Use already loaded binaries?
                binaries.insert( id.clone(), BinarySource::Filesystem( id, Path::new( &region.name ).into() ) );
            }
        }

        self.inner.reload( binaries, regions.clone(), true );
        Ok(())
    }

    pub fn unwind( &mut self, output: &mut Vec< UserFrame > ) {
        let regs = arch::native::Regs::get();

        self.dwarf_regs.clear();
        regs.into_dwarf_regs( &mut self.dwarf_regs );

        let memory = LocalMemory {
            regions: &self.inner.regions
        };

        let mut ctx = self.inner.ctx.start( &memory, &mut self.dwarf_regs );
        loop {
            let frame = UserFrame {
                address: ctx.current_address(),
                initial_address: ctx.current_initial_address()
            };
            output.push( frame );
            if ctx.unwind( &memory ) == false {
                return;
            }
        }
    }

    pub fn lookup_symbol( &self, address: u64 ) -> Option< &str > {
        self.inner.lookup_absolute_symbol( address )
    }
}

#[test]
fn test_self_unwind() {
    let _ = ::env_logger::try_init();

    let mut address_space = LocalAddressSpace::new().unwrap();
    let mut frames = Vec::new();
    address_space.unwind( &mut frames );
    assert!( frames.len() > 3 );

    let mut symbols = Vec::new();
    for frame in frames.iter() {
        if let Some( symbol ) = address_space.lookup_symbol( frame.address ) {
            symbols.push( symbol.to_owned() );
        }
    }

    assert!( symbols[ 0 ].contains( "LocalAddressSpace" ) && symbols[ 0 ].contains( "unwind" ) );
}
