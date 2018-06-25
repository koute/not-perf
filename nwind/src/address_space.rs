use std::path::Path;
use std::io;
use std::mem;
use std::ops::Deref;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::fmt;

use byteorder::{self, ByteOrder};

use arch::{Architecture, Endianity};
use dwarf_regs::DwarfRegs;
use maps::Region;
use range_map::RangeMap;
use unwind_context::EmptyUnwindContext;
use binary::BinaryData;
use symbols::Symbols;
use frame_descriptions::{FrameDescriptions, ContextCache, UnwindInfo, AddressMapping};
use types::{Bitness, BinaryId, UserFrame, Endianness};

#[derive(Clone, PartialEq, Eq, Default, Debug, Hash)]
struct BinaryAddresses {
    base: Option< u64 >,
    arm_exidx: Option< u64 >,
    arm_extab: Option< u64 >
}

pub struct Binary< A: Architecture > {
    virtual_addresses: BinaryAddresses,
    mappings: Vec< AddressMapping >,
    data: Arc< BinaryData >,
    symbols: Option< Arc< Symbols< BinaryData > > >,
    frame_descriptions: Option< FrameDescriptions< A::Endianity > >
}

pub type BinaryHandle< A > = Arc< Binary< A > >;

impl< A: Architecture > Binary< A > {
    pub fn lookup_unwind_row< 'a >( &'a self, ctx_cache: &'a mut ContextCache< A::Endianity >, address: u64 ) -> Option< UnwindInfo< 'a, A::Endianity > > {
        if let Some( ref frame_descriptions ) = self.frame_descriptions {
            frame_descriptions.find_unwind_info( ctx_cache, &self.mappings, address )
        } else {
            None
        }
    }

    pub fn base_address( &self ) -> u64 {
        self.virtual_addresses.base.unwrap()
    }

    pub fn arm_exidx_address( &self ) -> Option< u64 > {
        self.virtual_addresses.arm_exidx
    }

    pub fn arm_extab_address( &self ) -> Option< u64 > {
        self.virtual_addresses.arm_extab
    }

    fn lookup_relative_symbol_index( &self, address: u64 ) -> Option< usize > {
        self.symbols.as_ref().and_then( |symbols| symbols.get_symbol_index( address ) )
    }

    pub fn get_symbol_by_index( &self, index: usize ) -> Option< (Range< u64 >, &str) > {
        self.symbols.as_ref().and_then( |symbols| symbols.get_symbol_with_lifetime_by_index( &self.data, index ) )
    }

    pub fn lookup_absolute_symbol( &self, address: u64 ) -> Option< (Range< u64 >, &str) > {
        self.lookup_absolute_symbol_index( address ).and_then( |index| {
            self.get_symbol_by_index( index )
        })
    }

    pub fn lookup_absolute_symbol_index( &self, address: u64 ) -> Option< usize > {
        let effective_address = address.wrapping_sub( self.base_address() );
        self.lookup_relative_symbol_index( effective_address )
    }
}

impl< A: Architecture > Deref for Binary< A > {
    type Target = BinaryData;

    #[inline]
    fn deref( &self ) -> &Self::Target {
        &self.data
    }
}

pub struct BinaryRegion< A: Architecture > {
    binary: BinaryHandle< A >,
    memory_region: Region
}

impl< A: Architecture > BinaryRegion< A > {
    #[inline]
    pub fn binary( &self ) -> &BinaryHandle< A > {
        &self.binary
    }

    #[inline]
    pub fn is_executable( &self ) -> bool {
        self.memory_region.is_executable
    }

    #[inline]
    pub fn file_offset( &self ) -> u64 {
        self.memory_region.file_offset
    }
}

pub struct Memory< 'a, A: Architecture + 'a, T: ?Sized + BufferReader + 'a > {
    regions: &'a RangeMap< BinaryRegion< A > >,
    stack_address: u64,
    stack: &'a T
}

impl< 'a, A: Architecture, T: ?Sized + BufferReader + 'a > Memory< 'a, A, T > {
    #[inline]
    fn get_value_at_address< V: Primitive >( &self, endianness: Endianness, address: u64 ) -> Option< V > {
        if address >= self.stack_address {
            let offset = address - self.stack_address;
            if let Some( value ) = V::read_from_buffer( self.stack, endianness, offset ) {
                debug!( "Read stack address 0x{:016X} (+{}): 0x{:016X}", address, offset, value );
                return Some( value );
            }
        }

        if let Some( (range, region) ) = self.regions.get( address ) {
            let offset = (region.file_offset() + (address - range.start)) as usize;
            debug!( "Reading from binary '{}' at address 0x{:016X} (+{})", region.binary().name(), address, offset );
            let slice = &region.binary().data.as_bytes()[ offset..offset + mem::size_of::< V >() ];
            let value = V::read_from_slice( endianness, slice );
            Some( value )
        } else {
            None
        }
    }
}

impl< 'a, A: Architecture, T: ?Sized + BufferReader + 'a > MemoryReader< A > for Memory< 'a, A, T > {
    #[inline]
    fn get_region_at_address( &self, address: u64 ) -> Option< &BinaryRegion< A > > {
        self.regions.get_value( address )
    }

    #[inline]
    fn get_u32_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u32 > {
        self.get_value_at_address::< u32 >( endianness, address )
    }

    #[inline]
    fn get_u64_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u64 > {
        self.get_value_at_address::< u64 >( endianness, address )
    }

    #[inline]
    fn is_stack_address( &self, address: u64 ) -> bool {
        address >= self.stack_address && address < (self.stack_address + self.stack.len() as u64)
    }
}

pub trait BufferReader {
    fn len( &self ) -> usize;
    fn get_u32_at_offset( &self, endianness: Endianness, offset: u64 ) -> Option< u32 >;
    fn get_u64_at_offset( &self, endianness: Endianness, offset: u64 ) -> Option< u64 >;
}

pub trait MemoryReader< A: Architecture > {
    fn get_region_at_address( &self, address: u64 ) -> Option< &BinaryRegion< A > >;
    fn get_u32_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u32 >;
    fn get_u64_at_address( &self, endianness: Endianness, address: u64 ) -> Option< u64 >;
    fn is_stack_address( &self, address: u64 ) -> bool;

    #[inline]
    fn get_pointer_at_address( &self, endianness: Endianness, bitness: Bitness, address: u64 ) -> Option< u64 > {
        match bitness {
            Bitness::B32 => self.get_u32_at_address( endianness, address ).map( |value| value as u64 ),
            Bitness::B64 => self.get_u64_at_address( endianness, address )
        }
    }
}

pub trait Primitive: Sized + fmt::UpperHex {
    fn read_from_slice( endianness: Endianness, slice: &[u8] ) -> Self;
    fn read_from_buffer< T: ?Sized + BufferReader >( buffer: &T, endianness: Endianness, offset: u64 ) -> Option< Self >;
}

impl Primitive for u32 {
    #[inline]
    fn read_from_slice( endianness: Endianness, slice: &[u8] ) -> Self {
        match endianness {
            Endianness::LittleEndian => byteorder::LittleEndian::read_u32( slice ),
            Endianness::BigEndian => byteorder::BigEndian::read_u32( slice ),
        }
    }

    #[inline]
    fn read_from_buffer< T: ?Sized + BufferReader >( buffer: &T, endianness: Endianness, offset: u64 ) -> Option< Self > {
        buffer.get_u32_at_offset( endianness, offset )
    }
}

impl Primitive for u64 {
    #[inline]
    fn read_from_slice( endianness: Endianness, slice: &[u8] ) -> Self {
        match endianness {
            Endianness::LittleEndian => byteorder::LittleEndian::read_u64( slice ),
            Endianness::BigEndian => byteorder::BigEndian::read_u64( slice ),
        }
    }

    #[inline]
    fn read_from_buffer< T: ?Sized + BufferReader >( buffer: &T, endianness: Endianness, offset: u64 ) -> Option< Self > {
        buffer.get_u64_at_offset( endianness, offset )
    }
}

#[derive(Clone)]
pub enum BinarySource< 'a > {
    Filesystem( BinaryId, &'a Path ),
    StaticSlice( &'a [u8], BinaryId, &'static [u8] ),
    #[allow(dead_code)]
    Owned( &'a [u8], BinaryId, Vec< u8 > ),
    Preloaded( Arc< BinaryData > )
}

fn contains( range: Range< u64 >, value: u64 ) -> bool {
    (range.start <= value) && (value < range.end)
}

fn calculate_virtual_addr( region: &Region, physical_section_offset: u64 ) -> Option< u64 > {
    let region_range = region.file_offset..region.file_offset + (region.end - region.start);
    if contains( region_range, physical_section_offset ) {
        let virtual_addr = region.start + physical_section_offset - region.file_offset;
        Some( virtual_addr )
    } else {
        None
    }
}

pub trait IAddressSpace {
    fn reload( &mut self, binaries: HashMap< BinaryId, BinarySource >, regions: Vec< Region >, load: bool ) -> Reloaded;
    fn unwind( &mut self, regs: &mut DwarfRegs, stack: &BufferReader, output: &mut Vec< UserFrame > );
    fn lookup_absolute_symbol_index( &self, binary_id: &BinaryId, address: u64 ) -> Option< usize >;
    fn get_symbol_by_index< 'a >( &'a self, binary_id: &BinaryId, index: usize ) -> (Range< u64 >, &'a str);
    fn set_panic_on_partial_backtrace( &mut self, value: bool );
}

fn load_binary< A: Architecture >( source: BinarySource ) -> io::Result< Arc< BinaryData > > {
    let data = match source {
        BinarySource::Filesystem( id, path ) => Arc::new( BinaryData::load_from_fs( Some( id ), path )? ),
        BinarySource::StaticSlice( name, id, data ) => Arc::new( BinaryData::load_from_static_slice( &String::from_utf8_lossy( name ), id, data )? ),
        BinarySource::Owned( name, id, data ) => Arc::new( BinaryData::load_from_owned_bytes( &String::from_utf8_lossy( name ), id.clone(), data )? ),
        BinarySource::Preloaded( data ) => data
    };

    Ok( data )
}

#[derive(Clone, Default)]
pub struct Reloaded {
    pub binaries_unmapped: Vec< (BinaryId, u64) >,
    pub binaries_mapped: Vec< (Arc< BinaryData >, u64) >,
    pub regions_unmapped: Vec< Range< u64 > >,
    pub regions_mapped: Vec< Region >
}

pub struct AddressSpace< A: Architecture > {
    empty_ctx: Option< EmptyUnwindContext< A > >,
    binary_map: HashMap< BinaryId, BinaryHandle< A > >,
    regions: RangeMap< BinaryRegion< A > >,
    panic_on_partial_backtrace: bool
}

impl< A: Architecture > IAddressSpace for AddressSpace< A > {
    fn reload( &mut self, mut binaries: HashMap< BinaryId, BinarySource >, regions: Vec< Region >, load: bool ) -> Reloaded {
        debug!( "Reloading..." );

        struct Data< E: Endianity > {
            binary_data: Arc< BinaryData >,
            addresses: BinaryAddresses,
            mappings: Vec< AddressMapping >,
            old_addresses: Option< BinaryAddresses >,
            symbols: Option< Arc< Symbols< BinaryData > > >,
            frame_descriptions: Option< FrameDescriptions< E > >,
            regions: Vec< (Region, bool) >
        }

        let mut reloaded = Reloaded::default();

        let mut old_binary_map = HashMap::new();
        mem::swap( &mut old_binary_map, &mut self.binary_map );

        let mut old_region_map = RangeMap::new();
        mem::swap( &mut old_region_map, &mut self.regions );

        let mut old_regions = HashSet::new();
        for (_, region) in old_region_map {
            old_regions.insert( region.memory_region );
        }
        let old_region_count = old_regions.len();

        let mut new_binary_map = HashMap::new();
        for region in regions {
            if region.is_shared || region.name.is_empty() || (region.inode == 0 && region.name != "[vdso]") {
                continue;
            }

            debug!( "Adding memory region at 0x{:016X}-0x{:016X} for '{}' with offset 0x{:08X}", region.start, region.end, region.name, region.file_offset );

            let id = BinaryId {
                inode: region.inode,
                dev_major: region.major,
                dev_minor: region.minor
            };

            if !new_binary_map.contains_key( &id ) {
                if let Some( binary ) = old_binary_map.remove( &id ) {
                    let (binary_data, virtual_addresses, symbols, frame_descriptions) = match Arc::try_unwrap( binary ) {
                        Ok( binary ) => (binary.data, binary.virtual_addresses, binary.symbols, binary.frame_descriptions),
                        Err( arc ) => {
                            assert!( false );
                            (arc.data.clone(), arc.virtual_addresses.clone(), None, None)
                        }
                    };

                    new_binary_map.insert( id.clone(), Data {
                        binary_data,
                        addresses: BinaryAddresses::default(),
                        mappings: Default::default(),
                        old_addresses: Some( virtual_addresses ),
                        symbols,
                        frame_descriptions,
                        regions: Vec::new()
                    });
                } else if let Some( source ) = binaries.remove( &id ) {
                    if let Ok( binary_data ) = load_binary::< A >( source ) {
                        new_binary_map.insert( id.clone(), Data {
                            binary_data,
                            addresses: BinaryAddresses::default(),
                            mappings: Default::default(),
                            old_addresses: None,
                            symbols: None,
                            frame_descriptions: None,
                            regions: Vec::new()
                        });
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            let is_new = !old_regions.remove( &region );
            let mut data = new_binary_map.get_mut( &id ).unwrap();

            if region.file_offset == 0 && data.addresses.base.is_none() {
                if let Some( load_header ) = data.binary_data.load_headers().iter().find( |header| header.file_offset == 0 ) {
                    data.addresses.base = Some( region.start.wrapping_sub( load_header.address ) );
                    debug!( "'{}': found base address at 0x{:016X}", region.name, data.addresses.base.unwrap() );
                }
            }

            if let Some( header ) = data.binary_data.load_headers().iter().find( |header| header.file_offset == region.file_offset ) {
                data.mappings.push( AddressMapping {
                    declared_address: header.address,
                    actual_address: region.start,
                    file_offset: header.file_offset,
                    size: region.end - region.start
                });
            }

            macro_rules! section {
                ($name:expr, $section_range_getter:ident, $output_addr:expr) => {
                    if $output_addr.is_none() {
                        if let Some( section_range ) = data.binary_data.$section_range_getter() {
                            if let Some( addr ) = calculate_virtual_addr( &region, section_range.start as u64 ) {
                                debug!( "'{}': found {} section at 0x{:016X} (+0x{:08X})", region.name, $name, addr, addr - region.start );
                                *$output_addr = Some( addr );
                            }
                        }
                    }
                }
            }

            section!( ".ARM.exidx", arm_exidx_range, &mut data.addresses.arm_exidx );
            section!( ".ARM.extab", arm_extab_range, &mut data.addresses.arm_extab );

            data.regions.push( (region, is_new) );
        }

        let mut new_regions = Vec::new();
        for (id, data) in new_binary_map {
            if data.addresses.base.is_none() {
                warn!( "No base address found for '{}'!", data.binary_data.name() );
                if let Some( old_addresses ) = data.old_addresses {
                    reloaded.binaries_unmapped.push( (data.binary_data.id().clone(), old_addresses.base.unwrap()) );
                }

                for (region, is_new) in data.regions {
                    if is_new {
                        continue;
                    }
                    reloaded.regions_unmapped.push( region.start..region.end );
                }

                continue;
            }

            if let Some( old_addresses ) = data.old_addresses {
                if old_addresses.base != data.addresses.base {
                    reloaded.binaries_unmapped.push( (data.binary_data.id().clone(), old_addresses.base.unwrap()) );
                    reloaded.binaries_mapped.push( (data.binary_data.clone(), data.addresses.base.unwrap()) );
                }
            } else {
                reloaded.binaries_mapped.push( (data.binary_data.clone(), data.addresses.base.unwrap()) );
            }

            let symbols = match data.symbols {
                Some( symbols ) => Some( symbols ),
                None if load => Some( Arc::new( Symbols::load_from_binary_data( &data.binary_data ) ) ),
                None => None
            };


            let frame_descriptions = match data.frame_descriptions {
                Some( frame_descriptions ) => Some( frame_descriptions ),
                None if load => FrameDescriptions::load( &data.binary_data ),
                None => None
            };

            let binary = Arc::new( Binary {
                data: data.binary_data,
                virtual_addresses: data.addresses,
                mappings: data.mappings,
                symbols,
                frame_descriptions
            });

            for (region, is_new) in data.regions {
                let start = region.start;
                let end = region.end;
                let binary_region = BinaryRegion {
                    binary: binary.clone(),
                    memory_region: region.clone()
                };

                if is_new {
                    reloaded.regions_mapped.push( region );
                }

                new_regions.push( ((start..end), binary_region) );
            }

            self.binary_map.insert( id, binary );
        }

        let new_region_count = new_regions.len();
        self.regions = RangeMap::from_vec( new_regions );
        assert_eq!( new_region_count, self.regions.len() );

        for (_, binary) in old_binary_map {
            reloaded.binaries_unmapped.push( (binary.id().clone(), binary.virtual_addresses.base.unwrap()) );
        }

        reloaded.regions_unmapped.extend( old_regions.into_iter().map( |region| region.start..region.end ) );

        assert_eq!( new_region_count as i32 - old_region_count as i32, reloaded.regions_mapped.len() as i32 - reloaded.regions_unmapped.len() as i32 );
        reloaded
    }

    fn unwind( &mut self, regs: &mut DwarfRegs, stack: &BufferReader, output: &mut Vec< UserFrame > ) {
        output.clear();

        let stack_address = match A::get_stack_pointer( regs ) {
            Some( address ) => address,
            None => return
        };

        let memory = Memory {
            regions: &self.regions,
            stack,
            stack_address
        };

        let mut empty_ctx = self.empty_ctx.take().unwrap();
        empty_ctx.set_panic_on_partial_backtrace( self.panic_on_partial_backtrace );

        let mut ctx = empty_ctx.start( &memory, regs );
        loop {
            let frame = UserFrame {
                address: ctx.current_address(),
                initial_address: ctx.current_initial_address()
            };
            output.push( frame );
            match ctx.unwind( &memory ) {
                Ok( next_ctx ) => ctx = next_ctx,
                Err( empty_ctx ) => {
                    self.empty_ctx = Some( empty_ctx );
                    return;
                }
            }
        }
    }

    fn lookup_absolute_symbol_index( &self, binary_id: &BinaryId, address: u64 ) -> Option< usize > {
        self.binary_map.get( &binary_id ).and_then( |binary| {
            binary.lookup_absolute_symbol_index( address )
        })
    }

    fn get_symbol_by_index< 'a >( &'a self, binary_id: &BinaryId, index: usize ) -> (Range< u64 >, &'a str) {
        self.binary_map.get( &binary_id ).unwrap().get_symbol_by_index( index ).unwrap()
    }

    fn set_panic_on_partial_backtrace( &mut self, value: bool ) {
        self.panic_on_partial_backtrace = value;
    }
}

impl< A: Architecture > AddressSpace< A > {
    pub fn new() -> Self {
        AddressSpace {
            empty_ctx: Some( EmptyUnwindContext::< A >::new() ),
            binary_map: HashMap::new(),
            regions: RangeMap::new(),
            panic_on_partial_backtrace: false
        }
    }
}

#[test]
fn test_reload() {
    use std::env;
    use std::fs::File;
    use std::io::Read;
    use env_logger;
    use arch;

    env_logger::init();

    fn region( start: u64, inode: u64, name: &str ) -> Region {
        Region {
            start: start,
            end: start + 4096,
            is_read: true,
            is_write: false,
            is_executable: true,
            is_shared: false,
            file_offset: 0,
            major: 0,
            minor: 0,
            inode,
            name: name.to_owned()
        }
    }

    let path = env::current_exe().unwrap();
    let mut raw_data = Vec::new();
    {
        let mut fp = File::open( path ).unwrap();
        fp.read_to_end( &mut raw_data ).unwrap();
    }

    let mut binaries = HashMap::new();
    {
        let mut add_binary = |inode: u64, name: &'static str| {
            let id = BinaryId { inode, dev_major: 0, dev_minor: 0 };
            binaries.insert( id.clone(), BinarySource::Owned( name.as_bytes(), id, raw_data.clone() ) );
        };

        add_binary( 1, "file_1" );
        add_binary( 2, "file_2" );
        add_binary( 3, "file_3" );
    }

    let mut address_space = AddressSpace::< arch::native::Arch >::new();

    let mut regions = vec![
        region( 0x1000, 1, "file_1" ),
        region( 0x2000, 2, "file_2" )
    ];

    let res = address_space.reload( binaries.clone(), regions.clone(), false );
    assert_eq!( res.binaries_unmapped.len(), 0 );
    assert_eq!( res.binaries_mapped.len(), 2 );
    assert_eq!( res.regions_unmapped.len(), 0 );
    assert_eq!( res.regions_mapped.len(), 2 );

    let res = address_space.reload( binaries.clone(), regions.clone(), false );
    assert_eq!( res.binaries_unmapped.len(), 0 );
    assert_eq!( res.binaries_mapped.len(), 0 );
    assert_eq!( res.regions_unmapped.len(), 0 );
    assert_eq!( res.regions_mapped.len(), 0 );

    regions.push( region( 0x3000, 3, "file_3" ) );

    let res = address_space.reload( binaries.clone(), regions.clone(), false );
    assert_eq!( res.binaries_unmapped.len(), 0 );
    assert_eq!( res.binaries_mapped.len(), 1 );
    assert_eq!( res.regions_unmapped.len(), 0 );
    assert_eq!( res.regions_mapped.len(), 1 );

    regions.push( region( 0x4000, 3, "file_3" ) );

    let res = address_space.reload( binaries.clone(), regions.clone(), false );
    assert_eq!( res.binaries_unmapped.len(), 0 );
    assert_eq!( res.binaries_mapped.len(), 0 );
    assert_eq!( res.regions_unmapped.len(), 0 );
    assert_eq!( res.regions_mapped.len(), 1 );

    regions.pop();
    regions.pop();

    let res = address_space.reload( binaries.clone(), regions.clone(), false );
    assert_eq!( res.binaries_unmapped.len(), 1 );
    assert_eq!( res.binaries_mapped.len(), 0 );
    assert_eq!( res.regions_unmapped.len(), 2 );
    assert_eq!( res.regions_mapped.len(), 0 );
}
