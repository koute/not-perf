use std::ops::Range;
use std::sync::Arc;
use std::mem::{self, ManuallyDrop};
use std::time::Instant;
use std::marker::PhantomData;

use lru::LruCache;

use gimli::{
    self,
    BaseAddresses,
    EhFrame,
    EhFrameHdr,
    DebugFrame,
    UninitializedUnwindContext,
    UnwindSection,
    UnwindOffset,
    CfaRule,
    CieOrFde,
    FrameDescriptionEntry,
    UnwindTable,
    UnwindTableRow,
    Register,
    RegisterRule,
    EndianSlice,
    ParsedEhFrameHdr
};

use crate::utils::get_ms;
use crate::binary::{BinaryData};
use crate::arch::Endianity;
use crate::range_map::RangeMap;

type DataReader< E > = EndianSlice< 'static, E >;

pub struct ContextCache< E: Endianity > {
    cached_context: Option< UninitializedUnwindContext< DataReader< E > > >
}

impl< E: Endianity > ContextCache< E > {
    #[inline]
    pub fn new() -> Self {
        ContextCache {
            cached_context: None
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Hash)]
pub struct AddressMapping {
    pub declared_address: u64,
    pub actual_address: u64,
    pub file_offset: u64,
    pub size: u64
}

type FDE< E > = FrameDescriptionEntry< DataReader< E > >;

pub struct FrameDescriptions< E: Endianity > {
    binary: ManuallyDrop< Arc< BinaryData > >,
    eh_descriptions: ManuallyDrop< RangeMap< FDE< E > > >,
    debug_descriptions: ManuallyDrop< RangeMap< FDE< E > > >,

    debug_frame: ManuallyDrop< Option< (BaseAddresses, DebugFrame< DataReader< E > >) > >,
    eh_frame: ManuallyDrop< Option< (BaseAddresses, EhFrame< DataReader< E > >) > >,
    eh_frame_hdr: ManuallyDrop< Option< (BaseAddresses, ParsedEhFrameHdr< DataReader< E > >) > >
}

impl< E: Endianity > Drop for FrameDescriptions< E > {
    #[inline]
    fn drop( &mut self ) {
        unsafe {
            ManuallyDrop::drop( &mut self.eh_descriptions );
            ManuallyDrop::drop( &mut self.debug_descriptions );
            ManuallyDrop::drop( &mut self.eh_frame );
            ManuallyDrop::drop( &mut self.eh_frame_hdr );
            ManuallyDrop::drop( &mut self.binary );
        }
    }
}

pub struct UnwindInfoCache {
    cache: Option< LruCache< u64, CachedUnwindInfo > >
}

impl UnwindInfoCache {
    pub fn new() -> Self {
        UnwindInfoCache {
            cache: None
        }
    }

    pub fn lookup< E: Endianity >( &mut self, absolute_address: u64 ) -> Option< UnwindInfo< E > > {
        let cache = self.cache.as_mut()?;
        let info = match cache.get( &absolute_address ) {
            Some( info ) => info,
            None => return None
        };

        return Some( UnwindInfo {
            initial_address: info.initial_address,
            address: info.address,
            absolute_address,
            kind: UnwindInfoKind::Cached( info )
        });
    }
}

#[derive(Clone)]
enum SimpleRegisterRule {
    Undefined,
    SameValue,
    Offset( i64 ),
    ValOffset( i64 ),
    Register( Register ),
    Architectural
}

#[derive(Clone)]
struct CachedUnwindInfo {
    cfa: (Register, i64),
    rules: Vec< (Register, SimpleRegisterRule) >,
    initial_address: u64,
    address: u64
}

impl< T: ::gimli::Reader > Into< RegisterRule< T > > for SimpleRegisterRule {
    fn into( self ) -> RegisterRule< T > {
        match self {
            SimpleRegisterRule::Undefined => RegisterRule::Undefined,
            SimpleRegisterRule::SameValue => RegisterRule::SameValue,
            SimpleRegisterRule::Offset( arg ) => RegisterRule::Offset( arg ),
            SimpleRegisterRule::ValOffset( arg ) => RegisterRule::ValOffset( arg ),
            SimpleRegisterRule::Register( arg ) => RegisterRule::Register( arg ),
            SimpleRegisterRule::Architectural => RegisterRule::Architectural
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LoadHint {
    WhenNecessary,
    Always,
    Never
}

pub struct FrameDescriptionsBuilder< E: Endianity > {
    binary: Arc< BinaryData >,
    use_eh_frame_hdr: bool,
    load_eh_frame: LoadHint,
    load_debug_frame: bool,
    phantom: PhantomData< E >
}

impl< E: Endianity > FrameDescriptionsBuilder< E > {
    pub fn load( self ) -> Option< FrameDescriptions< E > > {
        FrameDescriptions::< E >::load_with_options( self )
    }

    pub fn should_use_eh_frame_hdr( mut self, value: bool ) -> Self {
        self.use_eh_frame_hdr = value;
        self
    }

    pub fn should_load_eh_frame( mut self, value: LoadHint ) -> Self {
        self.load_eh_frame = value;
        self
    }

    pub fn should_load_debug_frame( mut self, value: bool ) -> Self {
        self.load_debug_frame = value;
        self
    }
}

impl< E: Endianity > FrameDescriptions< E > {
    pub fn new( binary: &Arc< BinaryData > ) -> FrameDescriptionsBuilder< E > {
        FrameDescriptionsBuilder {
            binary: binary.clone(),
            use_eh_frame_hdr: true,
            load_eh_frame: LoadHint::WhenNecessary,
            load_debug_frame: true,
            phantom: PhantomData
        }
    }

    fn load_with_options( builder: FrameDescriptionsBuilder< E > ) -> Option< Self > {
        let binary = &builder.binary;
        let debug_frame;
        if let Some( range ) = binary.debug_frame_range() {
            let bases = BaseAddresses::default();
            let debug_frame_data: &[u8] = &binary.as_bytes()[ range ];
            let debug_frame_data: &'static [u8] = unsafe { mem::transmute( debug_frame_data ) };
            debug_frame = Some( (bases, DebugFrame::new( debug_frame_data, E::get() )) );
        } else {
            debug_frame = None;
        }

        let eh_frame;
        if let Some( range ) = binary.eh_frame_range() {
            let mut bases = BaseAddresses::default();

            if let Some( base ) = Self::get_base( binary, binary.text_range() ) {
                bases = bases.set_text( base );
            }

            if let Some( base ) = Self::get_base( binary, binary.eh_frame_range() ) {
                bases = bases.set_eh_frame( base );
            }

            let eh_frame_data: &[u8] = &binary.as_bytes()[ range ];
            let eh_frame_data: &'static [u8] = unsafe { mem::transmute( eh_frame_data ) };
            eh_frame = Some( (bases, EhFrame::new( eh_frame_data, E::get() )) );
        } else {
            eh_frame = None;
        }

        let eh_frame_hdr;
        if builder.use_eh_frame_hdr {
            eh_frame_hdr = Self::load_eh_frame_hdr( binary );
        } else {
            eh_frame_hdr = None;
        }

        let debug_descriptions: RangeMap< FDE< E > >;
        if debug_frame.is_some() && builder.load_debug_frame {
            debug!( "Loading FDEs from .debug_frame for {}...", binary.name() );
            let (ref bases, ref debug_frame) = debug_frame.as_ref().unwrap();

            let start_timestamp = Instant::now();
            debug_descriptions = Self::load_section( bases, binary, debug_frame );
            let elapsed = start_timestamp.elapsed();

            debug!( "Loaded {} FDEs from .debug_frame for '{}' in {}ms", debug_descriptions.len(), binary.name(), get_ms( elapsed ) );
        } else {
            debug_descriptions = RangeMap::new();
        }

        let want_to_load_eh_frame = builder.load_eh_frame == LoadHint::Always || (builder.load_eh_frame == LoadHint::WhenNecessary && eh_frame_hdr.is_none());
        let eh_descriptions: RangeMap< FDE< E > >;
        if eh_frame.is_some() && want_to_load_eh_frame {
            debug!( "Loading FDEs from .eh_frame for {}...", binary.name() );
            let (ref bases, ref eh_frame) = eh_frame.as_ref().unwrap();

            let start_timestamp = Instant::now();
            eh_descriptions = Self::load_section( bases, binary, eh_frame );
            let elapsed = start_timestamp.elapsed();

            debug!( "Loaded {} FDEs from .eh_frame for '{}' in {}ms", eh_descriptions.len(), binary.name(), get_ms( elapsed ) );
        } else {
            if want_to_load_eh_frame {
                warn!( "No .eh_frame section found for '{}'", binary.name() );
            }

            eh_descriptions = RangeMap::new();
        }

        let debug_descriptions: RangeMap< FDE< E > > = unsafe { mem::transmute( debug_descriptions ) };
        let eh_descriptions: RangeMap< FDE< E > > = unsafe { mem::transmute( eh_descriptions ) };

        Some( FrameDescriptions {
            binary: ManuallyDrop::new( binary.clone() ),
            debug_descriptions: ManuallyDrop::new( debug_descriptions ),
            eh_descriptions: ManuallyDrop::new( eh_descriptions ),
            debug_frame: ManuallyDrop::new( debug_frame ),
            eh_frame: ManuallyDrop::new( eh_frame ),
            eh_frame_hdr: ManuallyDrop::new( eh_frame_hdr )
        })
    }

    fn get_base( binary: &Arc< BinaryData >, range: Option< Range< usize > > ) -> Option< u64 > {
        let range = range?;
        let start = range.start as u64;
        for header in binary.load_headers() {
            if start >= header.file_offset && start < (header.file_offset + header.file_size) {
                return Some( header.address + (start - header.file_offset) );
            }
        }

        None
    }

    fn load_eh_frame_hdr< 'a >( binary: &'a Arc< BinaryData > ) -> Option< (BaseAddresses, ParsedEhFrameHdr< DataReader< E > >) > {
        let mut bases = BaseAddresses::default();

        if let Some( base ) = Self::get_base( binary, binary.text_range() ) {
            bases = bases.set_text( base );
        }

        let eh_frame_hdr_base = Self::get_base( binary, Some( binary.eh_frame_hdr_range()? ) )?;
        let eh_frame_base = Self::get_base( binary, Some( binary.eh_frame_range()? ) )?;
        bases = bases.set_eh_frame_hdr( eh_frame_hdr_base );
        bases = bases.set_eh_frame( eh_frame_base );

        let eh_frame_hdr_data: &[u8] = &binary.as_bytes()[ binary.eh_frame_hdr_range()? ];
        let eh_frame_hdr_data: &'static [u8] = unsafe { mem::transmute( eh_frame_hdr_data ) };
        let eh_frame_hdr = EhFrameHdr::new( eh_frame_hdr_data, E::get() );
        let eh_frame_hdr = match eh_frame_hdr.parse( &bases, mem::size_of::< usize >() as u8 ) {
            Ok( eh_frame_hdr ) => eh_frame_hdr,
            Err( error ) => {
                warn!( "Failed to load .eh_frame_hdr for {}: {}", binary.name(), error );
                return None;
            }
        };

        match eh_frame_hdr.eh_frame_ptr() {
            gimli::Pointer::Direct( pointer ) => {
                debug!( "Extracted .eh_frame address from .eh_frame_hdr for {}: 0x{:016X}", binary.name(), pointer );
                debug!( "Actual .eh_frame address: 0x{:016X}", eh_frame_base );
                debug_assert_eq!( pointer, eh_frame_base );
            },
            _ => {}
        }

        eh_frame_hdr.table()?;

        debug!( "Loaded .eh_frame_hdr for '{}'", binary.name() );
        Some( (bases, eh_frame_hdr) )
    }

    fn load_section< R: gimli::Reader< Offset = usize >, U: UnwindSection< R > >( bases: &BaseAddresses, binary: &Arc< BinaryData >, section: &U ) -> RangeMap< FrameDescriptionEntry< R > >
        where <U as UnwindSection< R >>::Offset: UnwindOffset
    {
        let mut entries = section.entries( bases );
        let mut descriptions = Vec::new();
        loop {
            match entries.next() {
                Ok( Some( CieOrFde::Cie( _ ) ) ) => continue,
                Ok( Some( CieOrFde::Fde( partial ) ) ) => {
                    match partial.parse( |_, _, offset| section.cie_from_offset( bases, offset ) ) {
                        Ok( fde ) => {
                            descriptions.push( (fde.initial_address()..fde.initial_address() + fde.len(), fde) );
                        },
                        Err( error ) => {
                            warn!( "Failed to parse FDE for '{}': {}", binary.name(), error );
                        }
                    }
                },
                Ok( None ) => break,
                Err( error ) => {
                    warn!( "Failed to iterate FDEs for '{}': {}", binary.name(), error );
                    break;
                }
            }
        }

        RangeMap::from_vec( descriptions )
    }

    pub fn find_unwind_info< 'a >( &'a self, ctx_cache: &mut ContextCache< E >, mappings: &[AddressMapping], absolute_address: u64 ) -> Option< UnwindInfo< 'a, E > > {
        let address = if let Some( mapping ) = mappings.iter().find( |mapping| absolute_address >= mapping.actual_address && absolute_address < (mapping.actual_address + mapping.size) ) {
            absolute_address - mapping.actual_address + mapping.declared_address
        } else {
            absolute_address
        };

        let mut info = None;

        if !self.debug_descriptions.is_empty() {
            if let Some( fde ) = self.debug_descriptions.get_value( address ) {
                let (bases, debug_frame) = &self.debug_frame.as_ref().unwrap();
                info = Self::find_unwind_info_impl( fde, debug_frame, bases, ctx_cache, address );
            }
        }

        if info.is_none() && !self.eh_descriptions.is_empty() {
            if let Some( fde ) = self.eh_descriptions.get_value( address ) {
                let (bases, eh_frame) = &self.eh_frame.as_ref().unwrap();
                info = Self::find_unwind_info_impl( fde, eh_frame, bases, ctx_cache, address );
            }
        }

        if info.is_none() {
            if let Some( &(ref bases, ref eh_frame_hdr) ) = self.eh_frame_hdr.as_ref() {
                let eh_frame = &self.eh_frame.as_ref().unwrap().1;

                if debug_logs_enabled!() {
                    match eh_frame_hdr.table().unwrap().lookup( address, bases ) {
                        Ok( gimli::Pointer::Direct( pointer ) ) => {
                            debug!( "FDE pointer for {:016X} from .eh_frame_hdr: {:016X} (relative: 0x{:X})", address, pointer, pointer - bases.eh_frame_hdr.section.unwrap() );
                        },
                        _ => {}
                    }
                }

                let fde = eh_frame_hdr.table().unwrap().lookup_and_parse( address, bases, eh_frame.clone(), |_, _, offset| {
                    eh_frame.cie_from_offset( bases, offset )
                });

                match fde {
                    Ok( fde ) => {
                        info = Self::find_unwind_info_impl( &fde, eh_frame, bases, ctx_cache, address );
                    },
                    Err( error ) => {
                        debug!( "FDE not found in .eh_frame_hdr for 0x{:016X}: {}", absolute_address, error );
                    }
                }
            }
        }

        if let Some( (initial_address, info) ) = info {
            Some( UnwindInfo {
                initial_address,
                address,
                absolute_address,
                kind: UnwindInfoKind::Uncached( info.row ),
            })
        } else {
            None
        }
    }

    fn find_unwind_info_impl< U >(
        fde: &FDE< E >,
        section: &U,
        bases: &BaseAddresses,
        ctx_cache: &mut ContextCache< E >,
        address: u64
    ) -> Option< (u64, UncachedUnwindInfo< E >) >
        where U: UnwindSection< DataReader< E > >,
              <U as UnwindSection< DataReader< E > >>::Offset: UnwindOffset
    {
        let mut ctx = ctx_cache.cached_context.take().unwrap_or_else( || Default::default() );
        let info = {
            let initial_address = fde.initial_address();
            let mut table = match UnwindTable::new( section, bases, &mut ctx, &fde ) {
                Ok( table ) => table,
                Err( _ ) => {
                    ctx_cache.cached_context = Some( ctx );
                    return None;
                }
            };

            loop {
                let row = match table.next_row() {
                    Ok( None ) => break None,
                    Ok( Some( row ) ) => row,
                    Err( error ) => {
                        error!( "Failed to iterate the unwind table: {:?}", error );
                        break None;
                    }
                };

                if row.contains( address ) {
                    let row = row.clone();
                    break Some( (initial_address, UncachedUnwindInfo {
                        row: row
                    }));
                }
            }
        };

        ctx_cache.cached_context = Some( ctx );
        info
    }
}

struct UncachedUnwindInfo< E: Endianity > {
    row: UnwindTableRow< DataReader< E > >
}

enum UnwindInfoKind< 'a, E: Endianity + 'a > {
    Cached( &'a CachedUnwindInfo ),
    Uncached( UnwindTableRow< DataReader< E > > ),
}

pub struct UnwindInfo< 'a, E: Endianity + 'a > {
    initial_address: u64,
    address: u64,
    absolute_address: u64,
    kind: UnwindInfoKind< 'a, E >
}

impl< 'a, E: Endianity > UnwindInfo< 'a, E > {
    #[inline]
    pub fn initial_absolute_address( &self ) -> u64 {
        ((self.absolute_address as i64) + ((self.initial_address as i64) - (self.address as i64))) as u64
    }

    #[inline]
    pub fn cfa( &self ) -> CfaRule< DataReader< E > > {
        match self.kind {
            UnwindInfoKind::Cached( ref info ) => {
                CfaRule::RegisterAndOffset {
                    register: info.cfa.0,
                    offset: info.cfa.1
                }
            },
            UnwindInfoKind::Uncached( ref row ) => {
                row.cfa().clone()
            }
        }
    }

    #[inline]
    pub fn register( &self, register: Register ) -> RegisterRule< DataReader< E > > {
        match self.kind {
            UnwindInfoKind::Cached( ref info ) => {
                if let Some( &(_, ref rule) ) = info.rules.iter().find( |rule| rule.0 == register ) {
                    rule.clone().into()
                } else {
                    RegisterRule::Undefined
                }
            },
            UnwindInfoKind::Uncached( ref row ) => {
                row.register( register )
            }
        }
    }

    #[inline]
    pub fn each_register< F: FnMut( (Register, &RegisterRule< DataReader< E > >) ) >( &self, mut callback: F ) {
        match self.kind {
            UnwindInfoKind::Uncached( ref row ) => {
                for &(register, ref rule) in row.registers() {
                    callback( (register, rule) );
                }
            },
            UnwindInfoKind::Cached( ref info ) => {
                for &(register, ref rule) in &info.rules {
                    let rule = rule.clone().into();
                    callback( (register, &rule) );
                }
            }
        }
    }

    pub fn cache_into( &self, unwind_cache: &mut UnwindInfoCache ) {
        let row = match self.kind {
            UnwindInfoKind::Uncached( ref row ) => row,
            _ => return
        };

        let cfa = match row.cfa() {
            &CfaRule::RegisterAndOffset { register, offset } => (register, offset),
            _ => return
        };

        let cache = unwind_cache.cache.get_or_insert_with( || LruCache::new( 2000 ) );

        let mut rules = Vec::new();
        if cache.len() == cache.cap() {
            rules = cache.pop_lru().map( |(_, old)| old.rules ).unwrap();
            rules.clear();
        } else {
            rules.reserve( 16 );
        }

        for &(register, ref rule) in row.registers() {
            let rule = match *rule {
                RegisterRule::Undefined => SimpleRegisterRule::Undefined,
                RegisterRule::SameValue => SimpleRegisterRule::SameValue,
                RegisterRule::Offset( arg ) => SimpleRegisterRule::Offset( arg ),
                RegisterRule::ValOffset( arg ) => SimpleRegisterRule::ValOffset( arg ),
                RegisterRule::Register( arg ) => SimpleRegisterRule::Register( arg ),
                RegisterRule::Architectural => SimpleRegisterRule::Architectural,
                RegisterRule::Expression( _ ) |
                RegisterRule::ValExpression( _ ) => {
                    return;
                }
            };

            rules.push( (register, rule) );
        }

        let info = CachedUnwindInfo { rules, cfa, initial_address: self.initial_address, address: self.address };
        cache.put( self.absolute_address, info );
    }
}
