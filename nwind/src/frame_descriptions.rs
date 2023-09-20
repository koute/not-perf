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
use crate::utils::HexValue;

type DataReader< E > = EndianSlice< 'static, E >;

pub struct ContextCache< E: Endianity > {
    cached_context: UninitializedUnwindContext< DataReader< E > >
}

impl< E: Endianity > ContextCache< E > {
    #[inline]
    pub fn new() -> Self {
        ContextCache {
            cached_context: Default::default()
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default, Hash)]
pub struct AddressMapping {
    pub declared_address: u64,
    pub actual_address: u64,
    pub file_offset: u64,
    pub size: u64
}

impl std::fmt::Debug for AddressMapping {
    fn fmt( &self, fmt: &mut std::fmt::Formatter ) -> std::fmt::Result {
        fmt.debug_struct( "AddressMapping" )
         .field( "declared_address", &HexValue( self.declared_address ) )
         .field( "actual_address", &HexValue( self.actual_address ) )
         .field( "file_offset", &HexValue( self.file_offset ) )
         .field( "size", &HexValue( self.size ) )
         .finish()
    }
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

    pub fn clear( &mut self ) {
        if let Some( cache ) = self.cache.as_mut() {
            cache.clear();
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
            is_signal_frame: info.is_signal_frame,
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
    address: u64,
    is_signal_frame: bool
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

// TODO: This will be unnecessary once Polonius lands; remove it once it does.
unsafe fn launder_lifetime< 'a, 'b, T >( reference: &'a mut T ) -> &'b mut T {
    &mut *(reference as *mut _)
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
            debug_descriptions = Self::load_section( bases, binary.name(), debug_frame );
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
            eh_descriptions = Self::load_section( bases, binary.name(), eh_frame );
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

    fn load_section< R, U >( bases: &BaseAddresses, name: &str, section: &U ) -> RangeMap< FrameDescriptionEntry< R > >
        where R: gimli::Reader< Offset = usize >,
              U: UnwindSection< R >,
              <U as UnwindSection< R >>::Offset: UnwindOffset
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
                            warn!( "Failed to parse FDE for '{}': {}", name, error );
                        }
                    }
                },
                Ok( None ) => break,
                Err( error ) => {
                    warn!( "Failed to iterate FDEs for '{}': {}", name, error );
                    break;
                }
            }
        }

        RangeMap::from_vec( descriptions )
    }

    pub fn find_unwind_info< 'a >(
        &self,
        ctx_cache: &'a mut ContextCache< E >,
        mappings: &[AddressMapping],
        absolute_address: u64
    ) -> Option< UnwindInfo< 'a, E > > {
        let address = if let Some( mapping ) = mappings.iter().find( |mapping| absolute_address >= mapping.actual_address && absolute_address < (mapping.actual_address + mapping.size) ) {
            absolute_address - mapping.actual_address + mapping.declared_address
        } else {
            absolute_address
        };

        let ctx = &mut ctx_cache.cached_context;

        if !self.debug_descriptions.is_empty() {
            if let Some( fde ) = self.debug_descriptions.get_value( address ) {
                let initial_address = fde.initial_address();

                let (bases, debug_frame) = &self.debug_frame.as_ref().unwrap();
                let ctx = unsafe { launder_lifetime( ctx ) };
                if let Ok( mut table ) = UnwindTable::new( debug_frame, bases, ctx, &fde ) {
                    loop {
                        match table.next_row() {
                            Ok( Some( row ) ) => {
                                if !row.contains( address ) {
                                    continue;
                                }
                            },
                            Ok( None ) => break,
                            Err( error ) => {
                                error!( "Failed to iterate the unwind table: {:?}", error );
                                break;
                            }
                        }

                        return Some( UnwindInfo {
                            initial_address,
                            address,
                            absolute_address,
                            is_signal_frame: fde.is_signal_trampoline(),
                            kind: UnwindInfoKind::Uncached( table.into_current_row().unwrap() )
                        });
                    }
                }
            }
        }

        if !self.eh_descriptions.is_empty() {
            if let Some( fde ) = self.eh_descriptions.get_value( address ) {
                let initial_address = fde.initial_address();

                let (bases, eh_frame) = &self.eh_frame.as_ref().unwrap();
                let ctx = unsafe { launder_lifetime( ctx ) };
                if let Ok( mut table ) = UnwindTable::new( eh_frame, bases, ctx, &fde ) {
                    loop {
                        match table.next_row() {
                            Ok( Some( row ) ) => {
                                if !row.contains( address ) {
                                    continue;
                                }
                            },
                            Ok( None ) => break,
                            Err( error ) => {
                                error!( "Failed to iterate the unwind table: {:?}", error );
                                break;
                            }
                        }

                        return Some( UnwindInfo {
                            initial_address,
                            address,
                            absolute_address,
                            is_signal_frame: fde.is_signal_trampoline(),
                            kind: UnwindInfoKind::Uncached( table.into_current_row().unwrap() )
                        });
                    }
                }
            }
        }

        if let Some( &(ref bases, ref eh_frame_hdr) ) = self.eh_frame_hdr.as_ref() {
            let eh_frame = &self.eh_frame.as_ref().unwrap().1;

            if debug_logs_enabled!() {
                match eh_frame_hdr.table().unwrap().lookup( address, bases ) {
                    Ok( gimli::Pointer::Direct( pointer ) ) => {
                        let base = bases.eh_frame_hdr.section.unwrap();
                        if pointer < base {
                            warn!( "FDE pointer for {:016X} from .eh_frame_hdr: {:016X} (relative: -0x{:X}", address, pointer, base - pointer );
                        } else {
                            debug!( "FDE pointer for {:016X} from .eh_frame_hdr: {:016X} (relative: 0x{:X})", address, pointer, pointer - base);
                        }
                    },
                    _ => {}
                }
            }

            let fde = eh_frame_hdr.table().unwrap().fde_for_address( &eh_frame, bases, address, |_, _, offset| {
                eh_frame.cie_from_offset( bases, offset )
            });

            match fde {
                Ok( fde ) => {
                    let initial_address = fde.initial_address();
                    if let Ok( mut table ) = UnwindTable::new( eh_frame, bases, ctx, &fde ) {
                        loop {
                            match table.next_row() {
                                Ok( Some( row ) ) => {
                                    if !row.contains( address ) {
                                        continue;
                                    }
                                },
                                Ok( None ) => break,
                                Err( error ) => {
                                    error!( "Failed to iterate the unwind table: {:?}", error );
                                    break;
                                }
                            }

                            return Some( UnwindInfo {
                                initial_address,
                                address,
                                absolute_address,
                                is_signal_frame: fde.is_signal_trampoline(),
                                kind: UnwindInfoKind::Uncached( table.into_current_row().unwrap() )
                            });
                        }
                    }
                },
                Err( error ) => {
                    debug!( "FDE not found in .eh_frame_hdr for 0x{:016X}: {}", absolute_address, error );
                }
            }
        }

        None
    }
}

enum UnwindInfoKind< 'a, E: Endianity + 'a > {
    Cached( &'a CachedUnwindInfo ),
    Uncached( &'a UnwindTableRow< DataReader< E > > ),
}

pub struct UnwindInfo< 'a, E: Endianity + 'a > {
    initial_address: u64,
    address: u64,
    absolute_address: u64,
    is_signal_frame: bool,
    kind: UnwindInfoKind< 'a, E >
}

impl< 'a, E: Endianity > UnwindInfo< 'a, E > {
    #[inline]
    pub fn is_signal_frame( &self ) -> bool {
        self.is_signal_frame
    }

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

        let cache = unwind_cache.cache.get_or_insert_with( || LruCache::new( 4096 ) );

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

        let info = CachedUnwindInfo { rules, cfa, initial_address: self.initial_address, address: self.address, is_signal_frame: self.is_signal_frame };
        cache.put( self.absolute_address, info );
    }
}

unsafe fn calculate_fde_length( fde: *const u8 ) -> usize {
    let mut p = fde;
    loop {
        let entry_length = std::ptr::read_unaligned( p as *const u32 );
        p = p.add( 4 );

        if entry_length == 0 {
            break;
        }

        if entry_length != 0xFFFFFFFF {
            p = p.add( entry_length as usize );
        } else {
            let entry_length = std::ptr::read_unaligned( p as *const u64 );
            p = p.add( entry_length as usize + 8 );
        }
    }

    p as usize - fde as usize
}

struct DynamicTable< E > where E: Endianity {
    bases: BaseAddresses,
    section: EhFrame< EndianSlice< 'static, E > >,
    fde_map: RangeMap< FrameDescriptionEntry< EndianSlice< 'static, E > > >
}

#[derive(Default)]
pub struct DynamicFdeRegistry< E > where E: Endianity {
    tables: Vec< (usize, DynamicTable< E >) >
}

impl< E > DynamicFdeRegistry< E > where E: Endianity {
    pub fn lookup_unwind_row< 'a >(
        &self,
        ctx_cache: &'a mut ContextCache< E >,
        address: u64
    ) -> Option< UnwindInfo< 'a, E > > {
        let ctx = &mut ctx_cache.cached_context;
        for (_, table) in &self.tables {
            if let Some( fde ) = table.fde_map.get_value( address ) {
                let initial_address = fde.initial_address();

                let ctx = unsafe { launder_lifetime( ctx ) };
                if let Ok( mut table ) = UnwindTable::new( &table.section, &table.bases, ctx, &fde ) {
                    loop {
                        match table.next_row() {
                            Ok( Some( row ) ) => {
                                if !row.contains( address ) {
                                    continue;
                                }
                            },
                            Ok( None ) => break,
                            Err( error ) => {
                                error!( "Failed to iterate the unwind table: {:?}", error );
                                break;
                            }
                        }

                        return Some( UnwindInfo {
                            initial_address,
                            address,
                            absolute_address: address,
                            is_signal_frame: fde.is_signal_trampoline(),
                            kind: UnwindInfoKind::Uncached( table.into_current_row().unwrap() )
                        });
                    }
                }
            }
        }

        None
    }
}

impl DynamicFdeRegistry< gimli::NativeEndian > {
    pub unsafe fn register_fde_from_pointer( &mut self, fde: *const u8 ) {
        let length = calculate_fde_length( fde );
        let slice = std::slice::from_raw_parts( fde, length );
        let mut bases = BaseAddresses::default();
        bases = bases.set_eh_frame( fde as u64 );

        let section = gimli::read::EhFrame::new( slice, gimli::NativeEndian );
        let fde_map = FrameDescriptions::< gimli::NativeEndian >::load_section( &bases, "<dynamic>", &section );
        let table = DynamicTable {
            bases,
            section,
            fde_map
        };
        self.tables.push( (fde as usize, table) );
    }

    pub fn unregister_fde_from_pointer( &mut self, fde: *const u8 ) {
        if let Some( (last_fde, _) ) = self.tables.last() {
            if *last_fde == fde as usize {
                self.tables.pop();
                return;
            }
        }

        if let Some( index ) = self.tables.iter().position( |(key, _)| *key == fde as usize ) {
            self.tables.remove( index );
        }
    }
}