use std::ops::Range;
use std::sync::Arc;
use std::mem::{self, ManuallyDrop};
use std::ptr;
use std::cell::UnsafeCell;
use std::time::Instant;

use lru::LruCache;

use gimli::{
    self,
    BaseAddresses,
    EhFrame,
    DebugFrame,
    InitializedUnwindContext,
    UninitializedUnwindContext,
    UnwindSection,
    UnwindOffset,
    CfaRule,
    CieOrFde,
    FrameDescriptionEntry,
    UnwindTable,
    UnwindTableRow,
    RegisterRule,
    EndianSlice
};

use utils::get_ms;
use binary::{BinaryData};
use arch::Endianity;
use range_map::RangeMap;

type DataReader< E > = EndianSlice< 'static, E >;

pub struct ContextCache< E: Endianity > {
    cached_eh_frame: Vec< UninitializedUnwindContext< EhFrame< DataReader< E > >, DataReader< E > > >,
    cached_debug_frame: Vec< UninitializedUnwindContext< DebugFrame< DataReader< E > >, DataReader< E > > >
}

trait CachableSection< 'a, E: Endianity >: UnwindSection< DataReader< E > > where <Self as UnwindSection< DataReader< E > >>::Offset: UnwindOffset {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, DataReader< E > >;
    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, DataReader< E > > );
    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, DataReader< E > > > ) -> IUC< E >;
}

impl< 'a, E: Endianity > CachableSection< 'a, E > for EhFrame< DataReader< E > > {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, DataReader< E > > {
        let uuc = ctx_cache.cached_eh_frame.pop().unwrap_or_else( || Default::default() );
        unsafe { mem::transmute( uuc ) }
    }

    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, DataReader< E > > > ) -> IUC< E > {
        IUC::EhFrame( iuc )
    }

    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, DataReader< E > > ) {
        ctx_cache.cached_eh_frame.push( unsafe { mem::transmute( uuc ) } );
    }
}

impl< 'a, E: Endianity > CachableSection< 'a, E > for DebugFrame< DataReader< E > > {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, DataReader< E > > {
        let uuc = ctx_cache.cached_debug_frame.pop().unwrap_or_else( || Default::default() );
        unsafe { mem::transmute( uuc ) }
    }

    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, DataReader< E > > > ) -> IUC< E > {
        IUC::DebugFrame( iuc )
    }

    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, DataReader< E > > ) {
        ctx_cache.cached_debug_frame.push( unsafe { mem::transmute( uuc ) } );
    }
}

impl< E: Endianity > ContextCache< E > {
    #[inline]
    pub fn new() -> Self {
        ContextCache {
            cached_eh_frame: Vec::new(),
            cached_debug_frame: Vec::new()
        }
    }

    #[inline]
    fn cache< 'a, U: CachableSection< 'a, E > >( &mut self, iuc: InitializedUnwindContext< U, DataReader< E > > )
        where <U as UnwindSection< DataReader< E > >>::Offset: UnwindOffset
    {
        U::cache( self, iuc.reset() );
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Hash)]
pub struct AddressMapping {
    pub declared_address: u64,
    pub actual_address: u64,
    pub file_offset: u64,
    pub size: u64
}

type EhFrameDescription< 'a, E > = FrameDescriptionEntry< EhFrame< DataReader< E > >, DataReader< E > >;
type DebugFrameDescription< 'a, E > = FrameDescriptionEntry< DebugFrame< DataReader< E > >, DataReader< E > >;

pub struct FrameDescriptions< E: Endianity > {
    binary: ManuallyDrop< Arc< BinaryData > >,
    eh_descriptions: ManuallyDrop< RangeMap< EhFrameDescription< 'static, E > > >,
    debug_descriptions: ManuallyDrop< RangeMap< DebugFrameDescription< 'static, E > > >
}

impl< E: Endianity > Drop for FrameDescriptions< E > {
    #[inline]
    fn drop( &mut self ) {
        unsafe {
            ManuallyDrop::drop( &mut self.eh_descriptions );
            ManuallyDrop::drop( &mut self.debug_descriptions );
            ManuallyDrop::drop( &mut self.binary );
        }
    }
}

pub struct UnwindInfoCache {
    cache: LruCache< u64, CachedUnwindInfo >
}

impl UnwindInfoCache {
    pub fn new() -> Self {
        UnwindInfoCache {
            cache: LruCache::new( 2000 )
        }
    }

    pub fn lookup< 'a, E: Endianity >( &'a mut self, absolute_address: u64 ) -> Option< UnwindInfo< 'a, E > > {
        let info = match self.cache.get( &absolute_address ) {
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
    Register( u8 ),
    Architectural
}

#[derive(Clone)]
struct CachedUnwindInfo {
    cfa: (u8, i64),
    rules: Vec< (u8, SimpleRegisterRule) >,
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

impl< E: Endianity > FrameDescriptions< E > {
    pub fn load( binary: &Arc< BinaryData > ) -> Option< Self > {
        let debug_descriptions: RangeMap< DebugFrameDescription< E > > = Self::load_debug_frame( binary );
        let eh_descriptions: RangeMap< EhFrameDescription< E > > = Self::load_eh_frame( binary );

        let debug_descriptions: RangeMap< DebugFrameDescription< 'static, E > > = unsafe { mem::transmute( debug_descriptions ) };
        let eh_descriptions: RangeMap< EhFrameDescription< 'static, E > > = unsafe { mem::transmute( eh_descriptions ) };

        Some( FrameDescriptions {
            binary: ManuallyDrop::new( binary.clone() ),
            debug_descriptions: ManuallyDrop::new( debug_descriptions ),
            eh_descriptions: ManuallyDrop::new( eh_descriptions )
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

    fn load_debug_frame< 'a >( binary: &'a Arc< BinaryData > ) -> RangeMap< FrameDescriptionEntry< DebugFrame< DataReader< E > >, DataReader< E > > > {
        let debug_frame_range = match binary.debug_frame_range() {
            Some( range ) => range,
            None => return RangeMap::new()
        };

        debug!( "Loading FDEs from .debug_frame for {}...", binary.name() );

        let start_timestamp = Instant::now();

        let mut bases = BaseAddresses::default();
        if let Some( base ) = Self::get_base( binary, binary.data_range() ) {
            bases = bases.set_data( base );
        }

        if let Some( base ) = Self::get_base( binary, binary.text_range() ) {
            bases = bases.set_text( base );
        }

        if let Some( base ) = Self::get_base( binary, Some( debug_frame_range.clone() ) ) {
            bases = bases.set_cfi( base );
        }

        let debug_frame_data: &[u8] = &binary.as_bytes()[ debug_frame_range.clone() ];
        let debug_frame_data: &'static [u8] = unsafe { mem::transmute( debug_frame_data ) };
        let debug_frame = DebugFrame::new( debug_frame_data, E::get() );

        let descriptions = Self::load_section( bases, binary, debug_frame );
        let elapsed = start_timestamp.elapsed();
        debug!( "Loaded {} FDEs from .debug_frame for '{}' in {}ms", descriptions.len(), binary.name(), get_ms( elapsed ) );

        descriptions
    }

    fn load_eh_frame< 'a >( binary: &'a Arc< BinaryData > ) -> RangeMap< FrameDescriptionEntry< EhFrame< DataReader< E > >, DataReader< E > > > {
        let eh_frame_range = match binary.eh_frame_range() {
            Some( range ) => range,
            None => {
                warn!( "No .eh_frame section found for '{}'", binary.name() );
                return RangeMap::new();
            }
        };

        debug!( "Loading FDEs from .eh_frame for {}...", binary.name() );

        let start_timestamp = Instant::now();

        let mut bases = BaseAddresses::default();
        if let Some( base ) = Self::get_base( binary, binary.data_range() ) {
            bases = bases.set_data( base );
        }

        if let Some( base ) = Self::get_base( binary, binary.text_range() ) {
            bases = bases.set_text( base );
        }

        if let Some( base ) = Self::get_base( binary, Some( eh_frame_range.clone() ) ) {
            bases = bases.set_cfi( base );
        }

        let eh_frame_data: &[u8] = &binary.as_bytes()[ eh_frame_range.clone() ];
        let eh_frame_data: &'static [u8] = unsafe { mem::transmute( eh_frame_data ) };
        let eh_frame = EhFrame::new( eh_frame_data, E::get() );

        let descriptions = Self::load_section( bases, binary, eh_frame );
        let elapsed = start_timestamp.elapsed();
        debug!( "Loaded {} FDEs from .eh_frame for '{}' in {}ms", descriptions.len(), binary.name(), get_ms( elapsed ) );

        descriptions
    }

    fn load_section< R: gimli::Reader< Offset = usize >, U: UnwindSection< R > >( bases: BaseAddresses, binary: &Arc< BinaryData >, section: U ) -> RangeMap< FrameDescriptionEntry< U, R > >
        where <U as UnwindSection< R >>::Offset: UnwindOffset
    {
        let mut entries = section.entries( &bases );
        let mut descriptions = Vec::new();
        loop {
            match entries.next() {
                Ok( Some( CieOrFde::Cie( _ ) ) ) => continue,
                Ok( Some( CieOrFde::Fde( partial ) ) ) => {
                    match partial.parse( |offset| section.cie_from_offset( &bases, offset ) ) {
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

    pub fn find_unwind_info< 'a >( &'a self, ctx_cache: &'a mut ContextCache< E >, mappings: &[AddressMapping], absolute_address: u64 ) -> Option< UnwindInfo< 'a, E > > {
        let address = if let Some( mapping ) = mappings.iter().find( |mapping| absolute_address >= mapping.actual_address && absolute_address < (mapping.actual_address + mapping.size) ) {
            absolute_address - mapping.actual_address + mapping.declared_address
        } else {
            absolute_address
        };

        // HACK: Returning the first `info` invalidates the `ctx_cache` mutable reference,
        //       so we keep a raw pointer to use it again.
        let ctx_cache_ptr = ctx_cache as *mut _;
        {
            let info = Self::find_unwind_info_impl( &self.debug_descriptions, ctx_cache, absolute_address, address );
            if info.is_some() {
                return info;
            }
        }

        Self::find_unwind_info_impl( &self.eh_descriptions, unsafe { &mut *ctx_cache_ptr }, absolute_address, address )
    }

    fn find_unwind_info_impl< 'a, U: CachableSection< 'a, E > >(
        descriptions: &RangeMap< FrameDescriptionEntry< U, DataReader< E > > >,
        ctx_cache: &'a mut ContextCache< E >,
        absolute_address: u64,
        address: u64
    ) -> Option< UnwindInfo< 'a, E > >
        where <U as UnwindSection< DataReader< E > >>::Offset: UnwindOffset
    {
        if descriptions.is_empty() {
            return None;
        }

        let fde = descriptions.get_value( address )?;
        let ctx = U::get( ctx_cache );
        let ctx = match ctx.initialize( fde.cie() ) {
            Ok( ctx ) => ctx,
            Err( (_, ctx) ) => {
                U::cache( ctx_cache, ctx );
                return None;
            }
        };

        let initial_address = fde.initial_address();
        let ctx = UnsafeCell::new( ctx );
        let mut table = UnwindTable::new( unsafe { &mut *ctx.get() }, &fde );
        loop {
            let row = match table.next_row() {
                Ok( None ) => break,
                Ok( Some( row ) ) => row,
                Err( error ) => {
                    error!( "Failed to iterate the unwind table: {:?}", error );
                    break;
                }
            };

            if row.contains( address ) {
                let row = row.clone();
                return Some( UnwindInfo {
                    initial_address,
                    address,
                    absolute_address,
                    kind: UnwindInfoKind::Uncached {
                        iuc: ManuallyDrop::new( U::wrap_context( ctx ) ),
                        row: ManuallyDrop::new( row ),
                        cache: ctx_cache
                    }
                });
            }
        }

        mem::drop( table );
        let ctx = ctx.into_inner();
        ctx_cache.cache( ctx );
        None
    }
}

enum IUC< E: Endianity > {
    EhFrame( UnsafeCell< InitializedUnwindContext< EhFrame< DataReader< E > >, DataReader< E > > > ),
    DebugFrame( UnsafeCell< InitializedUnwindContext< DebugFrame< DataReader< E > >, DataReader< E > > > )
}

enum UnwindInfoKind< 'a, E: Endianity + 'a > {
    Cached( &'a CachedUnwindInfo ),
    Uncached {
        iuc: ManuallyDrop< IUC< E > >,
        row: ManuallyDrop< UnwindTableRow< DataReader< E > > >,
        cache: &'a mut ContextCache< E >
    }
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
            UnwindInfoKind::Uncached { ref row, .. } => {
                row.cfa().clone()
            }
        }
    }

    #[inline]
    pub fn register( &self, register: u8 ) -> RegisterRule< DataReader< E > > {
        match self.kind {
            UnwindInfoKind::Cached( ref info ) => {
                if let Some( &(_, ref rule) ) = info.rules.iter().find( |rule| rule.0 == register ) {
                    rule.clone().into()
                } else {
                    RegisterRule::Undefined
                }
            },
            UnwindInfoKind::Uncached { ref row, .. } => {
                row.register( register )
            }
        }
    }

    #[inline]
    pub fn each_register< F: FnMut( (u8, &RegisterRule< DataReader< E > >) ) >( &self, mut callback: F ) {
        match self.kind {
            UnwindInfoKind::Uncached { ref row, .. } => {
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
            UnwindInfoKind::Uncached { ref row, .. } => row,
            _ => return
        };

        let cfa = match row.cfa() {
            &CfaRule::RegisterAndOffset { register, offset } => (register, offset),
            _ => return
        };

        let mut rules = Vec::new();
        if unwind_cache.cache.len() == unwind_cache.cache.cap() {
            rules = unwind_cache.cache.pop_lru().map( |(_, old)| old.rules ).unwrap();
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
        unwind_cache.cache.put( self.absolute_address, info );
    }
}

impl< 'a, E: Endianity > Drop for UnwindInfo< 'a, E > {
    #[inline]
    fn drop( &mut self ) {
        match self.kind {
            UnwindInfoKind::Uncached { ref mut iuc, ref mut row, ref mut cache } => {
                unsafe {
                    ManuallyDrop::drop( row );

                    match &mut **iuc {
                        &mut IUC::EhFrame( ref iuc ) => {
                            let iuc = ptr::read( iuc.get() );
                            cache.cache( iuc );
                        },
                        &mut IUC::DebugFrame( ref iuc ) => {
                            let iuc = ptr::read( iuc.get() );
                            cache.cache( iuc );
                        }
                    }
                }
            },
            _ => {}
        }
    }
}
