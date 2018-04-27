use std::ops::{Deref, Range};
use std::sync::Arc;
use std::mem::{self, ManuallyDrop};
use std::ptr;
use std::cell::UnsafeCell;
use std::time::Instant;

use gimli::{
    BaseAddresses,
    EhFrame,
    DebugFrame,
    InitializedUnwindContext,
    UninitializedUnwindContext,
    UnwindSection,
    UnwindOffset,
    CieOrFde,
    FrameDescriptionEntry,
    EndianBuf,
    UnwindTable,
    UnwindTableRow
};

use utils::get_ms;
use binary::BinaryData;
use arch::Endianity;
use range_map::RangeMap;

pub struct ContextCache< E: Endianity > {
    cached_eh_frame: Vec< UninitializedUnwindContext< EhFrame< EndianBuf< 'static, E > >, EndianBuf< 'static, E > > >,
    cached_debug_frame: Vec< UninitializedUnwindContext< DebugFrame< EndianBuf< 'static, E > >, EndianBuf< 'static, E > > >
}

trait CachableSection< 'a, E: Endianity >: UnwindSection< EndianBuf< 'a, E > > where <Self as UnwindSection< EndianBuf< 'a, E > >>::Offset: UnwindOffset {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, EndianBuf< 'a, E > >;
    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, EndianBuf< 'a, E > > );
    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, EndianBuf< 'a, E > > > ) -> IUC< 'a, E >;
}

impl< 'a, E: Endianity > CachableSection< 'a, E > for EhFrame< EndianBuf< 'a, E > > {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, EndianBuf< 'a, E > > {
        let uuc = ctx_cache.cached_eh_frame.pop().unwrap_or_else( || Default::default() );
        unsafe { mem::transmute( uuc ) }
    }

    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, EndianBuf< 'a, E > > > ) -> IUC< 'a, E > {
        IUC::EhFrame( iuc )
    }

    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, EndianBuf< 'a, E > > ) {
        ctx_cache.cached_eh_frame.push( unsafe { mem::transmute( uuc ) } );
    }
}

impl< 'a, E: Endianity > CachableSection< 'a, E > for DebugFrame< EndianBuf< 'a, E > > {
    fn get( ctx_cache: &mut ContextCache< E > ) -> UninitializedUnwindContext< Self, EndianBuf< 'a, E > > {
        let uuc = ctx_cache.cached_debug_frame.pop().unwrap_or_else( || Default::default() );
        unsafe { mem::transmute( uuc ) }
    }

    fn wrap_context( iuc: UnsafeCell< InitializedUnwindContext< Self, EndianBuf< 'a, E > > > ) -> IUC< 'a, E > {
        IUC::DebugFrame( iuc )
    }

    fn cache( ctx_cache: &mut ContextCache< E >, uuc: UninitializedUnwindContext< Self, EndianBuf< 'a, E > > ) {
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
    fn cache< 'a, U: CachableSection< 'a, E > >( &mut self, iuc: InitializedUnwindContext< U, EndianBuf< 'a, E > > )
        where <U as UnwindSection< EndianBuf< 'a, E > >>::Offset: UnwindOffset
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

type EhFrameDescription< 'a, E > = FrameDescriptionEntry< EhFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > >;
type DebugFrameDescription< 'a, E > = FrameDescriptionEntry< DebugFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > >;

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

    fn load_debug_frame< 'a >( binary: &'a Arc< BinaryData > ) -> RangeMap< FrameDescriptionEntry< DebugFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > > > {
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

    fn load_eh_frame< 'a >( binary: &'a Arc< BinaryData > ) -> RangeMap< FrameDescriptionEntry< EhFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > > > {
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

    fn load_section< 'a, U: UnwindSection< EndianBuf< 'a, E > > >( bases: BaseAddresses, binary: &Arc< BinaryData >, section: U ) -> RangeMap< FrameDescriptionEntry< U, EndianBuf< 'a, E > > >
        where <U as UnwindSection< EndianBuf< 'a, E > >>::Offset: UnwindOffset
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

    pub fn find_unwind_info< 'a >( &'a self, ctx_cache: &'a mut ContextCache< E >, mappings: &[AddressMapping], address: u64 ) -> Option< UnwindInfo< 'a, E > > {
        let address = if let Some( mapping ) = mappings.iter().find( |mapping| address >= mapping.actual_address && address < (mapping.actual_address + mapping.size) ) {
            address - mapping.actual_address + mapping.declared_address
        } else {
            address
        };

        // HACK: Returning the first `info` invalidates the `ctx_cache` mutable reference,
        //       so we keep a raw pointer to use it again.
        let ctx_cache_ptr = ctx_cache as *mut _;
        {
            let info = Self::find_unwind_info_impl( &self.debug_descriptions, ctx_cache, address );
            if info.is_some() {
                return info;
            }
        }

        Self::find_unwind_info_impl( &self.eh_descriptions, unsafe { &mut *ctx_cache_ptr }, address )
    }

    fn find_unwind_info_impl< 'a, U: CachableSection< 'a, E > >( descriptions: &RangeMap< FrameDescriptionEntry< U, EndianBuf< 'a, E > > >, ctx_cache: &'a mut ContextCache< E >, address: u64 ) -> Option< UnwindInfo< 'a, E > >
        where <U as UnwindSection< EndianBuf< 'a, E > >>::Offset: UnwindOffset
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
        while let Ok( Some( row ) ) = table.next_row() {
            if row.contains( address ) {
                let row = row.clone();
                return Some( UnwindInfo {
                    offset_to_initial_address: (initial_address as i64) - (address as i64),
                    iuc: ManuallyDrop::new( U::wrap_context( ctx ) ),
                    row: ManuallyDrop::new( row ),
                    cache: ctx_cache
                });
            }
        }

        mem::drop( table );
        let ctx = ctx.into_inner();
        ctx_cache.cache( ctx );
        None
    }
}

enum IUC< 'a, E: Endianity > {
    EhFrame( UnsafeCell< InitializedUnwindContext< EhFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > > > ),
    DebugFrame( UnsafeCell< InitializedUnwindContext< DebugFrame< EndianBuf< 'a, E > >, EndianBuf< 'a, E > > > )
}

pub struct UnwindInfo< 'a, E: Endianity + 'a > {
    offset_to_initial_address: i64,
    iuc: ManuallyDrop< IUC< 'a, E > >,
    row: ManuallyDrop< UnwindTableRow< EndianBuf< 'a, E > > >,
    cache: &'a mut ContextCache< E >
}

impl< 'a, E: Endianity > UnwindInfo< 'a, E > {
    #[inline]
    pub fn offset_to_initial_address( &self ) -> i64 {
        self.offset_to_initial_address
    }
}

impl< 'a, E: Endianity > Drop for UnwindInfo< 'a, E > {
    #[inline]
    fn drop( &mut self ) {
        unsafe {
            ManuallyDrop::drop( &mut self.row );

            match &mut *self.iuc {
                &mut IUC::EhFrame( ref iuc ) => {
                    let iuc = ptr::read( iuc.get() );
                    self.cache.cache( iuc );
                },
                &mut IUC::DebugFrame( ref iuc ) => {
                    let iuc = ptr::read( iuc.get() );
                    self.cache.cache( iuc );
                }
            }
        }
    }
}

impl< 'a, E: Endianity > Deref for UnwindInfo< 'a, E > {
    type Target = UnwindTableRow< EndianBuf< 'a, E > >;

    #[inline]
    fn deref( &self ) -> &Self::Target {
        &self.row
    }
}
