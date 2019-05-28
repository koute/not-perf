use std::fmt;
use gimli;
use crate::address_space::MemoryReader;
use crate::types::{Endianness, Bitness};

pub mod native {
    #[cfg(target_arch = "x86_64")]
    pub use crate::arch::amd64::*;

    #[cfg(target_arch = "mips64")]
    pub use crate::arch::mips64::*;

    #[cfg(target_arch = "arm")]
    pub use crate::arch::arm::*;

    #[cfg(target_arch = "aarch64")]
    pub use crate::arch::aarch64::*;
}

pub enum RegName {
    Known( u16, &'static str ),
    Unknown( u16 )
}

impl fmt::Debug for RegName {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        match *self {
            RegName::Known( register, name ) => write!( fmt, "#{} [{}]", register, name ),
            RegName::Unknown( register ) => write!( fmt, "#{}", register )
        }
    }
}

pub trait Endianity: gimli::Endianity {
    fn get() -> Self;
}

impl Endianity for gimli::LittleEndian {
    fn get() -> Self {
        gimli::LittleEndian
    }
}

impl Endianity for gimli::BigEndian {
    fn get() -> Self {
        gimli::BigEndian
    }
}

#[derive(Debug)]
pub enum UnwindStatus {
    InProgress,
    Finished
}

pub trait Architecture: Sized {
    const NAME: &'static str;
    const ENDIANNESS: Endianness;
    const BITNESS: Bitness;
    const RETURN_ADDRESS_REG: u16;

    type Endianity: Endianity + 'static;
    type State;
    type Regs: Registers + std::fmt::Debug;

    fn register_name( register: u16 ) -> RegName {
        if let Some( name ) = Self::register_name_str( register ) {
            RegName::Known( register, name )
        } else {
            RegName::Unknown( register )
        }
    }

    fn register_name_str( register: u16 ) -> Option< &'static str >;
    fn get_stack_pointer< R: Registers >( regs: &R ) -> Option< u64 >;
    fn get_instruction_pointer( regs: &Self::Regs ) -> Option< u64 >;
    fn initial_state() -> Self::State;
    fn unwind< M: MemoryReader< Self > >(
        nth_frame: usize,
        memory: &M,
        state: &mut Self::State,
        regs: &mut Self::Regs,
        initial_address: &mut Option< u64 >,
        ra_address: &mut Option< u64 >
    ) -> Option< UnwindStatus >;
}

pub struct RegsIter< 'a, T: Copy + Into< u64 > > {
    regs: &'a [T],
    regs_list: &'a [u16],
    index: usize,
    mask: u64
}

impl< 'a, T > Iterator for RegsIter< 'a, T > where T: Copy + Into< u64 > {
    type Item = (u16, T);
    fn next( &mut self ) -> Option< Self::Item > {
        while self.index < self.regs_list.len() {
            let register = self.regs_list[ self.index ];
            self.index += 1;

            let mask = 1_u64 << (register as u32);
            if (self.mask & mask) != 0 {
                let value = self.regs[ register as usize ];
                return Some( (register, value) );
            }
        }

        None
    }
}

impl< 'a, T > RegsIter< 'a, T > where T: Copy + Into< u64 > {
    #[inline]
    pub fn new( ids: &'a [u16], values: &'a [T], mask: u64 ) -> Self {
        RegsIter {
            regs: values,
            regs_list: ids,
            index: 0,
            mask
        }
    }
}

pub trait TryFrom< T > where Self: Sized {
    fn try_from( value: T ) -> Option< Self >;
}

impl< T > TryFrom< T > for T {
    fn try_from( value: T ) -> Option< Self > {
        Some( value )
    }
}

impl TryFrom< u64 > for u32 {
    fn try_from( value: u64 ) -> Option< u32 > {
        if value & 0xFFFFFFFF == value {
            Some( value as u32 )
        } else {
            None
        }
    }
}

pub trait TryInto< T > where Self: Sized {
    fn try_into( self ) -> Option< T >;
}

impl< T, U > TryInto< U > for T where U: TryFrom< T > {
    fn try_into( self ) -> Option< U > {
        TryFrom::try_from( self )
    }
}

pub trait Registers: Clone + Default {
    type RegTy: Copy + Into< u64 > + TryFrom< u64 >;

    fn get( &self, register: u16 ) -> Option< Self::RegTy >;
    fn contains( &self, register: u16 ) -> bool;
    fn append( &mut self, register: u16, value: Self::RegTy );
    fn iter< 'a >( &'a self ) -> RegsIter< 'a, Self::RegTy >;
    fn clear( &mut self );
}

pub trait LocalRegs {
    fn get_local_regs( &mut self );
}

#[cfg(not(feature = "local-unwinding"))]
macro_rules! impl_local_regs {
    ($regs_ty:ident, $arch:tt, $get_regs:ident) => {}
}

#[cfg(feature = "local-unwinding")]
macro_rules! impl_local_regs {
    ($regs_ty:ident, $arch:tt, $get_regs:ident) => {
        #[cfg(all(target_arch = $arch, feature = "local-unwinding"))]
        impl crate::arch::LocalRegs for $regs_ty {
            #[inline(always)]
            fn get_local_regs( &mut self ) {
                extern "C" {
                    fn $get_regs( ptr: *mut $regs_ty );
                }

                unsafe {
                    $get_regs( self );
                }

                let mut mask = 0;
                for &register in REGS {
                    mask = mask | (1_u64 << register as u32);
                }

                self.mask = mask;
            }
        }

    }
}

macro_rules! impl_regs_debug {
    ($regs_ty:ty, $regs_array:ident, $arch:ident) => {
        impl ::std::fmt::Debug for $regs_ty {
            fn fmt( &self, fmt: &mut ::std::fmt::Formatter ) -> ::std::fmt::Result {
                use crate::utils::HexValue;
                use std::borrow::Cow;

                let mut dbg = fmt.debug_struct( stringify!( $regs_ty ) );
                for &register in $regs_array {
                    let name = $arch::register_name_str( register ).map( |name| Cow::Borrowed( name ) ).unwrap_or_else( || format!( "{}", register ).into() );
                    if let Some( value ) = self.get( register ) {
                        dbg.field( &name, &HexValue( value as u64 ) );
                    } else {
                        dbg.field( &name, &"None" );
                    }
                }
                dbg.finish()
            }
        }
    }
}

macro_rules! unsafe_impl_registers {
    ($regs_ty:ty, $regs_array:ident, $reg_ty:ty) => {
        impl $regs_ty {
            #[inline]
            fn slice_length( &self ) -> usize {
                use ::std::mem::size_of;
                let length = size_of::< $regs_ty >() / size_of::< $reg_ty >() - 1;
                length
            }

            #[inline]
            fn as_slice( &self ) -> &[$reg_ty] {
                unsafe {
                    ::std::slice::from_raw_parts(
                        self as *const _ as *const $reg_ty,
                        self.slice_length()
                    )
                }
            }

            #[inline]
            fn as_slice_mut( &mut self ) -> &mut [$reg_ty] {
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        self as *const _ as *mut $reg_ty,
                        self.slice_length()
                    )
                }
            }
        }

        impl Registers for $regs_ty {
            type RegTy = $reg_ty;

            #[inline]
            fn get( &self, register: u16 ) -> Option< Self::RegTy > {
                if !self.contains( register ) {
                    return None
                }

                let value =
                    if cfg!( debug_assertions ) {
                        self.as_slice()[ register as usize ]
                    } else {
                        unsafe {
                            *self.as_slice().get_unchecked( register as usize )
                        }
                    };

                Some( value )
            }

            #[inline]
            fn contains( &self, register: u16 ) -> bool {
                if register >= self.slice_length() as u16 {
                    return false;
                }

                debug_assert!( register < 64, "Out of range register number: {}", register );
                self.mask & (1_u64 << (register as u32)) != 0
            }

            #[inline]
            fn append( &mut self, register: u16, value: Self::RegTy ) {
                if register >= self.slice_length() as u16 {
                    return;
                }

                debug_assert!( register < 64, "Out of range register number: {}", register );
                self.mask |= 1_u64 << (register as u32);
                if cfg!( debug_assertions ) {
                    self.as_slice_mut()[ register as usize ] = value as $reg_ty;
                } else {
                    unsafe {
                        *self.as_slice_mut().get_unchecked_mut( register as usize ) = value as $reg_ty;
                    }
                }
            }

            #[inline]
            fn iter< 'a >( &'a self ) -> crate::arch::RegsIter< 'a, $reg_ty > {
                crate::arch::RegsIter::new( $regs_array, self.as_slice(), self.mask )
            }

            #[inline]
            fn clear( &mut self ) {
                self.mask = 0;
            }
        }
    }
}

pub mod amd64;
pub mod mips64;
pub mod arm;
pub mod aarch64;
