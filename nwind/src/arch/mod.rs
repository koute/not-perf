use std::fmt;
use gimli;
use dwarf_regs::DwarfRegs;
use address_space::MemoryReader;
use types::{Endianness, Bitness};

pub mod native {
    #[cfg(target_arch = "x86_64")]
    pub use arch::amd64::*;

    #[cfg(target_arch = "mips64")]
    pub use arch::mips64::*;

    #[cfg(target_arch = "arm")]
    pub use arch::arm::*;
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
    type Regs: Registers;

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
        regs_next: &mut Self::Regs,
        initial_address: &mut Option< u64 >,
        ra_address: &mut Option< u64 >
    ) -> Option< UnwindStatus >;
}

pub struct RegsIter< 'a > {
    regs: &'a [u64],
    regs_list: &'a [u16],
    index: usize,
    mask: u64
}

impl< 'a > Iterator for RegsIter< 'a > {
    type Item = (u16, u64);
    fn next( &mut self ) -> Option< Self::Item > {
        if self.index >= self.regs_list.len() {
            return None;
        }

        let register = self.regs_list[ self.index ];
        let value = self.regs[ register as usize ];
        loop {
            self.index += 1;
            self.mask >>= 1;
            if (self.mask & 1) != 0 || self.index >= self.regs_list.len() {
                break;
            }
        }

        Some( (register, value) )
    }
}

impl< 'a > RegsIter< 'a > {
    #[inline]
    pub fn new( ids: &'a [u16], values: &'a [u64], mask: u64 ) -> Self {
        RegsIter {
            regs: values,
            regs_list: ids,
            index: 0,
            mask
        }
    }
}

pub trait Registers: Clone + Default {
    fn get( &self, register: u16 ) -> Option< u64 >;
    fn contains( &self, register: u16 ) -> bool;
    fn append( &mut self, register: u16, value: u64 );
    fn iter< 'a >( &'a self ) -> RegsIter< 'a >;
    fn clear( &mut self );

    fn from_dwarf_regs( &mut self, dwarf_regs: &DwarfRegs ) {
        self.clear();
        for (register, value) in dwarf_regs.iter() {
            self.append( register, value );
        }

    }
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
        impl ::arch::LocalRegs for $regs_ty {
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

macro_rules! unsafe_impl_registers {
    ($regs_ty:ty, $regs_array:ident) => {
        impl $regs_ty {
            #[inline]
            fn as_slice( &self ) -> &[u64] {
                unsafe {
                    ::std::slice::from_raw_parts(
                        self as *const _ as *const u64,
                        ::std::mem::size_of::< $regs_ty >() / ::std::mem::size_of::< u64 >() - 1
                    )
                }
            }

            #[inline]
            fn as_slice_mut( &mut self ) -> &mut [u64] {
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        self as *const _ as *mut u64,
                        ::std::mem::size_of::< $regs_ty >() / ::std::mem::size_of::< u64 >() - 1
                    )
                }
            }
        }

        impl Registers for $regs_ty {
            #[inline]
            fn get( &self, register: u16 ) -> Option< u64 > {
                if !self.contains( register ) {
                    return None
                }

                let value = unsafe {
                    *self.as_slice().get_unchecked( register as usize )
                };

                Some( value )
            }

            #[inline]
            fn contains( &self, register: u16 ) -> bool {
                self.mask & (1_u64 << (register as u32)) != 0
            }

            #[inline]
            fn append( &mut self, register: u16, value: u64 ) {
                self.mask |= 1_u64 << (register as u32);
                unsafe {
                    *self.as_slice_mut().get_unchecked_mut( register as usize ) = value;
                }
            }

            #[inline]
            fn iter< 'a >( &'a self ) -> ::arch::RegsIter< 'a > {
                ::arch::RegsIter::new( $regs_array, self.as_slice(), self.mask )
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
