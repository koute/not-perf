use std::fmt;
use gimli;
use dwarf_regs::DwarfRegs;
use address_space::MemoryReader;
use unwind_context::UnwindFrame;
use archive::{Endianness, Bitness};

pub mod amd64;
pub mod mips64;
pub mod arm;

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

pub trait Architecture: Sized {
    const NAME: &'static str;
    const ENDIANNESS: Endianness;
    const BITNESS: Bitness;

    type Endianity: Endianity + 'static;
    type State;

    fn register_name( register: u16 ) -> RegName {
        if let Some( name ) = Self::register_name_str( register ) {
            RegName::Known( register, name )
        } else {
            RegName::Unknown( register )
        }
    }

    fn register_name_str( register: u16 ) -> Option< &'static str >;
    fn get_stack_pointer( regs: &DwarfRegs ) -> Option< u64 >;
    fn get_instruction_pointer( regs: &DwarfRegs ) -> Option< u64 >;
    fn initial_state() -> Self::State;
    fn unwind< M: MemoryReader< Self > >( nth_frame: usize, memory: &M, state: &mut Self::State, current_frame: &mut UnwindFrame< Self >, next_frame: &mut UnwindFrame< Self >, panic_on_partial_backtrace: bool ) -> bool;
}
