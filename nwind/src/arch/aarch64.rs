use gimli::LittleEndian;
use crate::arch::{Architecture, Registers, UnwindStatus};
use crate::address_space::MemoryReader;
use crate::frame_descriptions::{ContextCache, UnwindInfoCache};
use crate::types::{Endianness, Bitness};
use crate::dwarf::dwarf_unwind;

// Source: DWARF for the ARM 64-bit, 3.1 DWARF register names
//         http://infocenter.arm.com/help/topic/com.arm.doc.ihi0057b/IHI0057B_aadwarf64.pdf
pub mod dwarf {
    pub const X0: u16 = 0;
    pub const X1: u16 = 1;
    pub const X2: u16 = 2;
    pub const X3: u16 = 3;
    pub const X4: u16 = 4;
    pub const X5: u16 = 5;
    pub const X6: u16 = 6;
    pub const X7: u16 = 7;
    pub const X8: u16 = 8;
    pub const X9: u16 = 9;
    pub const X10: u16 = 10;
    pub const X11: u16 = 11;
    pub const X12: u16 = 12;
    pub const X13: u16 = 13;
    pub const X14: u16 = 14;
    pub const X15: u16 = 15;
    pub const X16: u16 = 16;
    pub const X17: u16 = 17;
    pub const X18: u16 = 18;
    pub const X19: u16 = 19;
    pub const X20: u16 = 20;
    pub const X21: u16 = 21;
    pub const X22: u16 = 22;
    pub const X23: u16 = 23;
    pub const X24: u16 = 24;
    pub const X25: u16 = 25;
    pub const X26: u16 = 26;
    pub const X27: u16 = 27;
    pub const X28: u16 = 28;
    pub const X29: u16 = 29;
    pub const X30: u16 = 30;
    pub const X31: u16 = 31;

    pub const PC: u16 = 32;
}

static REGS: &'static [u16] = &[
    dwarf::X0,
    dwarf::X1,
    dwarf::X2,
    dwarf::X3,
    dwarf::X4,
    dwarf::X5,
    dwarf::X6,
    dwarf::X7,
    dwarf::X8,
    dwarf::X9,
    dwarf::X10,
    dwarf::X11,
    dwarf::X12,
    dwarf::X13,
    dwarf::X14,
    dwarf::X15,
    dwarf::X16,
    dwarf::X17,
    dwarf::X18,
    dwarf::X19,
    dwarf::X20,
    dwarf::X21,
    dwarf::X22,
    dwarf::X23,
    dwarf::X24,
    dwarf::X25,
    dwarf::X26,
    dwarf::X27,
    dwarf::X28,
    dwarf::X29,
    dwarf::X30,
    dwarf::X31,

    dwarf::PC
];

#[repr(C)]
#[derive(Clone, Default)]
pub struct Regs {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
    x31: u64,

    pc: u64,

    mask: u64
}

unsafe_impl_registers!( Regs, REGS, u64 );
impl_local_regs!( Regs, "aarch64", get_regs_aarch64 );
impl_regs_debug!( Regs, REGS, Arch );

#[allow(dead_code)]
pub struct Arch {}

#[doc(hidden)]
pub struct State {
    ctx_cache: ContextCache< LittleEndian >,
    unwind_cache: UnwindInfoCache,
    new_regs: Vec< (u16, u64) >
}

impl Architecture for Arch {
    const NAME: &'static str = "aarch64";
    const ENDIANNESS: Endianness = Endianness::LittleEndian;
    const BITNESS: Bitness = Bitness::B64;
    const RETURN_ADDRESS_REG: u16 = dwarf::X30;

    type Endianity = LittleEndian;
    type State = State;
    type Regs = Regs;

    fn register_name_str( register: u16 ) -> Option< &'static str > {
        use self::dwarf::*;

        let name = match register {
            X0 => "X0",
            X1 => "X1",
            X2 => "X2",
            X3 => "X3",
            X4 => "X4",
            X5 => "X5",
            X6 => "X6",
            X7 => "X7",
            X8 => "X8",
            X9 => "X9",
            X10 => "X10",
            X11 => "X11",
            X12 => "X12",
            X13 => "X13",
            X14 => "X14",
            X15 => "X15",
            X16 => "X16",
            X17 => "X17",
            X18 => "X18",
            X19 => "X19",
            X20 => "X20",
            X21 => "X21",
            X22 => "X22",
            X23 => "X23",
            X24 => "X24",
            X25 => "X25",
            X26 => "X26",
            X27 => "X27",
            X28 => "X28",
            X29 => "X29",
            X30 => "LR",
            X31 => "SP",
            _ => return None
        };

        Some( name )
    }

    #[inline]
    fn get_stack_pointer< R: Registers >( regs: &R ) -> Option< u64 > {
        regs.get( dwarf::X31 ).map( |value| value.into() )
    }

    #[inline]
    fn get_instruction_pointer( regs: &Self::Regs ) -> Option< u64 > {
        regs.get( dwarf::PC ).map( |value| value.into() )
    }

    #[inline]
    fn initial_state() -> Self::State {
        State {
            ctx_cache: ContextCache::new(),
            unwind_cache: UnwindInfoCache::new(),
            new_regs: Vec::with_capacity( 32 )
        }
    }

    #[inline]
    fn unwind< M: MemoryReader< Self > >(
        nth_frame: usize,
        memory: &M,
        state: &mut Self::State,
        regs: &mut Self::Regs,
        initial_address: &mut Option< u64 >,
        ra_address: &mut Option< u64 >
    ) -> Option< UnwindStatus > {
        let result = dwarf_unwind( nth_frame, memory, &mut state.ctx_cache, &mut state.unwind_cache, regs, &mut state.new_regs )?;
        *initial_address = Some( result.initial_address );
        *ra_address = result.ra_address;
        let cfa = result.cfa?;

        let mut recovered_return_address = false;
        for &(register, value) in &state.new_regs {
            regs.append( register, value );

            recovered_return_address = recovered_return_address || register == dwarf::X30;
        }

        regs.append( dwarf::X31, cfa );

        debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", Self::register_name( dwarf::X31 ), nth_frame + 1, cfa );

        if recovered_return_address || nth_frame == 0 {
            regs.pc = regs.x30;
            Some( UnwindStatus::InProgress )
        } else {
            debug!( "Previous frame not found: failed to determine the return address of frame #{}", nth_frame + 1 );
            Some( UnwindStatus::Finished )
        }
    }
}
