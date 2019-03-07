use gimli::BigEndian;
use arch::{Architecture, Registers, UnwindStatus};
use address_space::MemoryReader;
use frame_descriptions::{ContextCache, UnwindInfoCache};
use types::{Endianness, Bitness};
use dwarf::dwarf_unwind;

pub mod dwarf {
    pub const R0: u16 = 0;
    pub const R1: u16 = 1;
    pub const R2: u16 = 2;
    pub const R3: u16 = 3;
    pub const R4: u16 = 4;
    pub const R5: u16 = 5;
    pub const R6: u16 = 6;
    pub const R7: u16 = 7;
    pub const R8: u16 = 8;
    pub const R9: u16 = 9;
    pub const R10: u16 = 10;
    pub const R11: u16 = 11;
    pub const R12: u16 = 12;
    pub const R13: u16 = 13;
    pub const R14: u16 = 14;
    pub const R15: u16 = 15;
    pub const R16: u16 = 16;
    pub const R17: u16 = 17;
    pub const R18: u16 = 18;
    pub const R19: u16 = 19;
    pub const R20: u16 = 20;
    pub const R21: u16 = 21;
    pub const R22: u16 = 22;
    pub const R23: u16 = 23;
    pub const R24: u16 = 24;
    pub const R25: u16 = 25;
    pub const R26: u16 = 26;
    pub const R27: u16 = 27;
    pub const R28: u16 = 28;
    pub const R29: u16 = 29;
    pub const R30: u16 = 30;
    pub const R31: u16 = 31;

    pub const PC: u16 = 34;
}

static REGS: &'static [u16] = &[
    dwarf::R0,
    dwarf::R1,
    dwarf::R2,
    dwarf::R3,
    dwarf::R4,
    dwarf::R5,
    dwarf::R6,
    dwarf::R7,
    dwarf::R8,
    dwarf::R9,
    dwarf::R10,
    dwarf::R11,
    dwarf::R12,
    dwarf::R13,
    dwarf::R14,
    dwarf::R15,
    dwarf::R16,
    dwarf::R17,
    dwarf::R18,
    dwarf::R19,
    dwarf::R20,
    dwarf::R21,
    dwarf::R22,
    dwarf::R23,
    dwarf::R24,
    dwarf::R25,
    dwarf::R26,
    dwarf::R27,
    dwarf::R28,
    dwarf::R29,
    dwarf::R30,
    dwarf::R31,
    dwarf::PC
];

#[repr(C)]
#[derive(Clone, Default)]
pub struct Regs {
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
    r6: u64,
    r7: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    r16: u64,
    r17: u64,
    r18: u64,
    r19: u64,
    r20: u64,
    r21: u64,
    r22: u64,
    r23: u64,
    r24: u64,
    r25: u64,
    r26: u64,
    r27: u64,
    r28: u64,
    r29: u64,
    r30: u64,
    r31: u64,
    _padding: [u64; 2],
    pc: u64,

    mask: u64
}

unsafe_impl_registers!( Regs, REGS );
impl_local_regs!( Regs, "mips64", get_regs_mips64 );
impl_regs_debug!( Regs, REGS, Arch );

#[allow(dead_code)]
pub struct Arch {}

#[doc(hidden)]
pub struct State {
    ctx_cache: ContextCache< BigEndian >,
    unwind_cache: UnwindInfoCache,
    new_regs: Vec< (u16, u64) >
}

impl Architecture for Arch {
    const NAME: &'static str = "mips64";
    const ENDIANNESS: Endianness = Endianness::BigEndian;
    const BITNESS: Bitness = Bitness::B64;
    const RETURN_ADDRESS_REG: u16 = dwarf::R31;

    type Endianity = BigEndian;
    type State = State;
    type Regs = Regs;

    fn register_name_str( register: u16 ) -> Option< &'static str > {
        use self::dwarf::*;

        let name = match register {
            R0 => "R0",
            R1 => "AT",
            R2 => "V0",
            R3 => "V1",
            R4 => "A0",
            R5 => "A1",
            R6 => "A2",
            R7 => "A3",
            R8 => "A4",
            R9 => "A5",
            R10 => "A6",
            R11 => "A7",
            R12 => "T0",
            R13 => "T1",
            R14 => "T2",
            R15 => "T3",
            R16 => "S0",
            R17 => "S1",
            R18 => "S2",
            R19 => "S3",
            R20 => "S4",
            R21 => "S5",
            R22 => "S6",
            R23 => "S7",
            R24 => "T8",
            R25 => "T9",
            R26 => "K0",
            R27 => "K1",
            R28 => "GP",
            R29 => "SP",
            R30 => "FP",
            R31 => "RA",
            PC => "PC",
            _ => return None
        };

        Some( name )
    }

    #[inline]
    fn get_stack_pointer< R: Registers >( regs: &R ) -> Option< u64 > {
        regs.get( dwarf::R29 )
    }

    #[inline]
    fn get_instruction_pointer( regs: &Self::Regs ) -> Option< u64 > {
        regs.get( dwarf::PC )
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
        regs_next: &mut Self::Regs,
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
            regs_next.append( register, value );

            recovered_return_address = recovered_return_address || register == dwarf::R31;
        }

        regs.append( dwarf::R29, cfa );
        regs_next.append( dwarf::R29, cfa );

        debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", Self::register_name( dwarf::R29 ), nth_frame + 1, cfa );

        if recovered_return_address || nth_frame == 0 {
            regs.pc = regs.r31;
            regs_next.pc = regs.r31;
            Some( UnwindStatus::InProgress )
        } else {
            debug!( "Previous frame not found: failed to determine the return address of frame #{}", nth_frame + 1 );
            Some( UnwindStatus::Finished )
        }
    }
}
