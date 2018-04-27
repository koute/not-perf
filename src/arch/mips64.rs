use gimli::BigEndian;
use dwarf_regs::DwarfRegs;
use arch::Architecture;
use address_space::MemoryReader;
use unwind_context::UnwindFrame;
use frame_descriptions::ContextCache;
use archive::{Endianness, Bitness};
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

#[allow(dead_code)]
pub struct Arch {}

impl Architecture for Arch {
    const NAME: &'static str = "mips64";
    const ENDIANNESS: Endianness = Endianness::BigEndian;
    const BITNESS: Bitness = Bitness::B64;

    type Endianity = BigEndian;
    type State = ContextCache< BigEndian >;

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
    fn get_stack_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::R29 )
    }

    #[inline]
    fn get_instruction_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::PC )
    }

    #[inline]
    fn initial_state() -> Self::State {
        ContextCache::new()
    }

    #[inline]
    fn unwind< M: MemoryReader< Self > >( nth_frame: usize, memory: &M, state: &mut Self::State, current_frame: &mut UnwindFrame< Self >, next_frame: &mut UnwindFrame< Self >, _panic_on_partial_backtrace: bool ) -> bool {
        for (register, value) in current_frame.regs.iter() {
            match register {
                dwarf::PC |
                dwarf::R31 |
                dwarf::R29 => continue,
                _ => next_frame.regs.append( register ,value )
            }
        }

        if !dwarf_unwind( nth_frame, memory, state, current_frame, next_frame ) {
            return false;
        }

        let sp = current_frame.cfa.unwrap();
        next_frame.regs.append( dwarf::R29, sp );
        next_frame.regs.append( dwarf::R30, sp );
        debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", Self::register_name( dwarf::R29 ), nth_frame + 1, sp );

        if let Some( return_address ) = next_frame.regs.get( dwarf::R31 ) {
            next_frame.regs.append( dwarf::PC, return_address );
            true
        } else if nth_frame == 0 {
            let return_address = current_frame.regs.get( dwarf::R31 ).unwrap();
            next_frame.regs.append( dwarf::PC, return_address );
            true
        } else {
            debug!( "Previous frame not found: failed to determine the return address of frame #{}", nth_frame + 1 );
            false
        }
    }
}
