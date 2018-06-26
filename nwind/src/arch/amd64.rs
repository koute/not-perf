use std::mem;

use gimli::{RegisterRule, CfaRule, LittleEndian};

use dwarf_regs::DwarfRegs;
use arch::Architecture;
use address_space::MemoryReader;
use unwind_context::UnwindFrame;
use frame_descriptions::{ContextCache, UnwindInfoCache};
use types::{Endianness, Bitness};
use dwarf::dwarf_unwind;

// Source: https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI
pub mod dwarf {
    pub const RAX: u16 = 0;
    pub const RDX: u16 = 1;
    pub const RCX: u16 = 2;
    pub const RBX: u16 = 3;
    pub const RSI: u16 = 4;
    pub const RDI: u16 = 5;
    pub const RBP: u16 = 6;
    pub const RSP: u16 = 7;
    pub const R8: u16 = 8;
    pub const R9: u16 = 9;
    pub const R10: u16 = 10;
    pub const R11: u16 = 11;
    pub const R12: u16 = 12;
    pub const R13: u16 = 13;
    pub const R14: u16 = 14;
    pub const R15: u16 = 15;
    pub const RETURN_ADDRESS: u16 = 16;
    pub const FLAGS: u16 = 49;
    pub const CS: u16 = 51;
    pub const SS: u16 = 52;
}

#[allow(dead_code)]
pub struct Arch {}

fn guess_ebp< M: MemoryReader< Arch > >( nth_frame: usize, memory: &M, ctx_cache: &mut ContextCache< LittleEndian >, current_frame: &mut UnwindFrame< Arch > ) -> Option< u64 > {
    // This is a hacky workaround for the fact that Linux's perf events tend to return us
    // invalid RBP values (all FFs) if the call chain goes through the kernel space -> user space
    // boundary, so we try to figure it out some other way.

    debug!( "Trying to guess RBP for frame #{}...", nth_frame );

    let rip = current_frame.regs.get( dwarf::RETURN_ADDRESS )?;
    let binary = current_frame.binary.as_ref()?.clone();
    let unwind_info = binary.lookup_unwind_row( ctx_cache, rip )?;

    let cfa_offset = match unwind_info.cfa() {
        CfaRule::RegisterAndOffset { register: cfa_register, offset: cfa_offset } if cfa_register as u16 == dwarf::RBP => cfa_offset,
        _ => return None
    };

    // What this rule means is that:
    //   previous.RBP == *(current.RBP + rbp_offset)
    let rbp_offset = match unwind_info.register( dwarf::RBP as _ ) {
        RegisterRule::Offset( offset ) => offset + cfa_offset,
        _ => return None
    };

    let ra_offset = match unwind_info.register( dwarf::RETURN_ADDRESS as _ ) {
        RegisterRule::Offset( offset ) => offset + cfa_offset,
        _ => return None
    };

    mem::drop( unwind_info );

    let rsp = current_frame.regs.get( dwarf::RSP )?;

    let mut rbp = rsp;
    for _ in 0..32 {
        let candidate_ra = memory.get_u64_at_address( Endianness::LittleEndian, (rbp as i64 + ra_offset) as u64 )?;
        let candidate_rbp = memory.get_u64_at_address( Endianness::LittleEndian, (rbp as i64 + rbp_offset) as u64 )?;

        let valid_ra = memory.get_region_at_address( candidate_ra ).map( |region| region.is_executable() ).unwrap_or( false );
        let valid_rbp = memory.is_stack_address( candidate_rbp );
        if valid_rbp && valid_ra {
            debug!( "Guessed RBP=0x{:016X} based on stack scanning", rbp );
            return Some( rbp );
        }
        rbp += 8;
    }

    None
}

#[doc(hidden)]
pub struct State {
    ctx_cache: ContextCache< LittleEndian >,
    unwind_cache: UnwindInfoCache
}

impl Architecture for Arch {
    const NAME: &'static str = "amd64";
    const ENDIANNESS: Endianness = Endianness::LittleEndian;
    const BITNESS: Bitness = Bitness::B64;

    type Endianity = LittleEndian;
    type State = State;

    fn register_name_str( register: u16 ) -> Option< &'static str > {
        use self::dwarf::*;

        let name = match register {
            RAX => "RAX",
            RDX => "RDX",
            RCX => "RCX",
            RBX => "RBX",
            RSI => "RSI",
            RDI => "RDI",
            RBP => "RBP",
            RSP => "RSP",
            R8 => "R8",
            R9 => "R9",
            R10 => "R10",
            R11 => "R11",
            R12 => "R12",
            R13 => "R13",
            R14 => "R14",
            R15 => "R15",
            RETURN_ADDRESS => "RA",
            FLAGS => "EFLAGS",
            CS => "CS",
            SS => "SS",
            _ => return None
        };

        Some( name )
    }

    #[inline]
    fn get_stack_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::RSP )
    }

    #[inline]
    fn get_instruction_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::RETURN_ADDRESS )
    }

    #[inline]
    fn initial_state() -> Self::State {
        State {
            ctx_cache: ContextCache::new(),
            unwind_cache: UnwindInfoCache::new()
        }
    }

    #[inline]
    fn unwind< M: MemoryReader< Self > >( nth_frame: usize, memory: &M, state: &mut Self::State, current_frame: &mut UnwindFrame< Self >, next_frame: &mut UnwindFrame< Self >, panic_on_partial_backtrace: bool ) -> bool {
        if current_frame.regs.get( dwarf::RBP ).is_none() {
            if !current_frame.assign_binary( nth_frame, memory ) {
                return false;
            }

            if let Some( rbp ) = guess_ebp( nth_frame, memory, &mut state.ctx_cache, current_frame ) {
                current_frame.regs.append( dwarf::RBP, rbp );
            }
        }

        for (register, value) in current_frame.regs.iter() {
            match register {
                dwarf::RSP |
                dwarf::RETURN_ADDRESS => continue,
                _ => next_frame.regs.append( register, value )
            }
        }

        if !dwarf_unwind( nth_frame, memory, &mut state.ctx_cache, &mut state.unwind_cache, current_frame, next_frame ) {
            if panic_on_partial_backtrace {
                panic!( "Partial backtrace!" );
            }
            return false;
        }

        let rsp = current_frame.cfa.unwrap();
        next_frame.regs.append( dwarf::RSP, rsp );
        debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", Self::register_name( dwarf::RSP ), nth_frame + 1, rsp );

        if let Some( _ ) = next_frame.regs.get( dwarf::RETURN_ADDRESS ) {
            true
        } else {
            debug!( "Previous frame not found: failed to determine the return address of frame #{}", nth_frame + 1 );
            false
        }
    }
}
