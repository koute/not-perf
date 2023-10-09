use gimli::{RegisterRule, CfaRule, LittleEndian};

use crate::arch::{Architecture, Registers, UnwindStatus};
use crate::address_space::{MemoryReader, Binary, lookup_binary};
use crate::frame_descriptions::{ContextCache, UnwindInfoCache};
use crate::types::{Endianness, Bitness};
use crate::dwarf::dwarf_unwind;

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

static REGS: &'static [u16] = &[
    dwarf::RAX,
    dwarf::RDX,
    dwarf::RCX,
    dwarf::RBX,
    dwarf::RSI,
    dwarf::RDI,
    dwarf::RBP,
    dwarf::RSP,
    dwarf::R8,
    dwarf::R9,
    dwarf::R10,
    dwarf::R11,
    dwarf::R12,
    dwarf::R13,
    dwarf::R14,
    dwarf::R15,
    dwarf::RETURN_ADDRESS,
    dwarf::FLAGS,
    dwarf::CS,
    dwarf::SS
];

#[repr(C)]
#[derive(Clone, Default)]
pub struct Regs {
    rax: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    _padding_1: [u64; 32],
    flags: u64,
    _padding_2: u64,
    cs: u64,
    ss: u64,

    mask: u64
}

unsafe_impl_registers!( Regs, REGS, u64 );
impl_local_regs!( Regs, "x86_64", get_regs_amd64 );
impl_regs_debug!( Regs, REGS, Arch );

#[allow(dead_code)]
pub struct Arch {}

fn guess_ebp< M: MemoryReader< Arch > >( nth_frame: usize, memory: &M, ctx_cache: &mut ContextCache< LittleEndian >, regs: &<Arch as Architecture>::Regs, binary: &Binary< Arch > ) -> Option< u64 > {
    // This is a hacky workaround for the fact that Linux's perf events tend to return us
    // invalid RBP values (all FFs) if the call chain goes through the kernel space -> user space
    // boundary, so we try to figure it out some other way.

    debug!( "Trying to guess RBP for frame #{}...", nth_frame );

    let rip = regs.get( dwarf::RETURN_ADDRESS )?;
    let unwind_info = binary.lookup_unwind_row( ctx_cache, rip )?;

    let cfa_offset = match unwind_info.cfa() {
        CfaRule::RegisterAndOffset { register: cfa_register, offset: cfa_offset } if cfa_register == gimli::X86_64::RBP => cfa_offset,
        _ => return None
    };

    // What this rule means is that:
    //   previous.RBP == *(current.RBP + rbp_offset)
    let rbp_offset = match unwind_info.register( gimli::X86_64::RBP ) {
        RegisterRule::Offset( offset ) => offset + cfa_offset,
        _ => return None
    };

    let ra_offset = match unwind_info.register( gimli::X86_64::RA ) {
        RegisterRule::Offset( offset ) => offset + cfa_offset,
        _ => return None
    };

    let rsp = regs.get( dwarf::RSP )?;

    let mut rbp = rsp;
    for _ in 0..32 {
        let candidate_ra = memory.get_pointer_at_address( (rbp as i64 + ra_offset) as u64 )?;
        let candidate_rbp = memory.get_pointer_at_address( (rbp as i64 + rbp_offset) as u64 )?;

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
    unwind_cache: UnwindInfoCache,
    new_regs: Vec< (u16, u64) >
}

impl Architecture for Arch {
    const NAME: &'static str = "amd64";
    const ENDIANNESS: Endianness = Endianness::LittleEndian;
    const BITNESS: Bitness = Bitness::B64;
    const STACK_POINTER_REG: u16 = dwarf::RSP;
    const INSTRUCTION_POINTER_REG: u16 = dwarf::RETURN_ADDRESS;
    const RETURN_ADDRESS_REG: u16 = dwarf::RETURN_ADDRESS;

    type Endianity = LittleEndian;
    type State = State;
    type Regs = Regs;
    type RegTy = u64;

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
    fn initial_state() -> Self::State {
        State {
            ctx_cache: ContextCache::new(),
            unwind_cache: UnwindInfoCache::new(),
            new_regs: Vec::with_capacity( 32 )
        }
    }

    fn clear_cache( state: &mut Self::State ) {
        state.unwind_cache.clear();
    }

    fn unwind< M: MemoryReader< Self > >(
        nth_frame: usize,
        memory: &M,
        state: &mut Self::State,
        regs: &mut Self::Regs,
        initial_address: &mut Option< u64 >,
        ra_address: &mut Option< u64 >
    ) -> Option< UnwindStatus > {
        if !regs.contains( dwarf::RBP ) {
            let binary = lookup_binary( nth_frame, memory, regs )?;
            if let Some( rbp ) = guess_ebp( nth_frame, memory, &mut state.ctx_cache, regs, binary ) {
                regs.append( dwarf::RBP, rbp );
            }
        }

        let result = match dwarf_unwind( nth_frame, memory, &mut state.ctx_cache, &mut state.unwind_cache, regs, &mut state.new_regs ) {
            Some( result ) => result,
            None => {
                if let Some( rbp ) = regs.get( dwarf::RBP ) {
                    if let Some( next_rbp ) = memory.get_pointer_at_address( rbp ) {
                        if let Some( next_rip ) = memory.get_pointer_at_address( rbp + 8 ) {
                            trace!(
                                "RBP-based unwinding: RBP: {:x} -> {:x}, RIP: {:x} -> {:x}",
                                rbp,
                                next_rbp,
                                regs.get( dwarf::RETURN_ADDRESS ).expect( "no RIP" ),
                                next_rip
                            );

                            if next_rbp != rbp {
                                regs.clear();
                                regs.append( dwarf::RSP, rbp + 16 );
                                regs.append( dwarf::RBP, next_rbp );
                                regs.append( dwarf::RETURN_ADDRESS, next_rip );
                                *ra_address = Some( next_rip );
                                return Some( UnwindStatus::InProgress );
                            }
                        }
                    }
                }
                return None;
            }
        };
        *initial_address = Some( result.initial_address );
        *ra_address = result.ra_address;
        let cfa = result.cfa?;

        let mut recovered_return_address = false;
        for &(register, value) in &state.new_regs {
            regs.append( register, value );

            recovered_return_address = recovered_return_address || register == dwarf::RETURN_ADDRESS;
        }

        regs.append( dwarf::RSP, cfa );

        debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", Self::register_name( dwarf::RSP ), nth_frame + 1, cfa );

        if !recovered_return_address {
            debug!( "Previous frame not found: failed to determine the return address of frame #{}", nth_frame + 1 );
            return Some( UnwindStatus::Finished );
        }

        Some( UnwindStatus::InProgress )
    }
}
