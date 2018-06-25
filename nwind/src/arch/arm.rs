use gimli::LittleEndian;
use dwarf_regs::DwarfRegs;
use arch::Architecture;
use address_space::MemoryReader;
use unwind_context::UnwindFrame;
use types::{Endianness, Bitness};
use arm_extab::VirtualMachine as EhVm;
use arm_extab::Error as EhError;

// Source: DWARF for the ARM Architecture
//         http://infocenter.arm.com/help/topic/com.arm.doc.ihi0040b/IHI0040B_aadwarf.pdf
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
}

#[allow(dead_code)]
pub struct Arch {}

impl Architecture for Arch {
    const NAME: &'static str = "arm";
    const ENDIANNESS: Endianness = Endianness::LittleEndian;
    const BITNESS: Bitness = Bitness::B32;

    type Endianity = LittleEndian;
    type State = ();

    fn register_name_str( register: u16 ) -> Option< &'static str > {
        use self::dwarf::*;

        let name = match register {
            R0 => "R0",
            R1 => "R1",
            R2 => "R2",
            R3 => "R3",
            R4 => "R4",
            R5 => "R5",
            R6 => "R6",
            R7 => "R7",
            R8 => "R8",
            R9 => "R9",
            R10 => "R10",
            R11 => "FP",
            R12 => "IP",
            R13 => "SP",
            R14 => "LR",
            R15 => "PC",
            _ => return None
        };

        Some( name )
    }

    #[inline]
    fn get_stack_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::R13 )
    }

    #[inline]
    fn get_instruction_pointer( regs: &DwarfRegs ) -> Option< u64 > {
        regs.get( dwarf::R15 )
    }

    #[inline]
    fn initial_state() -> Self::State {
        ()
    }

    #[inline]
    fn unwind< M: MemoryReader< Self > >( nth_frame: usize, memory: &M, _state: &mut Self::State, current_frame: &mut UnwindFrame< Self >, next_frame: &mut UnwindFrame< Self >, panic_on_partial_backtrace: bool ) -> bool {
        let mut vm = EhVm::new();

        let binary = current_frame.binary.as_ref().unwrap();

        let exidx_range = match binary.arm_exidx_range() {
            Some( exidx_range ) => exidx_range,
            None => {
                debug!( "Previous frame not found: binary '{}' is missing .ARM.exidx section", binary.name() );
                return false
            }
        };

        let exidx_base = match binary.arm_exidx_address() {
            Some( exidx_address ) => exidx_address,
            None => {
                debug!( "Previous frame not found: binary '{}' .ARM.exidx address is not known", binary.name() );
                return false
            }
        };

        let extab_base = match binary.arm_extab_address() {
            Some( extab_address ) => extab_address,
            None => {
                if binary.arm_extab_range().is_none() {
                    0
                } else {
                    debug!( "Previous frame not found: binary '{}' .ARM.extab address is not known", binary.name() );
                    return false
                }
            }
        };

        let address = current_frame.regs.get( dwarf::R15 ).unwrap() as u32;
        let exidx = &binary.as_bytes()[ exidx_range ];
        let extab = if let Some( extab_range ) = binary.arm_extab_range() {
            &binary.as_bytes()[ extab_range ]
        } else {
            b""
        };

        for (register, value) in current_frame.regs.iter() {
            match register {
                dwarf::R15 |
                dwarf::R13 => continue,
                _ => next_frame.regs.append( register ,value )
            }
        }

        let mut initial_address = None;
        let result = vm.unwind(
            memory,
            &current_frame.regs,
            &mut initial_address,
            &mut next_frame.regs,
            exidx,
            extab,
            exidx_base as u32,
            extab_base as u32,
            address,
            nth_frame == 0
        );

        if let Some( initial_address ) = initial_address {
            debug!( "Initial address for frame #{}: 0x{:08X}", nth_frame, initial_address );
            current_frame.initial_address = Some( initial_address as u64 );
        }

        match result {
            Ok( () ) => return true,
            Err( EhError::EndOfStack ) => {
                debug!( "Previous frame not found: EndOfStack" );
                return false;
            },
            Err( error ) => {
                debug!( "Previous frame not found: {:?}", error );
                if panic_on_partial_backtrace {
                    panic!( "Partial backtrace!" );
                }
                return false;
            }
        }
    }
}
