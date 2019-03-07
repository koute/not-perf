use gimli::LittleEndian;
use arch::{Architecture, Registers, UnwindStatus};
use address_space::{MemoryReader, lookup_binary};
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
    dwarf::R15
];

#[repr(C)]
#[derive(Clone, Default)]
pub struct Regs {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    r5: u32,
    r6: u32,
    r7: u32,
    r8: u32,
    r9: u32,
    r10: u32,
    r11: u32,
    r12: u32,
    r13: u32,
    r14: u32,
    r15: u32,
    mask: u64
}

unsafe_impl_registers!( Regs, REGS, u32 );
impl_local_regs!( Regs, "arm", get_regs_arm );
impl_regs_debug!( Regs, REGS, Arch );

#[allow(dead_code)]
pub struct Arch {}

impl Architecture for Arch {
    const NAME: &'static str = "arm";
    const ENDIANNESS: Endianness = Endianness::LittleEndian;
    const BITNESS: Bitness = Bitness::B32;
    const RETURN_ADDRESS_REG: u16 = dwarf::R15;

    type Endianity = LittleEndian;
    type State = ();
    type Regs = Regs;

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
    fn get_stack_pointer< R: Registers >( regs: &R ) -> Option< u64 > {
        regs.get( dwarf::R13 )
    }

    #[inline]
    fn get_instruction_pointer( regs: &Self::Regs ) -> Option< u64 > {
        regs.get( dwarf::R15 )
    }

    #[inline]
    fn initial_state() -> Self::State {
        ()
    }

    fn unwind< M: MemoryReader< Self > >(
        nth_frame: usize,
        memory: &M,
        _state: &mut Self::State,
        regs: &mut Self::Regs,
        regs_next: &mut Self::Regs,
        initial_address: &mut Option< u64 >,
        ra_address: &mut Option< u64 >
    ) -> Option< UnwindStatus > {
        let binary = lookup_binary( nth_frame, memory, regs )?;
        let binary_data = binary.data()?;

        let exidx_range = match binary_data.arm_exidx_range() {
            Some( exidx_range ) => exidx_range,
            None => {
                debug!( "Previous frame not found: binary '{}' is missing .ARM.exidx section", binary_data.name() );
                return None;
            }
        };

        let exidx_base = match binary.arm_exidx_address() {
            Some( exidx_address ) => exidx_address,
            None => {
                debug!( "Previous frame not found: binary '{}' .ARM.exidx address is not known", binary_data.name() );
                return None;
            }
        };

        let extab_base = match binary.arm_extab_address() {
            Some( extab_address ) => extab_address,
            None => {
                if binary_data.arm_extab_range().is_none() {
                    0
                } else {
                    debug!( "Previous frame not found: binary '{}' .ARM.extab address is not known", binary_data.name() );
                    return None;
                }
            }
        };

        let address = regs.get( dwarf::R15 ).unwrap() as u32;
        let exidx = &binary_data.as_bytes()[ exidx_range ];
        let extab = if let Some( extab_range ) = binary_data.arm_extab_range() {
            &binary_data.as_bytes()[ extab_range ]
        } else {
            b""
        };

        for (register, value) in regs.iter() {
            match register {
                dwarf::R15 |
                dwarf::R13 => continue,
                _ => regs_next.append( register ,value )
            }
        }

        let mut initial_address_u32 = None;
        let mut vm = EhVm::new();
        let result = vm.unwind(
            memory,
            regs,
            &mut initial_address_u32,
            regs_next,
            exidx,
            extab,
            exidx_base as u32,
            extab_base as u32,
            address,
            nth_frame == 0
        );

        if let Some( initial_address_u32 ) = initial_address_u32 {
            debug!( "Initial address for frame #{}: 0x{:08X}", nth_frame, initial_address_u32 );
            *initial_address = Some( initial_address_u32 as _ )
        }

        match result {
            Ok( () ) => return Some( UnwindStatus::InProgress ),
            Err( EhError::EndOfStack ) => {
                debug!( "Previous frame not found: EndOfStack" );
                Some( UnwindStatus::Finished )
            },
            Err( error ) => {
                debug!( "Previous frame not found: {:?}", error );
                None
            }
        }
    }
}
