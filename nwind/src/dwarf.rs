use gimli::{
    self,
    RegisterRule,
    CfaRule
};

use arch::Architecture;
use address_space::MemoryReader;
use frame_descriptions::ContextCache;
use unwind_context::UnwindFrame;

fn dwarf_get_reg< A: Architecture, M: MemoryReader< A >, R: gimli::Reader >( nth_frame: usize, register: u16, memory: &M, cfa_value: u64, rule: &RegisterRule< R > ) -> Option< u64 > {
    let value = match *rule {
        RegisterRule::Offset( offset ) => {
            let value_address = (cfa_value as i64 + offset) as u64;
            let value = match memory.get_pointer_at_address( A::ENDIANNESS, A::BITNESS, value_address ) {
                Some( value ) => value,
                None => {
                    debug!( "Cannot grab register {:?} for frame #{}: failed to fetch it from 0x{:016X}", A::register_name( register ), nth_frame, value_address );
                    return None;
                }
            };
            value
        },
        ref rule => {
            error!( "Handling for this register rule is unimplemented: {:?}", rule );
            return None;
        }
    };

    debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", A::register_name( register ), nth_frame, value );
    Some( value )
}

pub fn dwarf_unwind< A: Architecture, M: MemoryReader< A > >( nth_frame: usize, memory: &M, ctx_cache: &mut ContextCache< A::Endianity >, frame: &mut UnwindFrame< A >, next_frame: &mut UnwindFrame< A > ) -> bool {
    let address = A::get_instruction_pointer( &frame.regs ).expect( "DWARF unwind: no instruction pointer" );

    let binary = frame.binary.as_ref().expect( "DWARF unwind: no associated binary" );
    let unwind_info = match binary.lookup_unwind_row( ctx_cache, address ) {
        Some( unwind_info ) => unwind_info,
        None => {
            debug!( "No unwind info for address 0x{:016X} in '{}'", address, binary.name() );
            return false;
        }
    };

    let initial_address = ((address as i64) + unwind_info.offset_to_initial_address()) as u64;
    frame.initial_address = Some( initial_address );
    debug!( "Initial address for frame #{}: 0x{:016X}", nth_frame, initial_address );

    let cfa = unwind_info.cfa();
    debug!( "Grabbing CFA for frame #{}: {:?}", nth_frame, cfa );

    let cfa_value = match *cfa {
        CfaRule::RegisterAndOffset { register: cfa_register, offset: cfa_offset } => {
            let cfa_register_value = match frame.regs.get( cfa_register as _ ) {
                Some( cfa_register_value ) => cfa_register_value,
                None => {
                    debug!( "Failed to fetch CFA for frame #{}: failed to fetch register {:?}", nth_frame, A::register_name( cfa_register as _ ) );
                    return false;
                }
            };

            let value: u64 = (cfa_register_value as i64 + cfa_offset) as u64;
            debug!( "Got CFA for frame #{}: {:?} (0x{:016X}) + {} = 0x{:016X}", nth_frame, A::register_name( cfa_register as _ ), cfa_register_value, cfa_offset, value );
            value
        },
        ref cfa => {
            error!( "Handling for this CFA rule is unimplemented: {:?}", cfa );
            return false;
        }
    };

    frame.cfa = Some( cfa_value );
    for &(register, ref rule) in unwind_info.registers() {
        debug!( "  Register {:?}: {:?}", A::register_name( register as _ ), rule );

        if let Some( value ) = dwarf_get_reg( nth_frame + 1, register as u16, memory, cfa_value, rule ) {
            next_frame.regs.append( register as u16, value );
        }
    }

    true
}
