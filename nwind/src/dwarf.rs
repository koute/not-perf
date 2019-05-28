use gimli::{
    self,
    RegisterRule,
    CfaRule,
    EvaluationResult,
    Format,
    Value,
    Location,
    Piece
};

use crate::arch::{Architecture, Registers, TryInto};
use crate::address_space::{MemoryReader, lookup_binary};
use crate::frame_descriptions::{UnwindInfo, ContextCache, UnwindInfoCache};
use crate::types::Bitness;

pub struct DwarfResult {
    pub initial_address: u64,
    pub cfa: Option< u64 >,
    pub ra_address: Option< u64 >
}

fn dwarf_get_reg< A: Architecture, M: MemoryReader< A >, R: gimli::Reader >( nth_frame: usize, register: u16, memory: &M, cfa_value: u64, rule: &RegisterRule< R > ) -> Option< (u64, u64) > {
    let (value_address, value) = match *rule {
        RegisterRule::Offset( offset ) => {
            let value_address = (cfa_value as i64 + offset) as u64;
            debug!( "Register {:?} at frame #{} is at 0x{:016X}", A::register_name( register ), nth_frame, value_address );

            let value = match memory.get_pointer_at_address( value_address.try_into().unwrap() ) {
                Some( value ) => value,
                None => {
                    debug!( "Cannot grab register {:?} for frame #{}: failed to fetch it from 0x{:016X}", A::register_name( register ), nth_frame, value_address );
                    return None;
                }
            };
            (value_address, value)
        },
        ref rule => {
            error!( "Handling for this register rule is unimplemented: {:?}", rule );
            return None;
        }
    };

    debug!( "Register {:?} at frame #{} is equal to 0x{:016X}", A::register_name( register ), nth_frame, value );
    Some( (value_address, value.into()) )
}

pub fn dwarf_unwind_impl< A: Architecture, M: MemoryReader< A > >(
    nth_frame: usize,
    memory: &M,
    unwind_cache: Option< &mut UnwindInfoCache >,
    regs: &A::Regs,
    unwind_info: &UnwindInfo< A::Endianity >,
    next_regs: &mut Vec< (u16, u64) >,
    ra_address: &mut Option< u64 >
) -> Option< u64 > {
    debug!( "Initial address for frame #{}: 0x{:016X}", nth_frame, unwind_info.initial_absolute_address() );

    let cfa = unwind_info.cfa();
    debug!( "Grabbing CFA for frame #{}: {:?}", nth_frame, cfa );

    let cfa_value = match cfa {
        CfaRule::RegisterAndOffset { register: cfa_register, offset: cfa_offset } => {
            let cfa_register_value = match regs.get( cfa_register.0 ) {
                Some( cfa_register_value ) => cfa_register_value.into(),
                None => {
                    debug!( "Failed to fetch CFA for frame #{}: failed to fetch register {:?}", nth_frame, A::register_name( cfa_register.0 ) );
                    return None;
                }
            };

            let value: u64 = (cfa_register_value as i64 + cfa_offset) as u64;
            debug!( "Got CFA for frame #{}: {:?} (0x{:016X}) + {} = 0x{:016X}", nth_frame, A::register_name( cfa_register.0 ), cfa_register_value, cfa_offset, value );
            value
        },
        CfaRule::Expression( expr ) => {
            let address_size = match A::BITNESS {
                Bitness::B32 => 4,
                Bitness::B64 => 8,
            };
            let encoding = gimli::Encoding {
                // TODO: use CIE format?
                format: Format::Dwarf32,
                // This doesn't currently matter for expressions.
                version: 0,
                address_size,
            };

            let mut evaluation = expr.evaluation( encoding );
            let mut result = evaluation.evaluate();
            let value;
            loop {
                match result {
                    Ok( EvaluationResult::Complete ) => {
                        let mut pieces = evaluation.result();
                        if pieces.len() == 1 {
                            match pieces.pop().unwrap() {
                                Piece {
                                    size_in_bits: None,
                                    bit_offset: None,
                                    location: Location::Address { address },
                                    ..
                                } => {
                                    value = address;
                                    break;
                                },
                                piece => {
                                    error!( "Unhandled CFA evaluation result: {:?}", piece );
                                    return None;
                                }
                            }
                        } else {
                            error!( "Unhandled CFA evaluation result: {:?}", pieces );
                            return None;
                        }
                    },
                    Ok( EvaluationResult::RequiresRegister { register, .. } ) => {
                        let reg_value = match regs.get( register.0 ) {
                            Some( reg_value ) => reg_value.into(),
                            None => {
                                error!( "Failed to evaluate CFA rule due to a missing value of register {:?}", A::register_name( register.0 ) );
                                return None;
                            }
                        };

                        result = evaluation.resume_with_register( Value::Generic( reg_value ) );
                    },
                    Ok( result ) => {
                        error!( "Failed to evaluate CFA rule due to unhandled requirement: {:?}", result );
                        return None;
                    },
                    Err( error ) => {
                        error!( "Failed to evaluate CFA rule: {:?}", error );
                        return None;
                    }
                }
            }

            debug!( "Evaluated CFA for frame #{}: 0x{:016X}", nth_frame, value );
            value
        },
    };

    let mut cacheable = true;
    unwind_info.each_register( |(register, rule)| {
        debug!( "  Register {:?}: {:?}", A::register_name( register.0 ), rule );

        if let Some( (value_address, value) ) = dwarf_get_reg( nth_frame + 1, register.0, memory, cfa_value, rule ) {
            if register.0 == A::RETURN_ADDRESS_REG {
                *ra_address = Some( value_address );
            }

            next_regs.push( (register.0, value) );
        } else {
            cacheable = false;
        }
    });

    if cacheable {
        if let Some( unwind_cache ) = unwind_cache {
            unwind_info.cache_into( unwind_cache );
        }
    }

    Some( cfa_value )
}

pub fn dwarf_unwind< A: Architecture, M: MemoryReader< A > >(
    nth_frame: usize,
    memory: &M,
    ctx_cache: &mut ContextCache< A::Endianity >,
    unwind_cache: &mut UnwindInfoCache,
    regs: &A::Regs,
    next_regs: &mut Vec< (u16, u64) >
) -> Option< DwarfResult > {
    next_regs.clear();

    let address = A::get_instruction_pointer( regs ).expect( "DWARF unwind: no instruction pointer" );
    let address = if nth_frame == 0 { address } else { address - 1 };
    if let Some( unwind_info ) = unwind_cache.lookup( address ) {
        let mut ra_address = None;
        let cfa = dwarf_unwind_impl(
            nth_frame,
            memory,
            None,
            regs,
            &unwind_info,
            next_regs,
            &mut ra_address
        );

        return Some( DwarfResult {
            initial_address: unwind_info.initial_absolute_address(),
            cfa,
            ra_address
        });
    }

    let binary = lookup_binary( nth_frame, memory, regs )?;
    let result = binary.lookup_unwind_row( ctx_cache, address, |unwind_info| {
        let mut ra_address = None;
        let cfa = dwarf_unwind_impl(
            nth_frame,
            memory,
            Some( unwind_cache ),
            regs,
            &unwind_info,
            next_regs,
            &mut ra_address
        );

        return Some( DwarfResult {
            initial_address: unwind_info.initial_absolute_address(),
            cfa,
            ra_address
        });
    });

    match result {
        Some( result ) => result,
        None => {
            debug!( "No unwind info for address 0x{:016X}", address );
            return None;
        }
    }
}
