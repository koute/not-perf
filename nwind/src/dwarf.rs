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

fn evaluate_dwarf_expression< A, M, R >(
    _memory: &M,
    regs: &A::Regs,
    expr: gimli::read::Expression< R >
) -> Option< u64 > where A: Architecture, M: MemoryReader< A >, R: gimli::Reader, <R as gimli::Reader>::Offset: Default {
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

    if debug_logs_enabled!() {
        debug!( "Evaluating DWARF expression:" );
        let mut iter = expr.clone().operations( encoding.clone() );
        while let Ok( Some( op ) ) = iter.next() {
            debug!( "  {:?}", op );
        }
    }

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
                            error!( "Unhandled DWARF evaluation result: {:?}", piece );
                            return None;
                        }
                    }
                } else {
                    error!( "Unhandled DWARF evaluation result: {:?}", pieces );
                    return None;
                }
            },
            Ok( EvaluationResult::RequiresRegister { register, base_type } ) => {
                if base_type != gimli::UnitOffset( Default::default() ) {
                    error!( "Failed to evaluate DWARF expression: unsupported base type in RequiresRegister rule: {:?}", base_type );
                    return None;
                }

                let reg_value = match regs.get( register.0 ) {
                    Some( reg_value ) => reg_value.into(),
                    None => {
                        error!( "Failed to evaluate DWARF expression due to a missing value of register {:?}", A::register_name( register.0 ) );
                        return None;
                    }
                };

                debug!( "Fetched register {:?}: 0x{:016X}", A::register_name( register.0 ), reg_value );
                result = evaluation.resume_with_register( Value::Generic( reg_value ) );
            },
            Ok( result ) => {
                error!( "Failed to evaluate DWARF expression due to unhandled requirement: {:?}", result );
                return None;
            },
            Err( error ) => {
                error!( "Failed to evaluate DWARF expression: {:?}", error );
                return None;
            }
        }
    }

    Some( value )
}

fn dwarf_unwind_impl< A: Architecture, M: MemoryReader< A > >(
    nth_frame: usize,
    memory: &M,
    regs: &A::Regs,
    unwind_info: &UnwindInfo< A::Endianity >,
    next_regs: &mut Vec< (u16, u64) >,
    ra_address: &mut Option< u64 >
) -> Option< (u64, bool) > {
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
            let value = evaluate_dwarf_expression( memory, regs, expr )?;
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

    Some( (cfa_value, cacheable) )
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

    let address: u64 = regs.get( A::INSTRUCTION_POINTER_REG ).expect( "DWARF unwind: no instruction pointer" ).into();
    if address == 0 {
        debug!( "Instruction pointer is NULL; cannot continue unwinding" );
        return None;
    }

    let address = if nth_frame == 0 { address } else { address - 1 };
    let cached_unwind_info = unwind_cache.lookup( address );
    let mut uncached_unwind_info = None;

    if cached_unwind_info.is_none() {
        if let Some( binary ) = lookup_binary( nth_frame, memory, regs ) {
            uncached_unwind_info = binary.lookup_unwind_row( ctx_cache, address );
        } else if let Some( registry ) = memory.dynamic_fde_registry() {
            uncached_unwind_info = registry.lookup_unwind_row( ctx_cache, address );
        }
    }

    let unwind_info = match cached_unwind_info.as_ref().or( uncached_unwind_info.as_ref() ) {
        Some( unwind_info ) => unwind_info,
        None => {
            debug!( "No unwind info for address 0x{:016X}", address );
            return None;
        }
    };

    if unwind_info.is_signal_frame() {
        debug!( "Frame #{} is a signal frame!", nth_frame );
        // TODO: AFAIK this requires some special handling to be 100% correct, although until I can get a testcase that
        // can demonstrate the necessity of it I'd rather not do anything blind.
    }

    let mut ra_address = None;
    let result = dwarf_unwind_impl(
        nth_frame,
        memory,
        regs,
        unwind_info,
        next_regs,
        &mut ra_address
    );

    let initial_address = unwind_info.initial_absolute_address();
    let cfa = match result {
        Some( (cfa, cacheable) ) => {
            if cacheable {
                if let Some( uncached_unwind_info ) = uncached_unwind_info {
                    uncached_unwind_info.cache_into( unwind_cache );
                }
            }
            Some( cfa )
        },
        None => None
    };

    Some( DwarfResult {
        initial_address,
        cfa,
        ra_address
    })
}
