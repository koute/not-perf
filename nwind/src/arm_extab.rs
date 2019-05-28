use std::slice;
use std::mem;
use std::fmt;
use std::ops::Range;

use byteorder::{ByteOrder, LittleEndian, BigEndian};
use lru::LruCache;

use crate::arch::arm;
use crate::arch::arm::dwarf;
use crate::arch::arm::Regs;
use crate::arch::Registers;
use crate::address_space::MemoryReader;

struct RegsIter {
    mask: u16,
    index: u8
}

impl RegsIter {
    fn new( mask: u16 ) -> Self {
        RegsIter { mask, index: 0 }
    }
}

impl Iterator for RegsIter {
    type Item = Reg;
    fn next( &mut self ) -> Option< Self::Item > {
        while self.index < 16 {
            let index = self.index;
            self.index += 1;

            if self.mask & (1 << index) != 0 {
                return Some( Reg( index ) );
            }
        }

        None
    }
}

#[test]
fn test_regs_iter() {
    fn to_vec< I: Iterator< Item = Reg > >( iter: I ) -> Vec< u8 > { iter.map( |reg| reg.0 ).collect() }
    assert!( to_vec( RegsIter::new( 0 ) ).is_empty() );
    assert_eq!( to_vec( RegsIter::new( 0b1 ) ), vec![ 0 ] );
    assert_eq!( to_vec( RegsIter::new( 0b11 ) ), vec![ 0, 1 ] );
    assert_eq!( to_vec( RegsIter::new( 0b10 ) ), vec![ 1 ] );
    assert_eq!( to_vec( RegsIter::new( 0b100 ) ), vec![ 2 ] );
    assert_eq!( to_vec( RegsIter::new( 0b1000_0000_0000_0000 ) ), vec![ 15 ] );
    assert_eq!( to_vec( RegsIter::new( 0b1000_0000_0000_0001 ) ), vec![ 0, 15 ] );
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Reg( u8 );

impl fmt::Debug for Reg {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        write!( fmt, "r{}", self.0 )
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct RegMask( u16 );

impl RegMask {
    #[inline]
    fn iter( self ) -> RegsIter {
        self.into_iter()
    }
}

impl IntoIterator for RegMask {
    type IntoIter = RegsIter;
    type Item = <RegsIter as Iterator>::Item;

    #[inline]
    fn into_iter( self ) -> Self::IntoIter {
        RegsIter::new( self.0 )
    }
}

impl fmt::Debug for RegMask {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        let mut set = fmt.debug_set();
        for nth_reg in self.iter() {
            set.entry( &nth_reg );
        }

        set.finish()
    }
}


struct FpRegsIter {
    mask: u32,
    index: u8
}

impl FpRegsIter {
    fn new( mask: u32 ) -> Self {
        FpRegsIter { mask, index: 0 }
    }
}

impl Iterator for FpRegsIter {
    type Item = FpReg;
    fn next( &mut self ) -> Option< Self::Item > {
        while self.index < 32 {
            let index = self.index;
            self.index += 1;

            if self.mask & (1 << index) != 0 {
                return Some( FpReg( index ) );
            }
        }

        None
    }
}

#[test]
fn test_fp_regs_iter() {
    fn to_vec< I: Iterator< Item = FpReg > >( iter: I ) -> Vec< u8 > { iter.map( |reg| reg.0 ).collect() }
    assert!( to_vec( FpRegsIter::new( 0 ) ).is_empty() );
    assert_eq!( to_vec( FpRegsIter::new( 0b1 ) ), vec![ 0 ] );
    assert_eq!( to_vec( FpRegsIter::new( 0b11 ) ), vec![ 0, 1 ] );
    assert_eq!( to_vec( FpRegsIter::new( 0b10 ) ), vec![ 1 ] );
    assert_eq!( to_vec( FpRegsIter::new( 0b100 ) ), vec![ 2 ] );
    assert_eq!( to_vec( FpRegsIter::new( 0b1000_0000_0000_0000 ) ), vec![ 15 ] );
    assert_eq!( to_vec( FpRegsIter::new( 0b1000_0000_0000_0001 ) ), vec![ 0, 15 ] );
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct FpReg( u8 );

impl fmt::Debug for FpReg {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        write!( fmt, "d{}", self.0 )
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct FpRegMask( u32 );

impl FpRegMask {
    #[inline]
    fn iter( self ) -> FpRegsIter {
        self.into_iter()
    }
}

impl IntoIterator for FpRegMask {
    type IntoIter = FpRegsIter;
    type Item = <FpRegsIter as Iterator>::Item;

    #[inline]
    fn into_iter( self ) -> Self::IntoIter {
        FpRegsIter::new( self.0 )
    }
}

impl fmt::Debug for FpRegMask {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        let mut set = fmt.debug_set();
        for nth_reg in self.iter() {
            set.entry( &nth_reg );
        }

        set.finish()
    }
}

// Source: Exception Handling ABI for the ARM Architecture
//         http://infocenter.arm.com/help/topic/com.arm.doc.ihi0038b/IHI0038B_ehabi.pdf

#[repr(C)]
struct IndexEntry {
    raw_offset_to_function: u32,
    raw_value: u32
}

impl IndexEntry {
    fn offset_to_function( &self ) -> u32 {
        if cfg!( target_endian = "little" ) {
            self.raw_offset_to_function
        } else {
            self.raw_offset_to_function.swap_bytes()
        }
    }

    fn value( &self ) -> u32 {
        if cfg!( target_endian = "little" ) {
            self.raw_value
        } else {
            self.raw_value.swap_bytes()
        }
    }
}

const EXIDX_CANTUNWIND: u32 = 0x1;
const EXIDX_INLINE_MASK: u32 = (1 << 31);

const EXTAB_OP_ADD_VSP: u8                  = 0b0000_0000;
const EXTAB_OP_ADD_VSP_MASK: u8             = 0b1100_0000;
const EXTAB_OP_ADD_VSP_ARG_MASK: u8         = 0b0011_1111;

const EXTAB_OP_ADD_VSP_ULEB128: u8          = 0b1011_0010;

const EXTAB_OP_SUB_VSP: u8                  = 0b0100_0000;
const EXTAB_OP_SUB_VSP_MASK: u8             = 0b1100_0000;
const EXTAB_OP_SUB_VSP_ARG_MASK: u8         = 0b0011_1111;

const EXTAB_OP_POP_REGS_SERIAL: u8                 = 0b1010_0000;
const EXTAB_OP_POP_REGS_SERIAL_MASK: u8            = 0b1111_0000;
const EXTAB_OP_POP_REGS_SERIAL_ARG_R14_MASK: u8    = 0b0000_1000;
const EXTAB_OP_POP_REGS_SERIAL_ARG_COUNT_MASK: u8  = 0b0000_0111;

const EXTAB_OP_POP_REGS: u8             = 0b1000_0000;
const EXTAB_OP_POP_REGS_MASK: u8        = 0b1111_0000;
const EXTAB_OP_POP_REGS_ARG_MASK: u8    = 0b0000_1111;

const EXTAB_OP_POP_INT_REGS: u8     = 0b1011_0001;

const EXTAB_OP_POP_VFP_REGS: u8                 = 0b1100_1000;
const EXTAB_OP_POP_VFP_REGS_MASK: u8            = 0b1111_1110;
const EXTAB_OP_POP_VFP_REGS_ARG_OFFSET_MASK: u8 = 0b0000_0001;

const EXTAB_OP_SET_VSP: u8          = 0b1001_0000;
const EXTAB_OP_SET_VSP_MASK: u8     = 0b1111_0000;
const EXTAB_OP_SET_VSP_ARG_MASK: u8 = 0b0000_1111;

const EXTAB_OP_FINISH: u8                   = 0b1011_0000;

const EXTAB_HEADER_MODEL_MASK: u32                  = 0b1000_0000_0000_0000_0000_0000_0000_0000;
const EXTAB_HEADER_DATA_MASK: u32                   = 0b0000_0000_1111_1111_1111_1111_1111_1111;
const EXTAB_HEADER_PERSONALITY_ROUTINE_MASK: u32    = 0b0000_1111_0000_0000_0000_0000_0000_0000;
const EXTAB_HEADER_PERSONALITY_ROUTINE_SHIFT: u32   = 24;

#[derive(PartialEq, Debug)]
pub enum DecodeError {
    UnknownOpcode( u8 ),
    UnexpectedEnd,
    ReservedInstruction,
    BadUnsignedLeb128,
    OutOfRangeUnsignedLeb128
}

fn exidx_offset( exidx_base: u32, exidx_index: u32, offset: u32 ) -> u32 {
    let offset = (((offset << 1) as i32) >> 1) as u32; // Sign extend to the left.
    (exidx_base + exidx_index * mem::size_of::< IndexEntry >() as u32).wrapping_add( offset )
}

fn search( exidx: &[IndexEntry], exidx_base: u32, address: u32 ) -> Option< usize > {
    let mut size = exidx.len();
    let mut base = 0_usize;
    loop {
        let half = size / 2;
        let mid = base + half;

        let entry = unsafe { exidx.get_unchecked( mid ) };
        let entry_function_address = exidx_offset( exidx_base, mid as u32, entry.offset_to_function() );
        if address > entry_function_address {
            base = mid;
        } else {
            if address == entry_function_address {
                return Some( mid );
            }
        }
        if half == 0 {
            break;
        }
        size -= half;
    }

    let entry = unsafe { exidx.get_unchecked( base ) };
    let entry_function_address = exidx_offset( exidx_base, base as u32, entry.offset_to_function() );
    if address >= entry_function_address {
        Some( base )
    } else {
        None
    }
}

#[derive(PartialEq, Debug)]
enum Instruction {
    VspAdd( i32 ),
    VspSet( Reg ),
    PopRegs( RegMask ),
    PopFpRegs( FpRegMask ),
    Finish,
    RefuseToUnwind
}

// See section 9.3 of ARM's EHABI docs for details.
struct Decoder< I: Iterator< Item = u8 > > {
    bytecode: I,
    index: usize,
    is_done: bool
}

impl< I: Iterator< Item = u8 > > Decoder< I > {
    fn new< T: IntoIterator< IntoIter = I, Item = u8 > >( bytecode: T ) -> Self {
        Decoder {
            bytecode: bytecode.into_iter(),
            index: 0,
            is_done: false
        }
    }
}

impl< I: Iterator< Item = u8 > > Iterator for Decoder< I > {
    type Item = Result< Instruction, DecodeError >;
    fn next( &mut self ) -> Option< Self::Item > {
        if self.is_done {
            return None;
        }

        let opcode = if let Some( opcode ) = self.bytecode.next() {
            opcode
        } else {
            return None;
        };

        self.index += 1;

        let instruction = if opcode & EXTAB_OP_ADD_VSP_MASK == EXTAB_OP_ADD_VSP {
            let offset = (((opcode & EXTAB_OP_ADD_VSP_ARG_MASK) as u32) << 2) + 4;
            Instruction::VspAdd( offset as i32 )
        } else if opcode & EXTAB_OP_SUB_VSP_MASK == EXTAB_OP_SUB_VSP {
            let offset = (((opcode & EXTAB_OP_SUB_VSP_ARG_MASK) as u32) << 2) + 4;
            Instruction::VspAdd( offset as i32 * -1 )
        } else if opcode & EXTAB_OP_POP_REGS_SERIAL_MASK == EXTAB_OP_POP_REGS_SERIAL {
            // This pops R4 and $extra_regs after R4, plus R14 if flagged.
            let extra_regs = opcode & EXTAB_OP_POP_REGS_SERIAL_ARG_COUNT_MASK;
            let pop_r14 = opcode & EXTAB_OP_POP_REGS_SERIAL_ARG_R14_MASK != 0;

            let mut mask = 0;
            if pop_r14 {
                mask |= 1 << 14;
            }

            for nth_reg in 4..5 + extra_regs as u16 {
                mask |= 1 << nth_reg;
            }

            Instruction::PopRegs( RegMask( mask ) )
        } else if opcode & EXTAB_OP_POP_REGS_MASK == EXTAB_OP_POP_REGS {
            // This pops the registers specified in the masks, fram R4 up to R15.
            let regs_2 = opcode & EXTAB_OP_POP_REGS_ARG_MASK;
            let regs_1 = match self.bytecode.next() {
                Some( byte ) => byte,
                None => return Some( Err( DecodeError::UnexpectedEnd ) )
            };
            self.index += 1;

            if regs_1 == 0 && regs_2 == 0 {
                self.is_done = true;
                Instruction::RefuseToUnwind
            } else {
                let mask = ((regs_1 as u16) << 4) | ((regs_2 as u16) << 12);
                Instruction::PopRegs( RegMask( mask ) )
            }
        } else if opcode == EXTAB_OP_POP_INT_REGS {
            let regs = match self.bytecode.next() {
                Some( byte ) => byte,
                None => return Some( Err( DecodeError::UnexpectedEnd ) )
            };
            self.index += 1;

            if regs == 0 || regs & 0b1111_0000 != 0 {
                return Some( Err( DecodeError::ReservedInstruction ) );
            }
            Instruction::PopRegs( RegMask( regs as u16 ) )
        } else if opcode == EXTAB_OP_FINISH {
            self.is_done = true;
            Instruction::Finish
        } else if opcode & EXTAB_OP_SET_VSP_MASK == EXTAB_OP_SET_VSP {
            let nth_reg = opcode & EXTAB_OP_SET_VSP_ARG_MASK;
            if nth_reg == 0b10011101 {
                // Reserved for ARM register-to-register moves.
                return Some( Err( DecodeError::ReservedInstruction ) );
            } else if nth_reg == 0b10011111 {
                // Reserved for MMX register-to-register moves.
                return Some( Err( DecodeError::ReservedInstruction ) );
            }

            Instruction::VspSet( Reg( nth_reg ) )
        } else if opcode == EXTAB_OP_ADD_VSP_ULEB128 {
            // This is based on the code from `gimli`.
            const CONTINUATION_BIT: u8 = 1 << 7;

            #[inline]
            fn low_bits_of_byte(byte: u8) -> u8 {
                byte & !CONTINUATION_BIT
            }

            let mut result = 0;
            let mut shift = 0;
            loop {
                let byte = match self.bytecode.next() {
                    Some( byte ) => byte,
                    None => return Some( Err( DecodeError::UnexpectedEnd ) )
                };
                self.index += 1;

                if shift == 63 && byte != 0x00 && byte != 0x01 {
                    return Some( Err( DecodeError::BadUnsignedLeb128 ) );
                }

                let low_bits = low_bits_of_byte( byte ) as u64;
                result |= low_bits << shift;

                if byte & CONTINUATION_BIT == 0 {
                    break;
                }

                shift += 7;
            }

            if result & !0xFFFFFFFF != 0 {
                return Some( Err( DecodeError::OutOfRangeUnsignedLeb128 ) );
            }

            let result = result as u32;
            let offset = 0x204 + (result << 2);

            Instruction::VspAdd( offset as i32 )
        } else if opcode & EXTAB_OP_POP_VFP_REGS_MASK == EXTAB_OP_POP_VFP_REGS {
            let offset_1 =
                if opcode & EXTAB_OP_POP_VFP_REGS_ARG_OFFSET_MASK == 0 {
                    16
                } else {
                    0
                };

            let byte = match self.bytecode.next() {
                Some( byte ) => byte,
                None => return Some( Err( DecodeError::UnexpectedEnd ) )
            };
            self.index += 1;

            let offset_2 = (byte & 0b1111_0000) >> 4;
            let offset = offset_1 + offset_2;
            let extra_count = byte & 0b0000_1111;
            let mut regs = 0;
            for nth_reg in offset..offset + extra_count + 1 {
                regs |= 1 << nth_reg;
            }

            Instruction::PopFpRegs( FpRegMask( regs ) )
        } else {
            return Some( Err( DecodeError::UnknownOpcode( opcode ) ) );
        };

        Some( Ok( instruction ) )
    }
}

#[cfg(test)]
fn decode_to_vec( bytecode: &[u8] ) -> (Vec< Instruction >, usize, Option< DecodeError >) {
    let mut output = Vec::new();
    let mut iter = Decoder::new( bytecode.iter().cloned() );
    let mut error = None;
    while let Some( instruction ) = iter.next() {
        match instruction {
            Ok( instruction ) => output.push( instruction ),
            Err( err ) => error = Some( err )
        }
    }

    (output, iter.index, error)
}

#[test]
fn test_decode_pop_r14() {
    assert_eq!(
        decode_to_vec( &[ 0x84, 0x00 ] ),
        (
            vec![ Instruction::PopRegs( RegMask( 1 << 14 ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_pop_r4() {
    assert_eq!(
        decode_to_vec( &[ 0xa0 ] ),
        (
            vec![ Instruction::PopRegs( RegMask( 1 << 4 ) ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_pop_r4_r5() {
    assert_eq!(
        decode_to_vec( &[ 0xa1 ] ),
        (
            vec![ Instruction::PopRegs( RegMask( (1 << 4) | (1 << 5) ) ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_pop_r4_r14() {
    assert_eq!(
        decode_to_vec( &[ 0xa8 ] ),
        (
            vec![ Instruction::PopRegs( RegMask( (1 << 4) | (1 << 14) ) ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_pop_r3() {
    assert_eq!(
        decode_to_vec( &[ 0xb1, 0x08 ] ),
        (
            vec![ Instruction::PopRegs( RegMask( 1 << 3 ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_pop_d8() {
    assert_eq!(
        decode_to_vec( &[ 0xc9, 0x80 ] ),
        (
            vec![ Instruction::PopFpRegs( FpRegMask( 1 << 8 ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_pop_d1() {
    assert_eq!(
        decode_to_vec( &[ 0xc9, 0b0001_0000 ] ),
        (
            vec![ Instruction::PopFpRegs( FpRegMask( 1 << 1 ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_pop_d1_d2() {
    assert_eq!(
        decode_to_vec( &[ 0xc9, 0b0001_0001 ] ),
        (
            vec![ Instruction::PopFpRegs( FpRegMask( (1 << 1) | (1 << 2) ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_pop_d17_d18() {
    assert_eq!(
        decode_to_vec( &[ 0xc8, 0b0001_0001 ] ),
        (
            vec![ Instruction::PopFpRegs( FpRegMask( (1 << 17) | (1 << 18) ) ) ],
            2,
            None
        )
    );
}

#[test]
fn test_decode_set_vsp_to_r7() {
    assert_eq!(
        decode_to_vec( &[ 0x97 ] ),
        (
            vec![ Instruction::VspSet( Reg( 7 ) ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_add_vsp_4() {
    assert_eq!(
        decode_to_vec( &[ 0x00 ] ),
        (
            vec![ Instruction::VspAdd( 4 ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_add_vsp_256() {
    assert_eq!(
        decode_to_vec( &[ 0x3f ] ),
        (
            vec![ Instruction::VspAdd( 256 ) ],
            1,
            None
        )
    );
}

#[test]
fn test_decode_add_vsp_uleb() {
    assert_eq!(
        decode_to_vec( &[ 0xb2, 0xe5, 0x8e, 0x26 ] ),
        (
            vec![ Instruction::VspAdd( 0x204 + (0x98765 << 2) ) ],
            4,
            None
        )
    );
}

#[test]
fn test_decode_finish() {
    assert_eq!(
        decode_to_vec( &[ 0xb0 ] ),
        (
            vec![ Instruction::Finish ],
            1,
            None
        )
    );
}

#[derive(PartialEq, Debug)]
pub enum Error {
    EndOfStack,
    DecodeError( DecodeError ),
    MemoryUnaccessible {
        address: u32
    },
    UnsupportedPersonality( u8 ),
    MissingRegisterValue( Reg ),
    UnwindingFailed,
    UnwindInfoMissing
}

impl From< DecodeError > for Error {
    fn from( err: DecodeError ) -> Self {
        Error::DecodeError( err )
    }
}

struct BytecodeIter< 'a > {
    chunk: u32,
    bytecode: &'a [u8],
    subindex: u8
}

// NOTE: This assumes that the data is little endian.
impl< 'a > BytecodeIter< 'a > {
    fn new( inline_bytecode: u32, inline_offset: u8, bytecode: &'a [u8] ) -> Self {
        let inline_bytecode = if cfg!( target_endian = "little" ) {
            (inline_bytecode << (inline_offset * 8)).swap_bytes()
        } else {
            unimplemented!();
        };

        BytecodeIter {
            chunk: inline_bytecode,
            bytecode,
            subindex: inline_offset
        }
    }
}

#[test]
fn test_bytecode_iter_inline_bytecode() {
    use byteorder::NativeEndian;
    let inline_bytecode = &[ 0x04, 0x03, 0x02, 0x01 ];
    let vec: Vec< u8 > = BytecodeIter::new( NativeEndian::read_u32( inline_bytecode ), 0, &[] ).collect();
    assert_eq!( vec, &[ 0x01, 0x02, 0x03, 0x04 ] );
}

#[test]
fn test_bytecode_iter_inline_bytecode_with_offset() {
    use byteorder::NativeEndian;
    let inline_bytecode = &[ 0x04, 0x03, 0x02, 0x01 ];
    let vec: Vec< u8 > = BytecodeIter::new( NativeEndian::read_u32( inline_bytecode ), 1, &[] ).collect();
    assert_eq!( vec, &[ 0x02, 0x03, 0x04 ] );
}

#[test]
fn test_bytecode_iter_inline_bytecode_with_offset_and_with_bytecode() {
    use byteorder::NativeEndian;
    let inline_bytecode = &[ 0x04, 0x03, 0x02, 0x01 ];
    let bytecode = &[ 0x08, 0x07, 0x06, 0x05 ];
    let vec: Vec< u8 > = BytecodeIter::new( NativeEndian::read_u32( inline_bytecode ), 1, bytecode ).collect();
    assert_eq!( vec, &[ 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ] );
}

impl< 'a > Iterator for BytecodeIter< 'a > {
    type Item = u8;
    fn next( &mut self ) -> Option< Self::Item > {
        if self.subindex == 0xFF {
            return None;
        }

        let byte = (self.chunk & 0xFF) as u8;
        self.subindex += 1;
        if self.subindex != 4 {
            self.chunk >>= 8;
        } else {
            if self.bytecode.is_empty() {
                self.subindex = 0xFF;
            } else {
                self.chunk = BigEndian::read_u32( &self.bytecode[ 0..4 ] );
                self.bytecode = &self.bytecode[ 4.. ];
                self.subindex = 0;
            }
        }

        debug!( "op: 0x{:02X}", byte );
        Some( byte )
    }
}

fn get_bytecode_iter< 'a >( address: u32, index: usize, entry: &IndexEntry, exidx_base: u32, extab_base: u32, extab: &'a [u8] ) -> Result< BytecodeIter< 'a >, Error > {
    if entry.value() & EXIDX_INLINE_MASK != 0 {
        let value = entry.value() & !EXIDX_INLINE_MASK;

        debug!( "Entry for 0x{:08X} (index: {}) is defined inline: 0x{:08X}", address, index, value );
        return Ok( BytecodeIter::new( value, 1, &[] ) );
    }

    let extab_address = exidx_offset( exidx_base, index as u32, entry.value() ) + mem::size_of_val( &entry.raw_offset_to_function ) as u32;

    debug!( "Entry for 0x{:08X} (index: {}) is defined in .ARM.extab at: 0x{:08X}", address, index, extab_address );
    let offset = extab_address - extab_base;
    let extab_bytes = &extab[ offset as usize.. ];
    if extab_bytes.len() < 4 {
        return Err( Error::DecodeError( DecodeError::UnexpectedEnd ) );
    }

    let extab_entry = LittleEndian::read_u32( extab_bytes );
    if extab_entry & EXTAB_HEADER_MODEL_MASK == 0 {
        // Generic model.
        let personality_offset = extab_entry & !EXTAB_HEADER_MODEL_MASK;
        debug!( "0x{:08X} uses the generic model with personality at offset 0x{:08X}", extab_address, personality_offset );

        if extab_bytes.len() < 8 {
            return Err( Error::DecodeError( DecodeError::UnexpectedEnd ) );
        }

        let data = LittleEndian::read_u32( &extab_bytes[ 4..8 ] );
        let count = ((data >> 24) & 0xFF) as usize;

        if extab_bytes.len() < (8 + count * 4) {
            return Err( Error::DecodeError( DecodeError::UnexpectedEnd ) );
        }

        let data_bytes = &extab_bytes[ 8..8 + count * 4 ];
        Ok( BytecodeIter::new( data, 1, data_bytes ) )
    } else {
        // ARM compact model.
        let personality_routine =
            (extab_entry & EXTAB_HEADER_PERSONALITY_ROUTINE_MASK) >> EXTAB_HEADER_PERSONALITY_ROUTINE_SHIFT;

        debug!( "0x{:08X} uses the ARM compact model with personality equal to {}", extab_address, personality_routine );
        let header = extab_entry & EXTAB_HEADER_DATA_MASK;
        match personality_routine {
            1 => {
                let count = ((header >> 16) & 0xff) as usize;
                if extab_bytes.len() < (4 + count * 4) {
                    return Err( Error::DecodeError( DecodeError::UnexpectedEnd ) );
                }

                let data_bytes = &extab_bytes[ 4..4 + count * 4 ];
                Ok( BytecodeIter::new( header, 2, data_bytes ) )
            },
            _ => {
                Err( Error::UnsupportedPersonality( personality_routine as u8 ) )
            }
        }
    }
}

#[derive(Clone)]
enum Rule {
    SetSp {
        reg: Reg
    },
    SetReg {
        reg: Reg,
        offset: i32
    }
}

#[derive(Clone)]
struct UnwindInfo {
    sp_offset: i32,
    rules: Vec< Rule >
}

pub struct UnwindInfoCache {
    cache: LruCache< u32, UnwindInfo >
}

impl UnwindInfoCache {
    pub fn new() -> Self {
        UnwindInfoCache {
            cache: LruCache::new( 2000 )
        }
    }

    pub fn clear( &mut self ) {
        self.cache.clear();
    }
}

fn interpret_bytecode( output: &mut UnwindInfo, bytecode: impl IntoIterator< Item = u8 > ) -> Result< (), Error > {
    let decoder = Decoder::new( bytecode.into_iter() );
    let mut vsp_offset = 0;

    output.rules.clear();
    let regs = &mut output.rules;

    for instruction in decoder {
        let instruction = instruction?;
        match instruction {
            Instruction::VspAdd( offset ) => {
                debug!( "op: VSP += {} ({} + {})", offset, vsp_offset, offset );
                vsp_offset += offset;
            },
            Instruction::VspSet( reg ) => {
                debug!( "op: VSP = {:?}", reg );
                vsp_offset = 0;
                regs.push( Rule::SetSp { reg } );
            },
            Instruction::PopRegs( reg_mask ) => {
                debug!( "op: pop {:?}", reg_mask );
                for reg in reg_mask {
                    regs.push( Rule::SetReg {
                        reg,
                        offset: vsp_offset
                    });
                    vsp_offset += 4;
                }
            },
            Instruction::Finish => {
                debug!( "op: finish" );
            },
            Instruction::PopFpRegs( reg_mask ) => {
                debug!( "op: pop {:?}", reg_mask );
                for _ in reg_mask {
                    vsp_offset += 8;
                }
            },
            Instruction::RefuseToUnwind => {
                debug!( "op: refuse" );
                return Err( Error::EndOfStack );
            }
        }
    }

    output.sp_offset = vsp_offset;
    Ok(())
}

fn run_bytecode< M, I >(
    memory: &M,
    regs: &mut Regs,
    regs_modified: &mut u32,
    mut vsp: u32,
    bytecode: I
) -> Result< (u32, Option< u32 >), Error > where M: MemoryReader< arm::Arch >, I: IntoIterator< Item = u8 > {
    let decoder = Decoder::new( bytecode.into_iter() );
    let mut link_register_addr = None;
    for instruction in decoder {
        let instruction = instruction?;
        match instruction {
            Instruction::VspAdd( offset ) => {
                debug!( "op: VSP += {} (0x{:08X} + {})", offset, vsp, offset );
                vsp = (vsp as i32 + offset) as u32;
            },
            Instruction::VspSet( reg ) => {
                let value = regs.get( reg.0 as u16 );
                match value {
                    Some( value ) => {
                        debug!( "op: VSP = {:?} = 0x{:08X}", reg, value );
                        vsp = value;
                    },
                    None => {
                        debug!( "op: VSP = {:?} = unknown", reg );
                        return Err( Error::MissingRegisterValue( reg ) );
                    }
                }
            },
            Instruction::PopRegs( reg_mask ) => {
                debug!( "op: pop {:?}", reg_mask );
                for reg in reg_mask {
                    match memory.get_pointer_at_address( vsp ) {
                        Some( value ) => {
                            debug!( "op:   {:?} = *(0x{:08X}) = 0x{:08X}", reg, vsp, value );
                            regs.append( reg.0 as u16, value );
                            *regs_modified |= 1 << reg.0;

                            if reg.0 == dwarf::R14 as u8 {
                                link_register_addr = Some( vsp );
                            }
                        },
                        None => {
                            debug!( "op:   {:?} = *(0x{:08X}) = unaccessible", reg, vsp );
                            return Err( Error::MemoryUnaccessible { address: vsp } );
                        }
                    }

                    vsp += 4;
                }
            },
            Instruction::Finish => {
                debug!( "op: finish" );
            },
            Instruction::PopFpRegs( reg_mask ) => {
                debug!( "op: pop {:?}", reg_mask );
                for _ in reg_mask {
                    vsp += 8;
                }
            },
            Instruction::RefuseToUnwind => {
                debug!( "op: refuse" );
                return Err( Error::EndOfStack );
            }
        }
    }

    Ok( (vsp, link_register_addr) )
}

fn find_entry(
    exidx: &[u8],
    exidx_base: u32,
    address: u32
) -> Option< (usize, &IndexEntry, Range< u32 >) > {
    let exidx: &[IndexEntry] = unsafe {
        slice::from_raw_parts( exidx.as_ptr() as *const IndexEntry, exidx.len() / mem::size_of::< IndexEntry >() )
    };

    let index = match search( exidx, exidx_base, address ) {
        Some( index ) => index,
        None => return None
    };

    let entry = &exidx[ index ];

    let function_start = exidx_offset( exidx_base, index as u32, entry.offset_to_function() );
    let function_end = if index + 1 < exidx.len() {
        exidx_offset( exidx_base, index as u32 + 1, exidx[ index + 1 ].offset_to_function() )
    } else {
        !0
    };

    let range = function_start..function_end;
    Some( (index, entry, range) )
}

pub fn unwind_from_cache< M >(
    memory: &M,
    unwind_cache: &mut UnwindInfoCache,
    regs: &mut Regs,
    address: u32
) -> Option< Result< Option< u32 >, Error > > where M: MemoryReader< arm::Arch > {
    let unwind_info = unwind_cache.cache.get( &address )?;
    let mut link_register_addr = None;
    let mut sp = regs.get( dwarf::R13 ).unwrap();

    for rule in &unwind_info.rules {
        match *rule {
            Rule::SetSp { reg } => {
                sp = regs.get( reg.0 as _ ).unwrap();
            },
            Rule::SetReg { reg, offset } => {
                let location = (sp as i32 + offset) as u32;
                if let Some( value ) = memory.get_pointer_at_address( location ) {
                    debug!( "{:?} = *(0x{:08X}) = 0x{:08X}", reg, location, value );
                    regs.append( reg.0 as u16, value );

                    if reg.0 == dwarf::R14 as u8 {
                        link_register_addr = Some( location );
                    }
                } else {
                    debug!( "{:?} = *(0x{:08X}) = unaccessible", reg, location );
                    return Some( Err( Error::MemoryUnaccessible { address: location } ) );
                }
            }
        }
    }

    sp = (sp as i32 + unwind_info.sp_offset) as u32;

    let link_register = regs.get( dwarf::R14 ).unwrap();
    let program_counter = link_register & !1;
    regs.append( dwarf::R15, program_counter );
    regs.append( dwarf::R13, sp );

    Some( Ok( link_register_addr ) )
}

pub fn unwind< M >(
    memory: &M,
    initial_address: &mut Option< u32 >,
    unwind_cache: &mut UnwindInfoCache,
    regs: &mut Regs,
    exidx: &[u8],
    extab: &[u8],
    exidx_base: u32,
    extab_base: u32,
    address: u32,
    is_first_frame: bool
) -> Result< Option< u32 >, Error > where M: MemoryReader< arm::Arch > {
    if address == 0 || exidx.is_empty() {
        return Err( Error::UnwindInfoMissing );
    }

    let original_sp = regs.get( dwarf::R13 );
    let original_pc = regs.get( dwarf::R15 );

    let (index, entry, function_range) = match find_entry( exidx, exidx_base, if is_first_frame { address } else { address - 1 } ) {
        Some( result ) => result,
        None => {
            debug!( "Address 0x{:08X} has no unwinding information", address );

            if is_first_frame {
                let link_register = regs.get( dwarf::R14 ).unwrap();
                let program_counter = link_register & !1;

                if original_pc.unwrap() == program_counter {
                    return Err( Error::UnwindingFailed );
                }

                regs.append( dwarf::R15, program_counter );
                return Ok( None );
            }

            return Err( Error::UnwindInfoMissing );
        }
    };

    let function_start = function_range.start;
    *initial_address = Some( function_start );

    if entry.value() == EXIDX_CANTUNWIND {
        debug!( "Entry for 0x{:08X} (index: {}) doesn't support unwinding", address, index );
        return Err( Error::EndOfStack );
    }

    let vsp = match original_sp {
        Some( value ) => value,
        None => return Err( Error::MissingRegisterValue( Reg( 13 ) ) )
    };

    if is_first_frame && address == function_start {
        debug!( "Address 0x{:08X} starts on the first instruction of its entry (index: {}) in .ARM.extab at: 0x{:08X}", address, index, extab_base );
        let link_register = regs.get( dwarf::R14 ).unwrap();
        let program_counter = link_register & !1;

        if original_pc.unwrap() == program_counter {
            return Err( Error::UnwindingFailed );
        }

        regs.append( dwarf::R15, program_counter ); // The program counter.
        regs.append( dwarf::R13, vsp ); // The stack pointer.
        return Ok( None );
    }

    let mut regs_modified = 0;
    let iter = get_bytecode_iter( address, index, entry, exidx_base, extab_base, extab )?;
    let (vsp, link_register_addr) = run_bytecode( memory, regs, &mut regs_modified, vsp, iter )?;

    let link_register = regs.get( dwarf::R14 ).unwrap();
    let program_counter = link_register & !1;

    {
        let r14_modified = regs_modified & (1 << dwarf::R14) != 0;
        if original_pc.unwrap() == program_counter && !r14_modified {
            return Err( Error::UnwindingFailed );
        }
    }

    {
        let mut rules = Vec::new();
        if unwind_cache.cache.len() == unwind_cache.cache.cap() {
            rules = unwind_cache.cache.pop_lru().map( |(_, old)| old.rules ).unwrap();
            rules.clear();
        } else {
            rules.reserve( 16 );
        }

        let mut info = UnwindInfo {
            sp_offset: 0,
            rules
        };

        let iter = get_bytecode_iter( address, index, entry, exidx_base, extab_base, extab ).unwrap();
        let result = interpret_bytecode( &mut info, iter );
        if result.is_ok() {
            unwind_cache.cache.put( address, info );
        }
    }

    regs.append( dwarf::R15, program_counter ); // The program counter.
    regs.append( dwarf::R13, vsp ); // The stack pointer.

    Ok( link_register_addr )
}

#[test]
fn test_decode_everything_from_a_binary() {
    use crate::binary::BinaryData;
    use std::path::PathBuf;
    let _ = ::env_logger::try_init();

    let mut target = PathBuf::from( env!( "CARGO_MANIFEST_DIR" ) )
        .join( ".." )
        .join( "test-data" )
        .join( "bin" )
        .join( "arm-usleep_in_a_loop_fp" );

    // This is here to make it possible to easily run this test on an arbitrary binary.
    if let Some( new_target ) = std::env::var_os( "TEST_DECODE_EVERYTHING_OVERRIDE" ) {
        target = PathBuf::from( new_target );
    }

    let binary = BinaryData::load_from_fs( target ).unwrap();
    let exidx_range = binary.arm_exidx_range().unwrap();
    let exidx_base = exidx_range.start as u32;
    let extab_range = binary.arm_extab_range().unwrap();
    let extab_base = extab_range.start as u32;
    let exidx = &binary[ exidx_range.start as u64..exidx_range.end as u64 ];
    let extab = &binary[ extab_range.start as u64..extab_range.end as u64 ];

    let exidx: &[IndexEntry] = unsafe {
        slice::from_raw_parts( exidx.as_ptr() as *const IndexEntry, exidx.len() / mem::size_of::< IndexEntry >() )
    };

    for (index, entry) in exidx.iter().enumerate() {
        if entry.value() == EXIDX_CANTUNWIND {
            continue;
        }

        let function_start = exidx_offset( exidx_base, index as u32, entry.offset_to_function() );
        let iter = get_bytecode_iter( function_start, index, entry, exidx_base, extab_base, extab ).unwrap();
        let mut decoder = Decoder::new( iter );
        assert!( decoder.all( |instruction| instruction.is_ok() ) );
    }
}
