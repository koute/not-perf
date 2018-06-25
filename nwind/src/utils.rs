use std::fmt;
use std::time::Duration;
use std::ops::Range;

pub unsafe trait StableIndex {}

pub struct HexValue( pub u64 );
impl fmt::Debug for HexValue {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        write!( fmt, "0x{:016X}", self.0 )
    }
}

pub struct HexRange( pub Range< u64 > );
impl fmt::Debug for HexRange {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        write!( fmt, "0x{:016X}..0x{:016X}", self.0.start, self.0.end )
    }
}


pub struct HexSlice< 'a >( pub &'a [u64] );
impl< 'a > fmt::Debug for HexSlice< 'a > {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        fmt.debug_list().entries( self.0.iter().map( |&value| HexValue( value ) ) ).finish()
    }
}

// Maximum value: 0xFFF
pub fn get_major( dev: u64 ) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

// Maximum value: 0xFFFFF
pub fn get_minor( dev: u64 ) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

pub fn get_ms( duration: Duration ) -> u32 {
    (duration.as_secs() * 1000 + duration.subsec_nanos() as u64 / 1_000_000) as u32
}
