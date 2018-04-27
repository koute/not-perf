use std::io::{self, Read};
use std::fs::File;
use std::path::Path;
use std::fmt;
use std::sync::atomic::{Ordering, AtomicBool};
use std::time::Duration;
use std::ops::Range;

use libc;

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

pub fn read_file< P: AsRef< Path > >( path: P ) -> io::Result< Vec< u8 > > {
    let mut fp = File::open( path )?;
    let mut buffer = Vec::new();
    fp.read_to_end( &mut buffer )?;
    Ok( buffer )
}

pub fn read_string_lossy< P: AsRef< Path > >( path: P ) -> io::Result< String > {
    let data = read_file( path )?;
    Ok( String::from_utf8_lossy( &data ).into_owned() )
}

lazy_static! {
    static ref SIGINT_FLAG: AtomicBool = AtomicBool::new( false );
}

#[derive(Clone)]
pub struct SigintHandler {
}

impl SigintHandler {
    pub fn new() -> Self {
        SIGINT_FLAG.store( false, Ordering::Relaxed ); // To initialize the `lazy_static`.

        extern fn handler( _: libc::c_int ) {
            SIGINT_FLAG.store( true, Ordering::Relaxed );
        }

        unsafe {
            libc::signal( libc::SIGINT, handler as libc::size_t );
        }
        SigintHandler {}
    }

    pub fn was_triggered( &self ) -> bool {
        SIGINT_FLAG.load( Ordering::Relaxed )
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
