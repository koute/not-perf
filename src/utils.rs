use std::io;
use std::fs::read;
use std::path::Path;
use std::sync::atomic::{Ordering, AtomicBool};

use libc;

pub use nwind::utils::*;

pub fn read_string_lossy< P: AsRef< Path > >( path: P ) -> io::Result< String > {
    let data = read( path )?;
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
