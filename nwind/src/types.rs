use std::io;

use speedy::{Readable, Writable, Context, Reader, Writer};

pub use speedy::Endianness;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Readable, Writable)]
pub struct Inode {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Readable, Writable)]
pub enum Bitness {
    B32,
    B64
}

impl Bitness {
    #[cfg( target_pointer_width = "32" )]
    pub const NATIVE: Bitness = Bitness::B32;

    #[cfg( target_pointer_width = "64" )]
    pub const NATIVE: Bitness = Bitness::B64;
}

#[derive(Clone, Debug)]
pub struct UserFrame {
    pub address: u64,
    pub initial_address: Option< u64 >
}

impl< 'a, C: Context > Readable< 'a, C > for UserFrame {
    #[inline]
    fn read_from< R: Reader< 'a, C > >( reader: &mut R ) -> io::Result< Self > {
        let address = reader.read_u64()?;
        let initial_address = match reader.read_u64()? {
            0 => None,
            value => Some( value )
        };

        Ok( UserFrame { address, initial_address } )
    }
}

impl< 'a, C: Context > Writable< C > for UserFrame {
    #[inline]
    fn write_to< 'this, T: ?Sized + Writer< 'this, C > >( &'this self, writer: &mut T ) -> io::Result< () > {
        writer.write_u64( self.address )?;
        writer.write_u64( self.initial_address.unwrap_or( 0 ) )?;
        Ok(())
    }
}
