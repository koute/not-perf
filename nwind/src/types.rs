use speedy::{Readable, Writable, Context, Reader, Writer};

pub use speedy::Endianness;
use proc_maps::Region;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Readable, Writable)]
pub struct Inode {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32
}

impl Inode {
    #[inline]
    pub fn is_invalid( &self ) -> bool {
        self.dev_major == 0 && self.dev_minor == 0
    }

    #[inline]
    pub fn empty() -> Self {
        Inode { inode: 0, dev_major: 0, dev_minor: 0 }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Readable, Writable)]
pub enum Bitness {
    B32,
    B64
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum BinaryId {
    ByInode( Inode ),
    ByName( String )
}

impl BinaryId {
    #[inline]
    pub fn to_inode( &self ) -> Option< Inode > {
        match *self {
            BinaryId::ByInode( inode ) => Some( inode ),
            _ => None
        }
    }
}

impl< 'a > From< &'a Region > for BinaryId {
    #[inline]
    fn from( region: &'a Region ) -> Self {
        if region.major == 0 && region.minor == 0 {
            BinaryId::ByName( region.name.clone() )
        } else {
            BinaryId::ByInode( Inode { inode: region.inode, dev_major: region.major, dev_minor: region.minor } )
        }
    }
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
    fn read_from< R: Reader< 'a, C > >( reader: &mut R ) -> Result< Self, C::Error > {
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
    fn write_to< T: ?Sized + Writer< C > >( &self, writer: &mut T ) -> Result< (), C::Error > {
        writer.write_u64( self.address )?;
        writer.write_u64( self.initial_address.unwrap_or( 0 ) )?;
        Ok(())
    }
}
