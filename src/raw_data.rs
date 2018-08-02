use std::borrow::Cow;
use std::fmt;
use std::io;

use speedy::{Readable, Writable, Reader, Writer, Context};
use perf_event_open::RawData;

pub enum CowRawData< 'a > {
    Owned( Vec< u8 > ),
    Borrowed( RawData< 'a > )
}

impl< 'a > CowRawData< 'a > {
    #[inline]
    pub fn as_slice( &'a self ) -> Cow< 'a, [u8] > {
        match *self {
            CowRawData::Owned( ref bytes ) => bytes.as_slice().into(),
            CowRawData::Borrowed( ref raw_data ) => raw_data.as_slice()
        }
    }
}

impl< 'a > fmt::Debug for CowRawData< 'a > {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        match *self {
            CowRawData::Owned( ref data ) => write!( fmt, "[u8; {}]", data.len() ),
            CowRawData::Borrowed( ref data ) => write!( fmt, "{:?}", data )
        }
    }
}

impl< 'a, C: Context > Readable< 'a, C > for CowRawData< 'a > {
    fn read_from< R: Reader< 'a, C > >( reader: &mut R ) -> io::Result< Self > {
        let bytes = reader.read_value()?;
        Ok( CowRawData::Owned( bytes ) )
    }
}

impl< 'a, C: Context > Writable< C > for CowRawData< 'a > {
    fn write_to< 'this, T: ?Sized + Writer< 'this, C > >( &'this self, writer: &mut T ) -> io::Result< () > {
        match *self {
            CowRawData::Owned( ref data ) => data.write_to( writer ),
            CowRawData::Borrowed( RawData::Single( ref data ) ) => data.write_to( writer ),
            CowRawData::Borrowed( RawData::Split( ref left, ref right ) ) => {
                writer.write_u32( (left.len() + right.len()) as u32 )?;
                writer.write_bytes( &left )?;
                writer.write_bytes( &right )?;
                Ok(())
            }
        }
    }
}

impl< 'a > From< RawData< 'a > > for CowRawData< 'a > {
    fn from( data: RawData< 'a > ) -> Self {
        CowRawData::Borrowed( data )
    }
}

impl< 'a > From< &'a CowRawData< 'a > > for RawData< 'a > {
    fn from( data: &'a CowRawData< 'a > ) -> Self {
        match *data {
            CowRawData::Owned( ref bytes ) => RawData::Single( bytes.as_slice() ),
            CowRawData::Borrowed( RawData::Single( bytes ) ) => RawData::Single( bytes ),
            CowRawData::Borrowed( RawData::Split( left, right ) ) => RawData::Split( left, right )
        }
    }
}
