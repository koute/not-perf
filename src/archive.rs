use std::borrow::Cow;
use std::io;
use std::ops::Range;
use std::iter;

use speedy::{Readable, Writable, Context, Reader, Writer};

pub use nwind::{
    Inode,
    Bitness,
    UserFrame,
    LoadHeader
};

pub use speedy::Endianness;
pub use raw_data::CowRawData;

#[derive(Copy, Clone, Debug)]
pub struct DwarfReg {
    pub register: u16,
    pub value: u64
}

impl< 'a, C: Context > Readable< 'a, C > for DwarfReg {
    #[inline]
    fn read_from< R: Reader< 'a, C > >( reader: &mut R ) -> io::Result< Self > {
        let mut register = reader.read_u16()?;
        let value = reader.read_u64()?;

        // HACK: Compatibility with old profiling data for AMD64.
        if register == 0xff01 {
            register = 16;
        }

        Ok( DwarfReg { register, value } )
    }
}

impl< 'a, C: Context > Writable< C > for DwarfReg {
    #[inline]
    fn write_to< 'this, T: ?Sized + Writer< 'this, C > >( &'this self, writer: &mut T ) -> io::Result< () > {
        writer.write_u16( self.register )?;
        writer.write_u64( self.value )?;
        Ok(())
    }
}

pub const ARCHIVE_MAGIC: u32 = 0x4652504E;
pub const ARCHIVE_VERSION: u32 = 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Readable, Writable)]
pub enum Packet< 'a > {
    Header {
        magic: u32,
        version: u32
    },
    MachineInfo {
        cpu_count: u32,
        bitness: Bitness,
        endianness: Endianness,
        architecture: Cow< 'a, str >
    },
    ProcessInfo {
        pid: u32,
        executable: Cow< 'a, [u8] >,
        binary_id: Inode
    },
    Sample {
        timestamp: u64,
        pid: u32,
        tid: u32,
        cpu: u32,
        kernel_backtrace: Cow< 'a, [u64] >,
        user_backtrace: Cow< 'a, [UserFrame] >
    },
    BinaryInfo {
        inode: Inode,
        is_shared_object: bool,
        symbol_table_count: u16,
        path: Cow< 'a, [u8] >,
        debuglink: Cow< 'a, [u8] >,
        #[speedy(default_on_eof)]
        load_headers: Cow< 'a, [LoadHeader] >
    },
    StringTable {
        inode: Inode,
        offset: u64,
        data: Cow< 'a, [u8] >,
        #[speedy(default_on_eof)]
        path: Cow< 'a, [u8] >
    },
    SymbolTable {
        inode: Inode,
        offset: u64,
        string_table_offset: u64,
        is_dynamic: bool,
        data: Cow< 'a, [u8] >,
        #[speedy(default_on_eof)]
        path: Cow< 'a, [u8] >
    },
    FileBlob {
        path: Cow< 'a, [u8] >,
        data: Cow< 'a, [u8] >
    },
    RawSample {
        timestamp: u64,
        pid: u32,
        tid: u32,
        cpu: u32,
        kernel_backtrace: Cow< 'a, [u64] >,
        stack: CowRawData< 'a >,
        regs: Cow< 'a, [DwarfReg] >
    },
    BinaryBlob {
        inode: Inode,
        path: Cow< 'a, [u8] >,
        data: Cow< 'a, [u8] >
    },
    ThreadName {
        pid: u32,
        tid: u32,
        name: Cow< 'a, [u8] >
    },
    MemoryRegionMap {
        pid: u32,
        range: Range< u64 >,
        is_read: bool,
        is_write: bool,
        is_executable: bool,
        is_shared: bool,
        file_offset: u64,
        inode: u64,
        major: u32,
        minor: u32,
        name: Cow< 'a, [u8] >
    },
    MemoryRegionUnmap {
        pid: u32,
        range: Range< u64 >
    },
    Deprecated_BinaryMap {
        pid: u32,
        inode: Inode,
        base_address: u64
    },
    Deprecated_BinaryUnmap {
        pid: u32,
        inode: Inode,
        base_address: u64
    },
    Lost {
        count: u64
    },
    BuildId {
        inode: Inode,
        build_id: Vec< u8 >,
        #[speedy(default_on_eof)]
        path: Cow< 'a, [u8] >
    },
    BinaryLoaded {
        pid: u32,
        inode: Option< Inode >,
        name: Cow< 'a, [u8] >
    },
    BinaryUnloaded {
        pid: u32,
        inode: Option< Inode >,
        name: Cow< 'a, [u8] >
    }
}

#[derive(Debug)]
pub enum FramedPacket< 'a > {
    Known( Packet< 'a > ),
    Unknown( Cow< 'a, [u8] > )
}

impl< 'a, C: Context > Readable< 'a, C > for FramedPacket< 'a > {
    fn read_from< R: Reader< 'a, C > >( reader: &mut R ) -> io::Result< Self > {
        let length = reader.read_u32()? as usize;
        let bytes = reader.read_bytes_cow( length )?;
        match bytes {
            Cow::Borrowed( bytes ) => {
                match Packet::read_from_buffer( Endianness::LittleEndian, &bytes ) {
                    Ok( packet ) => Ok( FramedPacket::Known( packet ) ),
                    Err( _ ) => Ok( FramedPacket::Unknown( Cow::Borrowed( bytes ) ) )
                }
            },
            Cow::Owned( bytes ) => {
                match Packet::read_from_buffer_owned( Endianness::LittleEndian, &bytes ) {
                    Ok( packet ) => Ok( FramedPacket::Known( packet ) ),
                    Err( _ ) => Ok( FramedPacket::Unknown( Cow::Owned( bytes ) ) )
                }
            }
        }
    }
}

impl< 'a, C: Context > Writable< C > for FramedPacket< 'a > {
    fn write_to< 'this, T: ?Sized + Writer< 'this, C > >( &'this self, writer: &mut T ) -> io::Result< () > {
        match self {
            &FramedPacket::Known( ref packet ) => {
                let length = Writable::< C >::bytes_needed( packet ) as u32;
                writer.write_u32( length )?;
                writer.write_value( packet )?;

                Ok(())
            },
            &FramedPacket::Unknown( ref bytes ) => {
                let length = bytes.len() as u32;
                writer.write_u32( length )?;
                writer.write_bytes( &bytes )?;

                Ok(())
            }
        }
    }
}

pub struct ArchiveReader< T: io::Read > {
    inner: T
}

impl< T: io::Read > ArchiveReader< T > {
    pub fn new( inner: T ) -> Self {
        ArchiveReader { inner }
    }

    pub fn validate_header( mut self ) -> io::Result< Self > {
        match self.next() {
            None => Ok( self ),
            Some( Err( error ) ) => Err( error ),
            Some( Ok( FramedPacket::Known( Packet::Header { magic, version } ) ) ) => {
                if magic != ARCHIVE_MAGIC {
                    panic!( "This is not a valid data file!" );
                }

                if version != ARCHIVE_VERSION {
                    panic!( "Unexpected version: expected '{}', found '{}'", ARCHIVE_VERSION, version )
                }

                Ok( self )
            },
            _ => {
                panic!( "A valid header was not found!" );
            }
        }
    }

    pub fn skip_unknown( self ) -> iter::FilterMap< Self, fn( io::Result< FramedPacket< 'static > > ) -> Option< io::Result< Packet< 'static > > > > {
        self.filter_map( |packet| {
            match packet {
                Err( error ) => Some( Err( error ) ),
                Ok( FramedPacket::Known( packet ) ) => Some( Ok( packet ) ),
                Ok( FramedPacket::Unknown( bytes ) ) => {
                    let id: u32 = Readable::read_from_buffer( Endianness::LittleEndian, &bytes ).unwrap();
                    warn!( "Unknown packet encountered: id = 0x{:02X}", id );
                    None
                }
            }
        })
    }
}

impl< T: io::Read > Iterator for ArchiveReader< T > {
    type Item = io::Result< FramedPacket< 'static > >;
    fn next( &mut self ) -> Option< Self::Item > {
        match Readable::read_from_stream( Endianness::LittleEndian, &mut self.inner ) {
            Ok( framed ) => Some( Ok( framed ) ),
            Err( ref err ) if err.kind() == io::ErrorKind::UnexpectedEof => None,
            Err( err ) => Some( Err( err ) )
        }
    }
}
