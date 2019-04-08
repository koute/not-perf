use std::str;
use std::io;
use std::fs::File;
use std::ops::{Range, Deref, Index};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::fmt;

use memmap::Mmap;
use goblin::elf::header as elf_header;
use goblin::elf::section_header::{SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB};
use goblin::elf::program_header::PT_LOAD;
use gimli;

use crate::elf::{self, Endian};
use crate::utils::{StableIndex, get_major, get_minor};
use crate::types::{Inode, Bitness, Endianness};

enum Blob {
    Mmap( Mmap ),
    StaticSlice( &'static [u8] ),
    Owned( Vec< u8 > )
}

impl Deref for Blob {
    type Target = [u8];

    #[inline]
    fn deref( &self ) -> &Self::Target {
        match *self {
            Blob::Mmap( ref mmap ) => &mmap,
            Blob::StaticSlice( slice ) => slice,
            Blob::Owned( ref bytes ) => &bytes
        }
    }
}

#[derive(Debug)]
pub struct SymbolTable {
    pub range: Range< u64 >,
    pub strtab_range: Range< u64 >,
    pub is_dynamic: bool
}

#[derive(Clone, Debug, Readable, Writable)]
pub struct LoadHeader {
    pub address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool
}

pub struct BinaryData {
    inode: Option< Inode >,
    name: String,
    blob: Blob,
    data_range: Option< Range< usize > >,
    text_range: Option< Range< usize > >,
    eh_frame_range: Option< Range< usize > >,
    eh_frame_hdr_range: Option< Range< usize > >,
    debug_frame_range: Option< Range< usize > >,
    gnu_debuglink_range: Option< Range< usize > >,
    arm_extab_range: Option< Range< usize > >,
    arm_exidx_range: Option< Range< usize > >,
    is_shared_object: bool,
    symbol_tables: Vec< SymbolTable >,
    load_headers: Vec< LoadHeader >,
    architecture: &'static str,
    endianness: Endianness,
    bitness: Bitness,
    build_id: Option< Vec< u8 > >
}

impl BinaryData {
    #[cfg(unix)]
    pub fn load_from_fs< P: AsRef< Path > >( path: P ) -> io::Result< Self > {
        let path = path.as_ref();
        debug!( "Loading binary {:?}...", path );

        let fp = File::open( path )?;
        let mmap = unsafe { Mmap::map( &fp )? };
        let blob = Blob::Mmap( mmap );

        let metadata = fp.metadata()?;
        let inode = metadata.ino();
        let dev = metadata.dev();
        let dev_major = get_major( dev );
        let dev_minor = get_minor( dev );
        let inode = Inode { inode, dev_major, dev_minor };

        let mut data = BinaryData::load( &path.to_string_lossy(), blob )?;
        data.set_inode( inode );

        Ok( data )
    }

    #[cfg(not(unix))]
    pub fn load_from_fs< P: AsRef< Path > >( _: P ) -> io::Result< Self > {
        unimplemented!();
    }

    pub fn load_from_static_slice( name: &str, slice: &'static [u8] ) -> io::Result< Self > {
        debug!( "Loading binary '{}'...", name );

        let blob = Blob::StaticSlice( slice );
        BinaryData::load( name, blob )
    }

    pub fn load_from_owned_bytes( name: &str, bytes: Vec< u8 > ) -> io::Result< Self > {
        debug!( "Loading binary '{}'...", name );

        let blob = Blob::Owned( bytes );
        BinaryData::load( name, blob )
    }

    pub fn check_inode( &self, expected_inode: Inode ) -> io::Result< () > {
        if self.inode != Some( expected_inode ) {
            return Err( io::Error::new( io::ErrorKind::Other, format!( "major/minor/inode of {:?} doesn't match the expected value: {:?} != {:?}", self.name, self.inode, expected_inode ) ) );
        }

        Ok(())
    }

    fn load( path: &str, blob: Blob ) -> io::Result< Self > {
        let mut data_range = None;
        let mut text_range = None;
        let mut eh_frame_range = None;
        let mut eh_frame_hdr_range = None;
        let mut debug_frame_range = None;
        let mut gnu_debuglink_range = None;
        let mut arm_extab_range = None;
        let mut arm_exidx_range = None;
        let mut build_id_range = None;
        let mut build_id = None;
        let mut is_shared_object = false;
        let mut symbol_tables = Vec::new();
        let mut load_headers = Vec::new();
        let mut endianness = Endianness::LittleEndian;
        let mut bitness = Bitness::B32;
        let mut architecture = "";

        {
            let elf = elf::parse( &blob ).map_err( |err| io::Error::new( io::ErrorKind::Other, err ) )?;
            parse_elf!( elf, |elf| {
                endianness = match elf.endianness() {
                    Endian::Little => Endianness::LittleEndian,
                    Endian::Big => Endianness::BigEndian
                };

                bitness = if elf.is_64_bit() {
                    Bitness::B64
                } else {
                    Bitness::B32
                };

                is_shared_object = match elf.header().e_type {
                    elf_header::ET_EXEC => false,
                    elf_header::ET_DYN => true,
                    _ => {
                        return Err( io::Error::new( io::ErrorKind::Other, format!( "unknown ELF type '{}' for {:?}", elf.header().e_type, path ) ) );
                    }
                };

                architecture = match elf.header().e_machine {
                    elf_header::EM_X86_64 => "amd64",
                    elf_header::EM_386 => "x86",
                    elf_header::EM_ARM => "arm",
                    elf_header::EM_MIPS => {
                        if elf.is_64_bit() {
                            "mips64"
                        } else {
                            "mips"
                        }
                    },
                    kind => {
                        return Err( io::Error::new( io::ErrorKind::Other, format!( "unknown machine type '{}' for {:?}", kind, path ) ) );
                    }
                };

                let name_strtab_header = elf.get_section_header( elf.header().e_shstrndx as usize )
                    .ok_or_else( || io::Error::new( io::ErrorKind::Other, format!( "missing section header for section names strtab for {:?}", path ) ) )?;

                let name_strtab = elf.get_strtab( &name_strtab_header )
                    .ok_or_else( || io::Error::new( io::ErrorKind::Other, format!( "missing strtab for section names strtab for {:?}", path ) ) )?;

                for header in elf.section_headers() {
                    let ty = header.sh_type as u32;
                    if ty == SHT_SYMTAB || ty == SHT_DYNSYM {
                        let is_dynamic = ty == SHT_DYNSYM;
                        let strtab_key = header.sh_link as usize;
                        if let Some( strtab_header ) = elf.get_section_header( strtab_key ) {
                            if strtab_header.sh_type as u32 == SHT_STRTAB {
                                let strtab_range = elf.get_section_body_range( &strtab_header );
                                let symtab_range = elf.get_section_body_range( &header );
                                symbol_tables.push( SymbolTable {
                                    range: symtab_range,
                                    strtab_range,
                                    is_dynamic
                                });
                            }
                        }
                    }

                    let section_name = match name_strtab.get( header.sh_name ) {
                        Some( Ok( name ) ) => name,
                        _ => continue
                    };

                    let out_range = match section_name {
                        ".data" => Some( &mut data_range ),
                        ".text" => Some( &mut text_range ),
                        ".eh_frame" => Some( &mut eh_frame_range ),
                        ".eh_frame_hdr" => Some( &mut eh_frame_hdr_range ),
                        ".debug_frame" => Some( &mut debug_frame_range ),
                        ".gnu_debuglink" => Some( &mut gnu_debuglink_range ),
                        ".ARM.extab" => Some( &mut arm_extab_range ),
                        ".ARM.exidx" => Some( &mut arm_exidx_range ),
                        ".note.gnu.build-id" => Some( &mut build_id_range ),
                        _ => None
                    };

                    let offset = header.sh_offset as usize;
                    let length = header.sh_size as usize;
                    let range = offset..offset + length;
                    if let Some( _ ) = blob.get( range.clone() ) {
                        if let Some( out_range ) = out_range {
                            *out_range = Some( range.clone() );
                        }
                    }
                }

                if let Some( range ) = build_id_range {
                    let data = blob.get( range.clone() ).unwrap();
                    let note = match endianness {
                        Endianness::LittleEndian => elf.parse_note( data ),
                        Endianness::BigEndian => elf.parse_note( data )
                    };

                    if let Some( note ) = note {
                        build_id = Some( note.desc.into() );
                    }
                }

                for header in elf.program_headers() {
                    if header.p_type != PT_LOAD {
                        continue;
                    }

                    let entry = LoadHeader {
                        address: header.p_vaddr,
                        file_offset: header.p_offset,
                        file_size: header.p_filesz,
                        memory_size: header.p_memsz,
                        alignment: header.p_align,
                        is_readable: header.is_read(),
                        is_writable: header.is_write(),
                        is_executable: header.is_executable()
                    };

                    load_headers.push( entry );
                }

                Ok(())
            })?;
        }

        let binary = BinaryData {
            inode: None,
            name: path.to_string(),
            blob,
            data_range,
            text_range,
            eh_frame_range,
            eh_frame_hdr_range,
            debug_frame_range,
            gnu_debuglink_range,
            arm_extab_range,
            arm_exidx_range,
            is_shared_object,
            symbol_tables,
            load_headers,
            architecture,
            endianness,
            bitness,
            build_id
        };

        Ok( binary )
    }

    #[inline]
    pub fn inode( &self ) -> Option< Inode > {
        self.inode
    }

    #[inline]
    pub fn set_inode( &mut self, inode: Inode ) {
        self.inode = Some( inode );
    }

    #[inline]
    pub fn name( &self ) -> &str {
        &self.name
    }

    #[inline]
    pub fn architecture( &self ) -> &str {
        self.architecture
    }

    #[inline]
    pub fn endianness( &self ) -> Endianness {
        self.endianness
    }

    #[inline]
    pub fn bitness( &self ) -> Bitness {
        self.bitness
    }

    #[inline]
    pub fn symbol_tables( &self ) -> &[SymbolTable] {
        &self.symbol_tables
    }

    #[inline]
    pub fn as_bytes( &self ) -> &[u8] {
        &self.blob
    }

    #[inline]
    pub fn is_shared_object( &self ) -> bool {
        self.is_shared_object
    }

    #[inline]
    pub fn data_range( &self ) -> Option< Range< usize > > {
        self.data_range.clone()
    }

    #[inline]
    pub fn text_range( &self ) -> Option< Range< usize > > {
        self.text_range.clone()
    }

    #[inline]
    pub fn eh_frame_range( &self ) -> Option< Range< usize > > {
        self.eh_frame_range.clone()
    }

    #[inline]
    pub fn eh_frame_hdr_range( &self ) -> Option< Range< usize > > {
        self.eh_frame_hdr_range.clone()
    }

    #[inline]
    pub fn debug_frame_range( &self ) -> Option< Range< usize > > {
        self.debug_frame_range.clone()
    }

    #[inline]
    pub fn gnu_debuglink_range( &self ) -> Option< Range< usize > > {
        self.gnu_debuglink_range.clone()
    }

    #[inline]
    pub fn arm_extab_range( &self ) -> Option< Range< usize > > {
        self.arm_extab_range.clone()
    }

    #[inline]
    pub fn arm_exidx_range( &self ) -> Option< Range< usize > > {
        self.arm_exidx_range.clone()
    }

    fn get_section_range( &self, name: &str ) -> Option< Range< usize > > {
        let elf = elf::parse( &self.blob ).map_err( |err| io::Error::new( io::ErrorKind::Other, err ) ).unwrap();
        parse_elf!( elf, |elf| {
            let name_strtab_header = elf.get_section_header( elf.header().e_shstrndx as usize ).unwrap();
            let name_strtab = elf.get_strtab( &name_strtab_header ).unwrap();

            for header in elf.section_headers() {
                let section_name = match name_strtab.get( header.sh_name ) {
                    Some( Ok( name ) ) => name,
                    _ => continue
                };

                if section_name != name {
                    continue;
                }

                let offset = header.sh_offset as usize;
                let length = header.sh_size as usize;
                let range = offset..offset + length;
                if let Some( _ ) = self.blob.get( range.clone() ) {
                    return Some( range );
                }
            }

            None
        })
    }

    #[inline]
    pub fn get_empty_section( data: &Arc< BinaryData > ) -> BinaryDataReader {
        Self::get_range_reader( data, 0..0 )
    }

    #[inline]
    pub fn get_section_or_empty< S >( data: &Arc< BinaryData > ) -> S
        where S: From< gimli::EndianReader< gimli::RunTimeEndian, BinaryDataSlice > > +
                 gimli::Section< gimli::EndianReader< gimli::RunTimeEndian, BinaryDataSlice > >

    {
        let range = match data.get_section_range( S::section_name() ) {
            Some( range ) => range.clone(),
            None => 0..0
        };
        Self::get_range_reader( data, range ).into()
    }

    #[inline]
    fn get_range_reader( data: &Arc< BinaryData >, range: Range< usize > ) -> BinaryDataReader {
        let endianness = match data.endianness() {
            Endianness::LittleEndian => gimli::RunTimeEndian::Little,
            Endianness::BigEndian => gimli::RunTimeEndian::Big
        };

        gimli::EndianReader::new( Self::subslice( data.clone(), range ), endianness ).into()
    }

    #[inline]
    pub fn load_headers( &self ) -> &[LoadHeader] {
        &self.load_headers
    }

    #[inline]
    pub fn build_id( &self ) -> Option< &[u8] > {
        self.build_id.as_ref().map( |id| id.as_slice() )
    }

    #[inline]
    pub fn debuglink( &self ) -> Option< &[u8] > {
        let debuglink = &self.as_bytes()[ self.gnu_debuglink_range.clone()? ];
        let debuglink_length = debuglink.iter().position( |&byte| byte == 0 ).unwrap_or( debuglink.len() );
        if debuglink_length == 0 {
            return None;
        }

        Some( &debuglink[ 0..debuglink_length ] )
    }

    #[inline]
    fn subslice( data: Arc< BinaryData >, range: Range< usize > ) -> BinaryDataSlice {
        BinaryDataSlice {
            data,
            range
        }
    }
}

impl Deref for BinaryData {
    type Target = [u8];

    #[inline]
    fn deref( &self ) -> &Self::Target {
        self.as_bytes()
    }
}

unsafe impl StableIndex for BinaryData {}

impl Index< Range< u64 > > for BinaryData {
    type Output = [u8];

    #[inline]
    fn index( &self, index: Range< u64 > ) -> &Self::Output {
        &self.as_bytes()[ index.start as usize..index.end as usize ]
    }
}

#[derive(Clone)]
pub struct BinaryDataSlice {
    data: Arc< BinaryData >,
    range: Range< usize >
}

impl fmt::Debug for BinaryDataSlice {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        write!( fmt, "BinaryData[{:?}]", self.range )
    }
}

impl Deref for BinaryDataSlice {
    type Target = [u8];

    #[inline]
    fn deref( &self ) -> &Self::Target {
        &self.data.as_bytes()[ self.range.clone() ]
    }
}

unsafe impl gimli::StableDeref for BinaryDataSlice {}
unsafe impl gimli::CloneStableDeref for BinaryDataSlice {}

pub type BinaryDataReader = gimli::EndianReader< gimli::RunTimeEndian, BinaryDataSlice >;
