use std::ops::Range;

use scroll;
use scroll::ctx::TryFromCtx;
use goblin::elf::header::{EI_DATA, EI_CLASS, ELFDATA2LSB, ELFDATA2MSB, ELFCLASS32, ELFCLASS64, SIZEOF_IDENT};
use goblin::elf::section_header::SHT_STRTAB;
use goblin::elf32::header::Header as Header32;
use goblin::elf64::header::Header as Header64;
use goblin::elf32::section_header::SectionHeader as SectionHeader32;
use goblin::elf64::section_header::SectionHeader as SectionHeader64;
use goblin::elf32::program_header::ProgramHeader as ProgramHeader32;
use goblin::elf64::program_header::ProgramHeader as ProgramHeader64;
use goblin::elf32::sym::Sym as Sym32;
use goblin::elf64::sym::Sym as Sym64;

pub use scroll::Endian;
pub use goblin::elf::header::Header;
pub use goblin::elf::section_header::SectionHeader;
pub use goblin::elf::program_header::ProgramHeader;
pub use goblin::elf::sym::Sym;
pub use goblin::strtab::Strtab;

pub trait Elf< 'a > {
    type SectionHeaderIter: Iterator< Item = SectionHeader >;
    type ProgramHeaderIter: Iterator< Item = ProgramHeader >;

    fn is_64_bit( &self ) -> bool;
    fn endianness( &self ) -> Endian;
    fn header( &self ) -> &Header;
    fn section_headers( &self ) -> Self::SectionHeaderIter;
    fn program_headers( &self ) -> Self::ProgramHeaderIter;
    fn get_section_header( &self, index: usize ) -> Option< SectionHeader >;
    fn get_section_body( &self, section_header: &SectionHeader ) -> &'a [u8];
    fn get_section_body_range( &self, section_header: &SectionHeader ) -> Range< u64 >;
    fn get_strtab( &self, section_header: &SectionHeader ) -> Option< Strtab< 'a > >;
}

macro_rules! define_elf {
    ($name:ident, $section_header_iter:ident, $program_header_iter:ident, $is_64:expr) => {
        pub struct $name< 'a > {
            bytes: &'a [u8],
            header: Header,
            endianness: Endian
        }

        impl< 'a > Elf< 'a > for $name< 'a > {
            type SectionHeaderIter = $section_header_iter< 'a >;
            type ProgramHeaderIter = $program_header_iter< 'a >;

            #[inline]
            fn is_64_bit( &self ) -> bool {
                $is_64
            }

            #[inline]
            fn endianness( &self ) -> Endian {
                self.endianness
            }

            #[inline]
            fn header( &self ) -> &Header {
                &self.header
            }

            #[inline]
            fn section_headers( &self ) -> Self::SectionHeaderIter {
                let header = &self.header;
                let bytes = &self.bytes[ header.e_shoff as usize..header.e_shoff as usize + (header.e_shnum as usize * header.e_shentsize as usize) ];

                Self::SectionHeaderIter::new( bytes, self.endianness )
            }

            #[inline]
            fn program_headers( &self ) -> Self::ProgramHeaderIter {
                let header = &self.header;
                let bytes = &self.bytes[ header.e_phoff as usize..header.e_phoff as usize + (header.e_phnum as usize * header.e_phentsize as usize) ];

                Self::ProgramHeaderIter::new( bytes, self.endianness )
            }

            #[inline]
            fn get_section_header( &self, index: usize ) -> Option< SectionHeader > {
                let header = &self.header;
                let start = header.e_shoff as usize + (index * header.e_shentsize as usize);
                let end = header.e_shoff as usize + (header.e_shnum as usize * header.e_shentsize as usize);
                if start >= end {
                    return None;
                }

                let bytes = &self.bytes[ start..end ];
                Self::SectionHeaderIter::new( bytes, self.endianness ).next()
            }

            #[inline]
            fn get_section_body( &self, section_header: &SectionHeader ) -> &'a [u8] {
                &self.bytes[ section_header.sh_offset as usize..section_header.sh_offset as usize + section_header.sh_size as usize ]
            }

            #[inline]
            fn get_section_body_range( &self, section_header: &SectionHeader ) -> Range< u64 > {
                section_header.sh_offset as u64..section_header.sh_offset as u64 + section_header.sh_size as u64
            }

            #[inline]
            fn get_strtab( &self, section_header: &SectionHeader ) -> Option< Strtab< 'a > > {
                if section_header.sh_type as u32 != SHT_STRTAB {
                    return None;
                }

                let bytes = self.get_section_body( &section_header );
                let strtab = Strtab::new( bytes, 0x0 );

                Some( strtab )
            }
        }
    }
}

define_elf!( Elf32, Elf32SectionHeaderIter, Elf32ProgramHeaderIter, false );
define_elf!( Elf64, Elf64SectionHeaderIter, Elf64ProgramHeaderIter, true );

macro_rules! define_iter {
    ($name:ident, $output_ty:ty, $converter:expr) => {
        pub struct $name< 'a > {
            bytes: &'a [u8],
            position: usize,
            endianness: Endian
        }

        impl< 'a > Iterator for $name< 'a > {
            type Item = $output_ty;

            #[inline]
            fn next( &mut self ) -> Option< Self::Item > {
                let (value, next_position) = TryFromCtx::try_from_ctx( &self.bytes[ self.position.. ], self.endianness ).ok()?;
                self.position += next_position;
                Some( $converter( value ) )
            }
        }

        impl< 'a > $name< 'a > {
            #[inline]
            pub fn new( bytes: &'a [u8], endianness: Endian ) -> Self {
                $name {
                    bytes,
                    position: 0,
                    endianness
                }
            }
        }
    }
}

define_iter! {
    Elf32SectionHeaderIter, SectionHeader, |header: SectionHeader32| {
        SectionHeader {
            sh_name: header.sh_name as usize,
            sh_type: header.sh_type,
            sh_flags: header.sh_flags as u64,
            sh_addr: header.sh_addr as u64,
            sh_offset: header.sh_offset as u64,
            sh_size: header.sh_size as u64,
            sh_link: header.sh_link,
            sh_info: header.sh_info,
            sh_addralign: header.sh_addralign as u64,
            sh_entsize: header.sh_entsize as u64
        }
    }
}

define_iter! {
    Elf64SectionHeaderIter, SectionHeader, |header: SectionHeader64| {
        SectionHeader {
            sh_name: header.sh_name as usize,
            sh_type: header.sh_type,
            sh_flags: header.sh_flags,
            sh_addr: header.sh_addr,
            sh_offset: header.sh_offset,
            sh_size: header.sh_size,
            sh_link: header.sh_link,
            sh_info: header.sh_info,
            sh_addralign: header.sh_addralign,
            sh_entsize: header.sh_entsize
        }
    }
}

define_iter! {
    Elf32ProgramHeaderIter, ProgramHeader, |header: ProgramHeader32| {
        ProgramHeader {
            p_type: header.p_type,
            p_flags: header.p_flags,
            p_offset: header.p_offset as u64,
            p_vaddr: header.p_vaddr as u64,
            p_paddr: header.p_paddr as u64,
            p_filesz: header.p_filesz as u64,
            p_memsz: header.p_memsz as u64,
            p_align: header.p_align as u64
        }
    }
}

define_iter! {
    Elf64ProgramHeaderIter, ProgramHeader, |header: ProgramHeader64| {
        ProgramHeader {
            p_type: header.p_type,
            p_flags: header.p_flags,
            p_offset: header.p_offset,
            p_vaddr: header.p_vaddr,
            p_paddr: header.p_paddr,
            p_filesz: header.p_filesz,
            p_memsz: header.p_memsz,
            p_align: header.p_align
        }
    }
}

define_iter! {
    Elf32SymIter, Sym, |sym: Sym32| {
        Sym {
            st_name: sym.st_name as usize,
            st_info: sym.st_info,
            st_other: sym.st_other,
            st_shndx: sym.st_shndx as usize,
            st_value: sym.st_value as u64,
            st_size: sym.st_size as u64
        }
    }
}

define_iter! {
    Elf64SymIter, Sym, |sym: Sym64| {
        Sym {
            st_name: sym.st_name as usize,
            st_info: sym.st_info,
            st_other: sym.st_other,
            st_shndx: sym.st_shndx as usize,
            st_value: sym.st_value,
            st_size: sym.st_size
        }
    }
}

#[macro_export]
macro_rules! parse_elf {
    ($elf:expr, $callback:expr) => {{
        use elf::{Elf, ElfKind, call_callback};

        match $elf {
            ElfKind::Elf32( elf ) => call_callback( elf, $callback ),
            ElfKind::Elf64( elf ) => call_callback( elf, $callback )
        }
    }}
}

pub enum ElfKind< 'a > {
    Elf32( Elf32< 'a > ),
    Elf64( Elf64< 'a > )
}

#[inline]
pub fn call_callback< 'a, R, E: Elf< 'a >, F: FnOnce( E ) -> R >( elf: E, callback: F ) -> R {
    callback( elf )
}

pub fn parse< 'a >( bytes: &'a [u8] ) -> Result< ElfKind< 'a >, &'static str > {
    if bytes.len() < SIZEOF_IDENT {
        return Err( "not an ELF file" );
    }

    let endianness =
        match bytes[ EI_DATA ] {
            ELFDATA2LSB => scroll::LE,
            ELFDATA2MSB => scroll::BE,
            _ => return Err( "invalid endianness" )
    };

    let is_64 =
        match bytes[ EI_CLASS ] {
            ELFCLASS32 => false,
            ELFCLASS64 => true,
            _ => return Err( "invalid bitness" )
        };

    if is_64 {
        let header = Header64::parse( bytes ).map_err( |_| "cannot parse ELF header" )?;
        let elf = Elf64 {
            bytes,
            header: Header {
                e_ident: header.e_ident,
                e_type: header.e_type,
                e_machine: header.e_machine,
                e_version: header.e_version,
                e_entry: header.e_entry,
                e_phoff: header.e_phoff,
                e_shoff: header.e_shoff,
                e_flags: header.e_flags,
                e_ehsize: header.e_ehsize,
                e_phentsize: header.e_phentsize,
                e_phnum: header.e_phnum,
                e_shentsize: header.e_shentsize,
                e_shnum: header.e_shnum,
                e_shstrndx: header.e_shstrndx
            },
            endianness
        };

        Ok( ElfKind::Elf64( elf ) )
    } else {
        let header = Header32::parse( bytes ).map_err( |_| "cannot parse ELF header" )?;
        let elf = Elf32 {
            bytes,
            header: Header {
                e_ident: header.e_ident,
                e_type: header.e_type,
                e_machine: header.e_machine,
                e_version: header.e_version,
                e_entry: header.e_entry as u64,
                e_phoff: header.e_phoff as u64,
                e_shoff: header.e_shoff as u64,
                e_flags: header.e_flags,
                e_ehsize: header.e_ehsize,
                e_phentsize: header.e_phentsize,
                e_phnum: header.e_phnum,
                e_shentsize: header.e_shentsize,
                e_shnum: header.e_shnum,
                e_shstrndx: header.e_shstrndx
            },
            endianness
        };

        Ok( ElfKind::Elf32( elf ) )
    }
}
