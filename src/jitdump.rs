use std::path::Path;
use std::borrow::Cow;
use std::convert::TryInto;

// These definitions were copied from `wasmtime` with minor modifications:
//   https://github.com/bytecodealliance/wasmtime/blob/03715dda9d536cc8f81d4ed9d5d152139fcd2eb0/crates/jit-debug/src/perf_jitdump.rs

/// Fixed-sized header for each jitdump file
#[derive(Debug, Default, Clone, Copy)]
#[derive(speedy::Readable)]
#[repr(C)]
pub struct FileHeader {
    /// `uint32_t magic`: a magic number tagging the file type. The value is 4-byte long and represents the
    /// string "JiTD" in ASCII form. It is 0x4A695444 or 0x4454694a depending on the endianness. The field can
    /// be used to detect the endianness of the file
    pub magic: u32,
    /// `uint32_t version`: a 4-byte value representing the format version. It is currently set to 2
    pub version: u32,
    /// `uint32_t total_size`: size in bytes of file header
    pub size: u32,
    /// `uint32_t elf_mach`: ELF architecture encoding (ELF e_machine value as specified in /usr/include/elf.h)
    pub e_machine: u32,
    /// `uint32_t pad1`: padding. Reserved for future use
    pub pad1: u32,
    /// `uint32_t pid`: JIT runtime process identification (OS specific)
    pub pid: u32,
    /// `uint64_t timestamp`: timestamp of when the file was created
    pub timestamp: u64,
    /// `uint64_t flags`: a bitmask of flags
    pub flags: u64,
}

/// The CodeLoadRecord is used for describing jitted functions
#[derive(Debug, Default, Clone, Copy)]
#[derive(speedy::Readable)]
#[repr(C)]
struct CodeLoadRecordHeader {
    /// `uint32_t pid`: OS process id of the runtime generating the jitted code
    pub pid: u32,
    /// `uint32_t tid`: OS thread identification of the runtime thread generating the jitted code
    pub tid: u32,
    /// `uint64_t vma`: virtual address of jitted code start
    pub virtual_address: u64,
    /// `uint64_t code_addr`: code start address for the jitted code. By default vma = code_addr
    pub address: u64,
    /// `uint64_t code_size`: size in bytes of the generated jitted code
    pub size: u64,
    /// `uint64_t code_index`: unique identifier for the jitted code (see below)
    pub index: u64,
}

/// Describes source line information for a jitted function
#[derive(Debug, Default)]
#[derive(speedy::Readable)]
#[repr(C)]
struct DebugEntry {
    /// `uint64_t code_addr`: address of function for which the debug information is generated
    pub address: u64,
    /// `uint32_t line`: source file line number (starting at 1)
    pub line: u32,
    /// `uint32_t discrim`: column discriminator, 0 is default
    pub discriminator: u32,
    /// `char name[n]`: source file name in ASCII, including null termination
    pub filename: String,
}

/// Describes debug information for a jitted function. An array of debug entries are
/// appended to this record during writting. Note, this record must preceed the code
/// load record that describes the same jitted function.
#[derive(Debug, Default, Clone, Copy)]
#[derive(speedy::Readable)]
#[repr(C)]
struct DebugInfoRecordHeader {
    /// `uint64_t code_addr`: address of function for which the debug information is generated
    pub address: u64,
    /// `uint64_t nr_entry`: number of debug entries for the function appended to this record
    pub count: u64,
}

/// Each record starts with this fixed size record header which describes the record that follows
#[derive(Debug, Default, Clone, Copy)]
#[derive(speedy::Readable)]
#[repr(C)]
struct RecordHeader {
    /// uint32_t id: a value identifying the record type (see below)
    pub id: u32,
    /// uint32_t total_size: the size in bytes of the record including the header.
    pub record_size: u32,
    /// uint64_t timestamp: a timestamp of when the record was created.
    pub timestamp: u64,
}

pub enum Record< 'a > {
    CodeLoad {
        timestamp: u64,
        pid: u32,
        tid: u32,
        virtual_address: u64,
        address: u64,
        index: u64,
        name: String,
        code: Cow< 'a, [u8] >
    },
    Unknown {
        id: u32,
        timestamp: u64,
        payload: Cow< 'a, [u8] >
    }
}

impl< 'a, C: speedy::Context > speedy::Readable< 'a, C > for Record< 'a > {
    #[inline]
    fn read_from< R: speedy::Reader< 'a, C > >( reader: &mut R ) -> Result< Self, C::Error > {
        let header: RecordHeader = reader.read_value()?;
        match header.id {
            0 => { // JIT_CODE_LOAD
                let record_header: CodeLoadRecordHeader = reader.read_value()?;

                let mut name = Vec::new();
                while reader.peek_u8()? != 0 {
                    name.push( reader.read_u8()? );
                }
                reader.read_u8()?;

                let name = String::from_utf8( name ).map_err( |_| speedy::Error::custom( "JIT_CODE_LOAD record has a name which is not valid UTF-8" ) )?;
                let code = reader.read_cow( record_header.size.try_into().map_err( |_| speedy::Error::custom( "out of range size" ) )? )?;

                Ok( Record::CodeLoad {
                    timestamp: header.timestamp,
                    pid: record_header.pid,
                    tid: record_header.tid,
                    virtual_address: record_header.virtual_address,
                    address: record_header.address,
                    index: record_header.index,
                    name,
                    code
                })
            },
            // 2 => { // JIT_CODE_DEBUG_INFO
            //     // TODO
            // },
            _ => {
                Ok( Record::Unknown {
                    id: header.id,
                    timestamp: header.timestamp,
                    payload: reader.read_cow( header.record_size as usize )?
                })
            }
        }
    }
}

#[derive(speedy::Readable)]
struct JitDumpFile< 'a > {
    _header: FileHeader,
    #[speedy(length = ..)]
    records: Vec< Record< 'a > >
}

pub struct JitDump< 'a > {
    pub records: Vec< Record< 'a > >
}

impl< 'a > JitDump< 'a > {
    pub fn load( path: &Path ) -> Result< Self, std::io::Error > {
        let file: JitDumpFile = speedy::Readable::read_from_file( path )?;
        Ok( Self {
            records: file.records
        })
    }
}
