use std::fs;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::ops::{Range, Index};
use std::cmp::min;
use std::fmt;
use std::error::Error;
use std::borrow::Cow;

use speedy::Endianness;
use regex::Regex;

use proc_maps::Region;
use nwind::arch::{self, Architecture, Registers};
use nwind::{
    DwarfRegs,
    RangeMap,
    Symbols,
    BinaryData,
    SymbolTable,
    IAddressSpace,
    AddressSpace,
    LoadHeader,
    BinaryId,
    StringInterner,
    StringId,
    DebugInfoIndex
};

use archive::{Packet, Inode, Bitness, UserFrame, ArchiveReader};
use utils::StableIndex;
use kallsyms::{self, KernelSymbol};

use stack_reader::StackReader;

#[derive(PartialEq, Eq, Debug, Hash)]
enum FrameKind {
    Process( u32 ),
    Thread( u32 ),
    MainThread,
    User( u64 ),
    UserBinary( BinaryId, u64 ),
    UserSymbol( BinaryId, u64, bool, StringId ),
    Kernel( u64 ),
    KernelSymbol( usize )
}

struct Process {
    pid: u32,
    executable: String,
    memory_regions: RangeMap< Region >,
    base_address_for_binary: HashMap< BinaryId, u64 >,
    address_space: Box< IAddressSpace >,
    address_space_needs_reload: bool
}

impl Process {
    fn reload_if_necessary( &mut self, debug_info_index: &DebugInfoIndex, binary_by_id: &mut HashMap< BinaryId, Binary > ) {
        if !self.address_space_needs_reload {
            return;
        }

        self.address_space_needs_reload = false;
        let regions = self.memory_regions.values().cloned().collect();
        let base_address_for_binary = &mut self.base_address_for_binary;

        self.address_space.reload( regions, &mut |region, handle| {
            let binary_id = region.into();
            if let Some( binary ) = binary_by_id.get_mut( &binary_id ) {
                if let Some( ref data ) = binary.data {
                    handle.set_binary( data.clone() );
                } else {
                    for load_header in binary.load_headers.iter().cloned() {
                        handle.add_region_mapping( load_header );
                    }

                    // For compatibility with old profiling data.
                    if let Some( &base_address ) = base_address_for_binary.get( &binary_id ) {
                        let address = region.start - base_address;
                        let size = region.end - region.start;
                        debug!( "Old profiling data compatibility: adding PT_LOAD region for '{}': {:016X}-{:016X}", region.name, address, address + size );
                        handle.add_region_mapping( LoadHeader {
                            address,
                            file_offset: 0,
                            file_size: size,
                            memory_size: size,
                            alignment: 0,
                            is_readable: true,
                            is_writable: false,
                            is_executable: true
                        });
                    }
                }

                binary.load_debug_info( debug_info_index );

                if let Some( symbols ) = binary.symbols.take() {
                    handle.add_symbols( symbols );
                }

                if let Some( ref data ) = binary.debug_data {
                    handle.set_debug_binary( data.clone() );
                }
            }
        });
    }
}

struct Binary {
    path: String,
    basename: String,
    string_tables: Arc< BinaryChunks >,
    symbol_table_count: u16,
    symbol_tables_chunks: BinaryChunks,
    symbol_tables: Vec< SymbolTable >,
    symbols: Option< Symbols >,
    data: Option< Arc< BinaryData > >,
    debug_data: Option< Arc< BinaryData > >,
    load_headers: Vec< LoadHeader >,
    build_id: Option< Vec< u8 > >,
    debuglink: Option< Vec< u8 > >
}

impl Binary {
    fn debuglink( &self ) -> Option< &[u8] > {
        self.debuglink.as_ref().map( |debuglink| debuglink.as_slice() )
    }

    fn build_id( &self ) -> Option< &[u8] > {
        self.build_id.as_ref().map( |build_id| build_id.as_slice() )
    }

    fn load_debug_info( &mut self, debug_info_index: &DebugInfoIndex ) {
        if self.debug_data.is_some() {
            return;
        }

        if let Some( debug_data ) = debug_info_index.get( &self.basename, self.debuglink(), self.build_id() ) {
            debug!( "Found debug symbols for '{}': '{}'", self.path, debug_data.name() );
            self.debug_data = Some( debug_data.clone() );
        }
    }
}

struct BinaryChunks {
    chunks: Vec< (Range< u64 >, Vec< u8 >) >
}

impl BinaryChunks {
    fn new() -> Self {
        BinaryChunks {
            chunks: Vec::new()
        }
    }

    fn add( &mut self, offset: u64, bytes: Vec< u8 > ) {
        let range = offset..offset + bytes.len() as u64;
        self.chunks.push( (range, bytes) );
    }

    fn range_by_offset( &self, offset: u64 ) -> Range< u64 > {
        for &(ref range, _) in &self.chunks {
            if offset == range.start {
                return range.clone();
            }
        }

        panic!();
    }

    fn clear( &mut self ) {
        self.chunks.clear();
        self.chunks.shrink_to_fit();
    }
}

impl Index< Range< u64 > > for BinaryChunks {
    type Output = [u8];
    fn index( &self, index: Range< u64 > ) -> &Self::Output {
        for &(ref range, ref chunk) in &self.chunks {
            if index == *range {
                return chunk;
            }
        }

        panic!();
    }
}

unsafe impl StableIndex for BinaryChunks {}

fn get_basename( path: &str ) -> String {
    path[ path.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ].to_owned()
}

pub enum CollateFormat {
    Collapsed,
    PerfLike
}

pub struct Args< 'a > {
    pub input_path: &'a OsStr,
    pub debug_symbols: Vec< &'a OsStr >,
    pub force_stack_size: Option< u32 >,
    pub omit_symbols: Vec< &'a str >,
    pub only_sample: Option< u64 >,
    pub without_kernel_callstacks: bool,
    pub format: CollateFormat
}

struct CollateArgs< 'a > {
    input_path: &'a OsStr,
    debug_symbols: &'a [&'a OsStr],
    force_stack_size: Option< u32 >,
    only_sample: Option< u64 >,
    without_kernel_callstacks: bool,
}

struct Collation {
    kallsyms: RangeMap< KernelSymbol >,
    process_index_by_pid: HashMap< u32, usize >,
    processes: Vec< Process >,
    thread_names: HashMap< u32, String >,
    binary_by_id: HashMap< BinaryId, Binary >
}

impl Collation {
    fn get_kernel_symbol( &self, symbol_index: usize ) -> &KernelSymbol {
        self.kallsyms.get_value_by_index( symbol_index ).unwrap()
    }

    fn get_binary( &self, binary_id: &BinaryId ) -> &Binary {
        self.binary_by_id.get( binary_id ).unwrap()
    }

    fn get_thread_name( &self, tid: u32 ) -> Option< &str > {
        self.thread_names.get( &tid ).map( |str| str.as_str() )
    }

    fn get_process( &self, pid: u32 ) -> Option< &Process > {
        self.process_index_by_pid.get( &pid ).map( |&index| &self.processes[ index ] )
    }
}

fn to_binary_id( inode: Inode, name: &str ) -> BinaryId {
    if inode.is_invalid() {
        BinaryId::ByName( name.to_owned() )
    } else {
        BinaryId::ByInode( inode )
    }
}

fn collate< F >( args: CollateArgs, mut on_sample: F ) -> Result< Collation, Box< Error > >
    where F: FnMut( &Collation, u64, &Process, u32, u32, &[UserFrame], &[u64] )
{
    let fp = fs::File::open( args.input_path ).map_err( |err| format!( "cannot open {:?}: {}", args.input_path, err ) )?;
    let mut reader = ArchiveReader::new( fp ).validate_header().unwrap().skip_unknown();

    let mut collation = Collation {
        kallsyms: RangeMap::new(),
        process_index_by_pid: HashMap::new(),
        processes: Vec::new(),
        thread_names: HashMap::new(),
        binary_by_id: HashMap::new()
    };

    let mut machine_architecture = String::new();
    let mut machine_endianness = Endianness::LittleEndian;
    let mut machine_bitness = Bitness::B64;
    let mut sample_counter = 0;

    let debug_info_index = {
        let mut debug_info_index = DebugInfoIndex::new();
        for path in args.debug_symbols {
            debug_info_index.add( path );
        }
        debug_info_index
    };

    while let Some( packet ) = reader.next() {
        let packet = packet.unwrap();
        match packet {
            Packet::MachineInfo { architecture, bitness, endianness, .. } => {
                machine_architecture = architecture.into_owned();
                machine_bitness = bitness;
                machine_endianness = endianness;
            },
            Packet::ProcessInfo { pid, executable, .. } => {
                let executable = String::from_utf8_lossy( &executable ).into_owned();
                let executable = get_basename( &executable );
                debug!( "New process with PID {}: \"{}\"", pid, executable );

                let address_space: Box< IAddressSpace > = match &*machine_architecture {
                    arch::arm::Arch::NAME => Box::new( AddressSpace::< arch::arm::Arch >::new() ),
                    arch::amd64::Arch::NAME => Box::new( AddressSpace::< arch::amd64::Arch >::new() ),
                    arch::mips64::Arch::NAME => Box::new( AddressSpace::< arch::mips64::Arch >::new() ),
                    _ => panic!( "Unknown architecture: {}", machine_architecture )
                };

                let process = Process {
                    pid,
                    executable,
                    memory_regions: RangeMap::new(),
                    base_address_for_binary: HashMap::new(),
                    address_space,
                    address_space_needs_reload: true
                };

                let process_index = collation.processes.len();
                collation.processes.push( process );
                collation.process_index_by_pid.insert( pid, process_index );
            },
            Packet::BinaryInfo { inode, symbol_table_count, path, debuglink, load_headers, .. } => {
                let debuglink_length = debuglink.iter().position( |&byte| byte == 0 ).unwrap_or( debuglink.len() );
                let debuglink = debuglink[ 0..debuglink_length ].to_owned();
                let debuglink = if debuglink.is_empty() {
                    None
                } else {
                    Some( debuglink )
                };

                let path = String::from_utf8_lossy( &path ).into_owned();
                let binary_id = if inode.dev_major == 0 && inode.dev_minor == 0 {
                    BinaryId::ByName( path.clone() )
                } else {
                    BinaryId::ByInode( inode )
                };

                let mut binary = Binary {
                    basename: get_basename( &path ),
                    path,
                    string_tables: Arc::new( BinaryChunks::new() ),
                    symbol_table_count,
                    symbol_tables_chunks: BinaryChunks::new(),
                    symbol_tables: Vec::new(),
                    symbols: None,
                    data: None,
                    debug_data: None,
                    load_headers: load_headers.into_owned(),
                    build_id: None,
                    debuglink
                };

                debug!( "New binary: {:?}", binary.path );
                if let Some( ref debuglink ) = binary.debuglink {
                    if debug_info_index.get( &binary.basename, binary.debuglink(), binary.build_id() ).is_none() {
                        warn!( "Missing external debug symbols for '{}': '{}'", binary.path, String::from_utf8_lossy( debuglink ) );
                    }
                }

                collation.binary_by_id.insert( binary_id, binary );
            },
            Packet::BuildId { inode, path, build_id } => {
                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                let binary = collation.binary_by_id.get_mut( &binary_id ).unwrap();
                binary.build_id = Some( build_id );
            },
            Packet::MemoryRegionMap { pid, range, is_read, is_write, is_executable, is_shared, file_offset, inode, major, minor, name } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

                let region = Region {
                    start: range.start,
                    end: range.end,
                    is_read,
                    is_write,
                    is_executable,
                    is_shared,
                    file_offset,
                    inode,
                    major,
                    minor,
                    name: String::from_utf8_lossy( &name ).into_owned()
                };

                if sample_counter == 0 {
                    trace!( "Memory region mapped for PID {}: 0x{:016X}-0x{:016X}", pid, range.start, range.end );
                } else {
                    debug!( "Memory region mapped for PID {}: 0x{:016X}-0x{:016X}", pid, range.start, range.end );
                    trace!( "{:#?}", region );
                }

                process.memory_regions.push( range, region ).expect( "duplicate memory region" );
                process.address_space_needs_reload = true;
            },
            Packet::MemoryRegionUnmap { pid, range } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

                debug!( "Memory region unmapped for PID {}: 0x{:016X}-0x{:016X}", pid, range.start, range.end );
                process.memory_regions.remove_by_exact_range( range ).expect( "unknown region unmapped" );
                process.address_space_needs_reload = true;
            },
            Packet::Deprecated_BinaryMap { pid, inode, base_address } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

                let id = BinaryId::ByInode( inode );
                let binary = match collation.binary_by_id.get( &id ) {
                    Some( binary ) => binary,
                    None => {
                        warn!( "Unknown binary mapped for PID {}: {:?}", pid, id );
                        continue;
                    }
                };

                debug!( "Binary mapped for PID {}: \"{}\" @ 0x{:016X}", pid, binary.path, base_address );
                process.base_address_for_binary.insert( id, base_address );
                process.address_space_needs_reload = true;
            },
            Packet::Deprecated_BinaryUnmap { pid, inode, .. } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

                let binary_id = BinaryId::ByInode( inode );
                let binary = match collation.binary_by_id.get( &binary_id ) {
                    Some( binary ) => binary,
                    None => {
                        warn!( "Unknown binary unmapped for PID {}: {:?}", pid, binary_id );
                        continue;
                    }
                };

                debug!( "Binary unmapped for PID {}: \"{}\"", pid, binary.path );
                process.base_address_for_binary.remove( &binary_id );
                process.address_space_needs_reload = true;
            },
            Packet::StringTable { inode, offset, data, path } => {
                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                let binary = collation.binary_by_id.get_mut( &binary_id ).unwrap();
                Arc::get_mut( &mut binary.string_tables ).unwrap().add( offset, data.into_owned() );
            },
            Packet::SymbolTable { inode, offset, data, string_table_offset, is_dynamic, path } => {
                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                let binary = collation.binary_by_id.get_mut( &binary_id ).unwrap();

                let range = offset..offset + data.len() as u64;
                let strtab_range = binary.string_tables.range_by_offset( string_table_offset );

                binary.symbol_tables_chunks.add( offset, data.into_owned() );
                binary.symbol_tables.push(
                    SymbolTable {
                        range,
                        strtab_range,
                        is_dynamic
                    }
                );

                if binary.symbol_tables.len() == binary.symbol_table_count as usize {
                    binary.symbols = Some( Symbols::load(
                        &binary.path,
                        &machine_architecture,
                        machine_bitness,
                        machine_endianness,
                        &binary.symbol_tables,
                        &binary.symbol_tables_chunks,
                        &binary.string_tables
                    ));

                    binary.symbol_tables.clear();
                    binary.symbol_tables_chunks.clear();
                }
            },
            Packet::Sample { user_backtrace, mut kernel_backtrace, pid, tid, cpu, timestamp, .. } => {
                if let Some( only_sample ) = args.only_sample {
                    if only_sample != sample_counter {
                        sample_counter += 1;
                        continue;
                    }
                }

                debug!( "Sample #{}", sample_counter );

                if collation.processes[ 0 ].pid != pid {
                    debug!( "Sample #{} is from different process with PID {}, skipping!", sample_counter, pid );
                    continue;
                }

                collation.processes[ 0 ].reload_if_necessary( &debug_info_index, &mut collation.binary_by_id );

                if args.without_kernel_callstacks {
                    kernel_backtrace = Vec::new().into();
                }

                on_sample( &collation, timestamp, &collation.processes[ 0 ], tid, cpu, &user_backtrace, &kernel_backtrace );

                sample_counter += 1;
            },
            Packet::RawSample { mut kernel_backtrace, pid, tid, stack, regs, cpu, timestamp, .. } => {
                if let Some( only_sample ) = args.only_sample {
                    if only_sample != sample_counter {
                        sample_counter += 1;
                        continue;
                    }
                }

                debug!( "Sample #{}", sample_counter );

                if collation.processes[ 0 ].pid != pid {
                    debug!( "Sample #{} is from different process with PID {}, skipping!", sample_counter, pid );
                    continue;
                }

                if args.without_kernel_callstacks {
                    kernel_backtrace = Vec::new().into();
                }

                let user_backtrace = {
                    let mut process = &mut collation.processes[ 0 ];
                    process.reload_if_necessary( &debug_info_index, &mut collation.binary_by_id );

                    let mut dwarf_regs = DwarfRegs::new();
                    for reg in regs.iter() {
                        dwarf_regs.append( reg.register, reg.value );
                    }

                    let mut stack = &stack.as_slice()[..];
                    if let Some( force_stack_size ) = args.force_stack_size {
                        stack = &stack[ 0..min( force_stack_size as usize, stack.len() ) ];
                    }

                    let reader = StackReader { stack: stack.into() };
                    let mut user_backtrace = Vec::new();
                    process.address_space.unwind( &mut dwarf_regs, &reader, &mut user_backtrace );
                    user_backtrace
                };

                on_sample( &collation, timestamp, &collation.processes[ 0 ], tid, cpu, &user_backtrace, &kernel_backtrace );
                sample_counter += 1;
            },
            Packet::BinaryBlob { inode, path, data } => {
                let name = String::from_utf8_lossy( &path );
                let mut data = BinaryData::load_from_owned_bytes( &name, data.into_owned() ).unwrap();
                if !inode.is_invalid() {
                    data.set_inode( inode );
                }

                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                collation.binary_by_id.get_mut( &binary_id ).unwrap().data = Some( Arc::new( data ) );
            },
            Packet::FileBlob { ref path, ref data } if path.as_ref() == b"/proc/kallsyms" => {
                collation.kallsyms = kallsyms::parse( data.as_ref() );
            },
            Packet::ThreadName { tid, name, .. } => {
                if name.is_empty() {
                    collation.thread_names.remove( &tid );
                    continue;
                }

                let name = String::from_utf8_lossy( &name ).into_owned();
                collation.thread_names.insert( tid, name );
            },
            _ => {}
        }
    }


    Ok( collation )
}

fn decode_user_frames( omit_regex: &Option< Regex >, process: &Process, user_backtrace: &[UserFrame], interner: &mut StringInterner, output: &mut Vec< FrameKind > ) -> bool {
    for user_frame in user_backtrace.iter() {
        let default = FrameKind::User( user_frame.initial_address.unwrap_or( user_frame.address ) );
        let region = match process.memory_regions.get_value( user_frame.address ) {
            Some( region ) => region,
            None => {
                output.push( default );
                return true;
            }
        };

        let binary_id: BinaryId = region.into();
        let mut omit = false;
        process.address_space.decode_symbol_while( user_frame.address, &mut |frame| {
            if let Some( name ) = frame.demangled_name.take().or_else( || frame.name.take() ) {
                if let Some( ref regex ) = *omit_regex {
                    if regex.is_match( &name ) {
                        omit = true;
                        return false;
                    }
                }

                let string_id = interner.get_or_intern( name );
                output.push( FrameKind::UserSymbol( binary_id.clone(), frame.absolute_address, frame.is_inline, string_id ) );
            } else {
                output.push( FrameKind::UserBinary( binary_id.clone(), frame.absolute_address ) );
            }

            true
        });

        if omit {
            return false;
        }
    }

    true
}

fn collapse_frames(
    omit_regex: &Option< Regex >,
    collation: &Collation,
    process: &Process,
    tid: u32,
    user_backtrace: &[UserFrame],
    kernel_backtrace: &[u64],
    interner: &mut StringInterner,
    stacks: &mut HashMap< Vec< FrameKind >, u64 >
) {
    let mut frames = Vec::with_capacity( user_backtrace.len() + kernel_backtrace.len() + 1 );
    for &addr in kernel_backtrace.iter() {
        if let Some( index ) = collation.kallsyms.get_index( addr ) {
            frames.push( FrameKind::KernelSymbol( index ) );
        } else {
            frames.push( FrameKind::Kernel( addr ) );
        }
    }

    if !decode_user_frames( omit_regex, process, user_backtrace, interner, &mut frames ) {
        return;
    }

    if process.pid == tid {
        frames.push( FrameKind::MainThread );
    } else {
        frames.push( FrameKind::Thread( tid ) );
    }

    frames.push( FrameKind::Process( process.pid ) );

    *stacks.entry( frames ).or_insert( 0 ) += 1;
}

fn escape< 'a >( string: &'a str ) -> Cow< 'a, str > {
    let mut output: Cow< str > = string.into();
    if output.contains( " " ) {
        output = output.replace( " ", "_" ).into();
    }
    output
}

fn write_perf_like_output< T: io::Write >(
    omit_regex: &Option< Regex >,
    collation: &Collation,
    process: &Process,
    tid: u32,
    user_backtrace: &[UserFrame],
    kernel_backtrace: &[u64],
    cpu: u32,
    timestamp: u64,
    output: &mut T
) -> Result< (), io::Error > {
    let mut interner = StringInterner::new();
    let mut frames = Vec::new();
    if !decode_user_frames( omit_regex, process, user_backtrace, &mut interner, &mut frames ) {
        return Ok(()); // Was filtered out.
    }

    let secs = timestamp / 1000_000_000;
    let nsecs = timestamp - (secs * 1000_000_000);
    write!( output, "{}", escape( &process.executable ) )?;
    writeln!( output, " {}/{} [{:03}] {}.{:09}: cpu-clock: ", process.pid, tid, cpu, secs, nsecs )?;

    for &address in kernel_backtrace {
        if let Some( symbol ) = collation.kallsyms.get_value( address ) {
            if let Some( module ) = symbol.module.as_ref() {
                writeln!( output, "\t{:16X} {} ([linux:{}])", address, symbol.name, module ).unwrap()
            } else {
                writeln!( output, "\t{:16X} {} ([linux])", address, symbol.name ).unwrap()
            }
        } else {
            writeln!( output, "\t{:16X} 0x{:016X} ([linux])", address, address )?;
        }
    }

    for frame in frames {
        match frame {
            FrameKind::User( address ) => {
                writeln!( output, "\t{:16X} 0x{:016X} ([unknown])", address, address )?;
            },
            FrameKind::UserBinary( ref binary_id, address ) => {
                let binary = collation.get_binary( binary_id );
                writeln!( output, "\t{:16X} 0x{:016X} ({})", address, address, binary.basename )?;
            },
            FrameKind::UserSymbol( ref binary_id, address, is_inline, symbol_id ) => {
                let binary = collation.get_binary( binary_id );
                let symbol = interner.resolve( symbol_id ).unwrap();
                if is_inline {
                    writeln!( output, "\t{:16X} inline {} ({})", address, symbol, binary.basename )?;
                } else {
                    writeln!( output, "\t{:16X} {} ({})", address, symbol, binary.basename )?;
                }
            },
            _ => unreachable!()
        }
    }

    writeln!( output )?;

    Ok(())
}

fn write_frame< T: fmt::Write >( collation: &Collation, interner: &StringInterner, output: &mut T, frame: &FrameKind ) {
    match *frame {
        FrameKind::Process( pid ) => {
            if let Some( process ) = collation.get_process( pid ) {
                write!( output, "{} [PID={}]", process.executable, pid ).unwrap()
            } else {
                write!( output, "[PID={}]", pid ).unwrap()
            }
        },
        FrameKind::MainThread => {
            write!( output, "[MAIN_THREAD]" ).unwrap()
        },
        FrameKind::Thread( tid ) => {
            if let Some( name ) = collation.get_thread_name( tid ) {
                write!( output, "{} [THREAD={}]", name, tid ).unwrap()
            } else {
                write!( output, "[THREAD={}]", tid ).unwrap()
            }
        },
        FrameKind::UserSymbol( ref binary_id, _, is_inline, symbol_id ) => {
            let binary = collation.get_binary( binary_id );
            let symbol = interner.resolve( symbol_id ).unwrap();
            if is_inline {
                write!( output, "inline {} [{}]", symbol, binary.basename ).unwrap()
            } else {
                write!( output, "{} [{}]", symbol, binary.basename ).unwrap()
            }
        },
        FrameKind::UserBinary( ref binary_id, addr ) => {
            let binary = collation.get_binary( binary_id );
            write!( output, "0x{:016X} [{}]", addr, binary.basename ).unwrap()
        },
        FrameKind::User( addr ) => {
            write!( output, "0x{:016X}", addr ).unwrap()
        },
        FrameKind::KernelSymbol( symbol_index ) => {
            let symbol = collation.get_kernel_symbol( symbol_index );
            if let Some( module ) = symbol.module.as_ref() {
                write!( output, "{} [linux:{}]_[k]", symbol.name, module ).unwrap()
            } else {
                write!( output, "{} [linux]_[k]", symbol.name ).unwrap()
            }
        },
        FrameKind::Kernel( addr ) => {
            write!( output, "0x{:016X}_[k]", addr ).unwrap()
        }
    }
}

pub fn main( args: Args ) -> Result< (), Box< Error > > {
    let omit_regex = if args.omit_symbols.is_empty() {
        None
    } else {
        let regex = args.omit_symbols.join( "|" );
        let regex = Regex::new( &regex ).expect( "invalid regexp passed in `--omit`" );
        Some( regex )
    };

    let collate_args = CollateArgs {
        input_path: args.input_path,
        debug_symbols: &args.debug_symbols,
        force_stack_size: args.force_stack_size,
        only_sample: args.only_sample,
        without_kernel_callstacks: args.without_kernel_callstacks
    };

    match args.format {
        CollateFormat::Collapsed => {
            let mut stacks: HashMap< Vec< FrameKind >, u64 > = HashMap::new();
            let mut interner = StringInterner::new();
            let collation = collate( collate_args, |collation, _timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
                collapse_frames(
                    &omit_regex,
                    &collation,
                    process,
                    tid,
                    &user_backtrace,
                    &kernel_backtrace,
                    &mut interner,
                    &mut stacks
                );
            })?;

            let stdout = io::stdout();
            let mut stdout = stdout.lock();

            let mut line = String::new();
            for (ref frames, count) in &stacks {
                line.clear();

                let mut is_first = true;
                for frame in frames.into_iter().rev() {
                    if is_first {
                        is_first = false;
                    } else {
                        line.push( ';' );
                    }

                    write_frame( &collation, &interner, &mut line, frame );
                }

                write!( &mut line, " {}\n", count ).unwrap();
                stdout.write_all( line.as_bytes() ).unwrap();
            }
        },
        CollateFormat::PerfLike => {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            collate( collate_args, |collation, timestamp, process, tid, cpu, user_backtrace, kernel_backtrace| {
                write_perf_like_output(
                    &omit_regex,
                    &collation,
                    process,
                    tid,
                    &user_backtrace,
                    &kernel_backtrace,
                    cpu,
                    timestamp,
                    &mut stdout
                ).unwrap();
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::{StringInterner, CollateArgs, FrameKind, Collation, collate, collapse_frames};
    use std::path::Path;
    use std::collections::HashMap;
    use env_logger;

    struct Data {
        collation: Collation,
        stacks: HashMap< Vec< FrameKind >, u64 >,
        interner: StringInterner
    }

    fn load( filename: &str ) -> Data {
        let _ = env_logger::try_init();
        let mut interner = StringInterner::new();
        let path = Path::new( env!( "CARGO_MANIFEST_DIR" ) ).join( "test-data" ).join( "artifacts" ).join( filename );
        let args = CollateArgs {
            input_path: path.as_os_str(),
            debug_symbols: &[],
            force_stack_size: None,
            only_sample: None,
            without_kernel_callstacks: false
        };

        let mut stacks: HashMap< Vec< FrameKind >, u64 > = HashMap::new();
        let collation = collate( args, |collation, _timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
            collapse_frames(
                &None,
                &collation,
                process,
                tid,
                &user_backtrace,
                &kernel_backtrace,
                &mut interner,
                &mut stacks
            );
        }).unwrap();

        Data {
            collation,
            stacks,
            interner
        }
    }

    fn most_frequent_trace( data: &Data ) -> (&[FrameKind], u64) {
        let (frames, count) = data.stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();
        (&frames, *count)
    }

    fn frame_to_str( data: &Data, frame: &FrameKind ) -> String {
        match *frame {
            FrameKind::Process( pid ) => {
                if let Some( process ) = data.collation.get_process( pid ) {
                    format!( "[process:{}]", process.executable )
                } else {
                    format!( "[process]" )
                }
            },
            FrameKind::MainThread => {
                format!( "[main_thread]" )
            },
            FrameKind::Thread( tid ) => {
                if let Some( name ) = data.collation.get_thread_name( tid ) {
                    format!( "[thread:{}]", name )
                } else {
                    format!( "[thread]" )
                }
            },
            FrameKind::UserSymbol( ref binary_id, _, _, symbol_id ) => {
                let binary = data.collation.get_binary( binary_id );
                let symbol = data.interner.resolve( symbol_id ).unwrap();
                format!( "{}:{}", symbol, binary.basename )
            },
            FrameKind::UserBinary( ref binary_id, _ ) => {
                let binary = data.collation.get_binary( binary_id );
                format!( "?:{}", binary.basename )
            },
            FrameKind::User( _ ) => {
                format!( "?" )
            },
            FrameKind::KernelSymbol( symbol_index ) => {
                let symbol = data.collation.get_kernel_symbol( symbol_index );
                if let Some( module ) = symbol.module.as_ref() {
                    format!( "{}:{}:linux", symbol.name, module )
                } else {
                    format!( "{}:linux", symbol.name )
                }
            },
            FrameKind::Kernel( _ ) => {
                format!( "?" )
            }
        }
    }

    fn frames_to_str< 'a, I: IntoIterator< Item = &'a FrameKind > >( data: &Data, frames: I, highlighted: Option< usize > ) -> String
        where <I as IntoIterator>::IntoIter: DoubleEndedIterator
    {
        let frames: Vec< _ > = frames.into_iter().rev().enumerate().map( |(index, frame)| {
            let frame = frame_to_str( data, frame );
            if highlighted.map( |highlighted| index == highlighted ).unwrap_or( false ) {
                format!( "    >>>{}<<<", frame )
            } else {
                format!( "    {}", frame )
            }
        }).collect();

        frames.join( "\n" )
    }

    fn join( frames: &[&str], highlighted: Option< usize > ) -> String {
        let frames: Vec< _ > = frames.iter().enumerate().map( |(index, frame)| {
            if highlighted.map( |highlighted| index == highlighted ).unwrap_or( false ) {
                format!( "    >>>{}<<<", frame )
            } else {
                format!( "    {}", frame )
            }
        }).collect();

        frames.join( "\n" )
    }

    fn assert_backtrace( data: &Data, frames: &[FrameKind], expected_frames: &[&str] ) {
        let mut expected_iter = expected_frames.iter();
        let mut actual_iter = frames.iter().rev().enumerate();

        loop {
            let (expected, actual, index) = match (expected_iter.next(), actual_iter.next()) {
                (None, None) => break,
                (Some( &expected ), None) => {
                    if expected == "**" {
                        break;
                    }

                    eprintln!( "" );
                    eprintln!( "Expected ({} frames)\n{}", expected_frames.len(), join( expected_frames, None ) );
                    eprintln!( "Actual ({} frames)\n{}", frames.len(), frames_to_str( data, frames, None ) );
                    panic!( "Expected a longer stack trace!" );
                },
                (None, Some( _ )) => {
                    eprintln!( "" );
                    eprintln!( "Expected ({} frames)\n{}", expected_frames.len(), join( expected_frames, None ) );
                    eprintln!( "Actual ({} frames)\n{}", frames.len(), frames_to_str( data, frames, None ) );
                    panic!( "Expected a shorter stack trace!" );
                },
                (Some( expected ), Some( (index, actual) )) => (expected, actual, index)
            };

            let expected = *expected;
            if expected == "*" {
                continue;
            }

            if expected == "**" {
                break;
            }

            let actual = frame_to_str( data, actual );
            if expected == actual {
                continue;
            }

            eprintln!( "" );
            eprintln!( "Expected ({} frames)\n{}", expected_frames.len(), join( expected_frames, Some( index ) ) );
            eprintln!( "Actual ({} frames)\n{}", frames.len(), frames_to_str( data, frames, Some( index ) ) );
            panic!( "Unexpected stack trace!" );
        }
    }

    #[test]
    fn collate_arm_hot_spot_usleep_in_a_loop_no_fp() {
        let data = load( "arm-usleep_in_a_loop_no_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:arm-usleep_in_a_loop_no_fp]",
            "[main_thread]",
            "?:arm-usleep_in_a_loop_no_fp",
            "__libc_start_main:libc-2.26.so",
            "main:arm-usleep_in_a_loop_no_fp",
            "function:arm-usleep_in_a_loop_no_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "ret_fast_syscall:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_arm_perfect_unwinding_usleep_in_a_loop_no_fp() {
        let data = load( "arm-usleep_in_a_loop_no_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:arm-usleep_in_a_loop_no_fp]",
                "[main_thread]",
                "?:arm-usleep_in_a_loop_no_fp",
                "__libc_start_main:libc-2.26.so",
                "main:arm-usleep_in_a_loop_no_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_arm_hot_spot_usleep_in_a_loop_fp() {
        let data = load( "arm-usleep_in_a_loop_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:arm-usleep_in_a_loop_fp]",
            "[main_thread]",
            "?:arm-usleep_in_a_loop_fp",
            "__libc_start_main:libc-2.26.so",
            "main:arm-usleep_in_a_loop_fp",
            "function:arm-usleep_in_a_loop_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "ret_fast_syscall:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_arm_perfect_unwinding_usleep_in_a_loop_fp() {
        let data = load( "arm-usleep_in_a_loop_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:arm-usleep_in_a_loop_fp]",
                "[main_thread]",
                "?:arm-usleep_in_a_loop_fp",
                "__libc_start_main:libc-2.26.so",
                "main:arm-usleep_in_a_loop_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_amd64_hot_spot_usleep_in_a_loop_no_fp() {
        let data = load( "amd64-usleep_in_a_loop_no_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:amd64-usleep_in_a_loop_no_fp]",
            "[main_thread]",
            "_start:amd64-usleep_in_a_loop_no_fp",
            "__libc_start_main:libc-2.26.so",
            "main:amd64-usleep_in_a_loop_no_fp",
            "function:amd64-usleep_in_a_loop_no_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "entry_SYSCALL_64_fastpath:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_amd64_perfect_unwinding_usleep_in_a_loop_no_fp() {
        let data = load( "amd64-usleep_in_a_loop_no_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-usleep_in_a_loop_no_fp]",
                "[main_thread]",
                "_start:amd64-usleep_in_a_loop_no_fp",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-usleep_in_a_loop_no_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_amd64_hot_spot_usleep_in_a_loop_no_fp_online() {
        let data = load( "amd64-usleep_in_a_loop_no_fp_online.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:amd64-usleep_in_a_loop_no_fp]",
            "[main_thread]",
            "_start:amd64-usleep_in_a_loop_no_fp",
            "__libc_start_main:libc-2.26.so",
            "main:amd64-usleep_in_a_loop_no_fp",
            "function:amd64-usleep_in_a_loop_no_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "entry_SYSCALL_64_fastpath:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_amd64_hot_spot_usleep_in_a_loop_fp() {
        let data = load( "amd64-usleep_in_a_loop_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:amd64-usleep_in_a_loop_fp]",
            "[main_thread]",
            "_start:amd64-usleep_in_a_loop_fp",
            "__libc_start_main:libc-2.26.so",
            "main:amd64-usleep_in_a_loop_fp",
            "function:amd64-usleep_in_a_loop_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "entry_SYSCALL_64_fastpath:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_amd64_perfect_unwinding_usleep_in_a_loop_fp() {
        let data = load( "amd64-usleep_in_a_loop_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-usleep_in_a_loop_fp]",
                "[main_thread]",
                "_start:amd64-usleep_in_a_loop_fp",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-usleep_in_a_loop_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_amd64_pthread_cond_wait() {
        let data = load( "amd64-pthread_cond_wait.nperf" );

        for (ref foo, _) in data.stacks.iter() {
            println!( "{:?}", frame_to_str( &data, &foo[ foo.len() - 2 ] ) );
        }

        let main_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[main_thread]" ).collect();
        let thread_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[thread:another thread]" ).collect();

        let &(ref main_frames, _) = main_stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();
        let &(ref thread_frames, _) = thread_stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();

        assert_backtrace( &data, &main_frames, &[
            "[process:amd64-pthread_cond_wait]",
            "[main_thread]",
            "_start:amd64-pthread_cond_wait",
            "__libc_start_main:libc-2.26.so",
            "main:amd64-pthread_cond_wait",
            "pthread_cond_wait:libpthread-2.26.so",
            "entry_SYSCALL_64_fastpath:linux",
            "sys_futex:linux",
            "**"
        ]);

        assert_backtrace( &data, &thread_frames, &[
            "[process:amd64-pthread_cond_wait]",
            "[thread:another thread]",
            "clone:libc-2.26.so",
            "?:libpthread-2.26.so",
            "thread_main:amd64-pthread_cond_wait",
            "pthread_cond_signal:libpthread-2.26.so",
            "entry_SYSCALL_64_fastpath:linux",
            "sys_futex:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_mips64_hot_spot_usleep_in_a_loop_no_fp() {
        let data = load( "mips64-usleep_in_a_loop_no_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 50 );
        assert_backtrace( &data, frames, &[
            "[process:mips64-usleep_in_a_loop_no_fp]",
            "[main_thread]",
            "?:mips64-usleep_in_a_loop_no_fp",
            "__libc_start_main:libc-2.26.so",
            "main:mips64-usleep_in_a_loop_no_fp",
            "function:mips64-usleep_in_a_loop_no_fp",
            "usleep:libc-2.26.so",
            "__nanosleep:libc-2.26.so",
            "syscall_common:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_mips64_perfect_unwinding_usleep_in_a_loop_no_fp() {
        let data = load( "mips64-usleep_in_a_loop_no_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:mips64-usleep_in_a_loop_no_fp]",
                "[main_thread]",
                "?:mips64-usleep_in_a_loop_no_fp",
                "__libc_start_main:libc-2.26.so",
                "main:mips64-usleep_in_a_loop_no_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_mips64_hot_spot_usleep_in_a_loop_fp() {
        let data = load( "mips64-usleep_in_a_loop_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 100 );
        assert_backtrace( &data, frames, &[
            "[process:mips64-usleep_in_a_loop_fp]",
            "[main_thread]",
            "?:mips64-usleep_in_a_loop_fp",
            "__libc_start_main:libc-2.26.so",
            "main:mips64-usleep_in_a_loop_fp",
            "function:mips64-usleep_in_a_loop_fp",
            "usleep:libc-2.26.so",
            "__nanosleep:libc-2.26.so",
            "syscall_common:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_mips64_perfect_unwinding_usleep_in_a_loop_fp() {
        let data = load( "mips64-usleep_in_a_loop_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:mips64-usleep_in_a_loop_fp]",
                "[main_thread]",
                "?:mips64-usleep_in_a_loop_fp",
                "__libc_start_main:libc-2.26.so",
                "main:mips64-usleep_in_a_loop_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_mips64_pthread_cond_wait() {
        let data = load( "mips64-pthread_cond_wait.nperf" );

        for (ref foo, _) in data.stacks.iter() {
            println!( "{:?}", frame_to_str( &data, &foo[ foo.len() - 2 ] ) );
        }

        let main_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[main_thread]" ).collect();
        let thread_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[thread:another thread]" ).collect();

        let &(ref main_frames, _) = main_stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();
        let &(ref thread_frames, _) = thread_stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();

        assert_backtrace( &data, &main_frames, &[
            "[process:mips64-pthread_cond_wait]",
            "[main_thread]",
            "?:mips64-pthread_cond_wait",
            "__libc_start_main:libc-2.26.so",
            "main:mips64-pthread_cond_wait",
            "pthread_cond_wait:libpthread-2.26.so",
            "__pthread_mutex_cond_lock:libpthread-2.26.so",
            "__lll_lock_wait:libpthread-2.26.so",
            "**"
        ]);

        assert_backtrace( &data, &thread_frames, &[
            "[process:mips64-pthread_cond_wait]",
            "[thread:another thread]",
            "__thread_start:libc-2.26.so",
            "start_thread:libpthread-2.26.so",
            "thread_main:mips64-pthread_cond_wait",
            "pthread_mutex_lock:libpthread-2.26.so"
        ]);
    }

    #[test]
    fn collate_amd64_inline_functions() {
        let data = load( "amd64-inline_functions.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-inline_functions]",
                "[main_thread]",
                "_start:amd64-inline_functions",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-inline_functions",
                "inline_function_1st:amd64-inline_functions",
                "inline_function_2nd:amd64-inline_functions",
                "function:amd64-inline_functions",
                "usleep:libc-2.26.so",
                "**"
            ]);
        }
    }

    #[ignore]
    #[test]
    fn collate_mips64_inline_functions() {
        let data = load( "mips64-inline_functions.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:mips64-inline_functions]",
                "[main_thread]",
                "?:mips64-inline_functions",
                "__libc_start_main:libc-2.26.so",
                "main:mips64-inline_functions",
                "inline_function_1st:mips64-inline_functions",
                "inline_function_2nd:mips64-inline_functions",
                "function:mips64-inline_functions",
                "usleep:libc-2.26.so",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_arm_inline_functions() {
        let data = load( "arm-inline_functions.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:arm-inline_functions]",
                "[main_thread]",
                "?:arm-inline_functions",
                "__libc_start_main:libc-2.26.so",
                "main:arm-inline_functions",
                "inline_function_1st:arm-inline_functions",
                "inline_function_2nd:arm-inline_functions",
                "function:arm-inline_functions",
                "usleep:libc-2.26.so",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_amd64_noreturn() {
        let data = load( "amd64-noreturn.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-noreturn]",
                "[main_thread]",
                "_start:amd64-noreturn",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-noreturn",
                "function:amd64-noreturn",
                "infinite_loop:amd64-noreturn",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_mips64_noreturn() {
        let data = load( "mips64-noreturn.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:mips64-noreturn]",
                "[main_thread]",
                "?:mips64-noreturn",
                "__libc_start_main:libc-2.26.so",
                "main:mips64-noreturn",
                "function:mips64-noreturn",
                "infinite_loop:mips64-noreturn",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_arm_noreturn() {
        let data = load( "arm-noreturn.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:arm-noreturn]",
                "[main_thread]",
                "?:arm-noreturn",
                "__libc_start_main:libc-2.26.so",
                "main:arm-noreturn",
                "function:arm-noreturn",
                "infinite_loop:arm-noreturn",
                "usleep:libc-2.26.so",
                "**"
            ]);
        }
    }
}
