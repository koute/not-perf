use std::fs;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::ops::{Range, Index};
use std::path::Path;
use std::cmp::min;
use std::fmt;
use std::error::Error;
use std::borrow::Cow;

use speedy::Endianness;
use cpp_demangle;
use regex::Regex;

use nwind::arch::{self, Architecture, Registers};
use nwind::maps::Region;
use nwind::{
    DwarfRegs,
    RangeMap,
    Symbols,
    BinaryData,
    BinarySource,
    SymbolTable,
    IAddressSpace,
    AddressSpace
};

use archive::{Packet, Inode, Bitness, UserFrame, ArchiveReader};
use utils::StableIndex;
use kallsyms::{self, KernelSymbol};

use stack_reader::StackReader;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
enum Table {
    Debug,
    Original,
    AddressSpace
}

#[derive(PartialEq, Eq, Debug, Hash)]
enum Frame {
    Process( u32 ),
    Thread( u32 ),
    MainThread,
    User( u64 ),
    UserBinary( Inode, u64 ),
    UserSymbol( Inode, u64, usize, Table ),
    Kernel( u64 ),
    KernelSymbol( usize )
}

struct Process {
    pid: u32,
    executable: String,
    memory_regions: RangeMap< Region >,
    base_address_for_binary: HashMap< Inode, u64 >,
    address_space_needs_reload: bool
}

struct Binary {
    path: String,
    basename: String,
    string_tables: Arc< BinaryChunks >,
    symbol_table_count: u16,
    symbol_tables_chunks: BinaryChunks,
    symbol_tables: Vec< SymbolTable >,
    symbols: Option< Symbols< BinaryChunks > >,
    debug_symbols: Option< Symbols< BinaryData > >
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

fn decode_user_frame(
    omit_regex: &Option< Regex >,
    address_space: Option< &Box< IAddressSpace > >,
    process: &Process,
    binary_by_id: &HashMap< Inode, Binary >,
    user_frame: &UserFrame
) -> Option< Frame > {
    let address = user_frame.initial_address.unwrap_or( user_frame.address );
    if let Some( region ) = process.memory_regions.get_value( address ) {
        let binary_id = Inode {
            inode: region.inode,
            dev_major: region.major,
            dev_minor: region.minor
        };

        if let Some( binary ) = binary_by_id.get( &binary_id ) {
            if let Some( debug_symbols ) = binary.debug_symbols.as_ref() {
                let base_address = process.base_address_for_binary.get( &binary_id ).expect( "no base address for binary" );
                if let Some( index ) = debug_symbols.get_symbol_index( address - base_address ) {
                    if let Some( ref regex ) = *omit_regex {
                        let symbol = debug_symbols.get_symbol_by_index( index ).unwrap().1;
                        if regex.is_match( symbol ) {
                            return None;
                        }
                    }

                    return Some( Frame::UserSymbol( binary_id, address, index, Table::Debug ) );
                }
            }

            if let Some( symbols ) = binary.symbols.as_ref() {
                let base_address = process.base_address_for_binary.get( &binary_id ).expect( "no base address for binary" );
                if let Some( index ) = symbols.get_symbol_index( address - base_address ) {
                    if let Some( ref regex ) = *omit_regex {
                        let symbol = symbols.get_symbol_by_index( index ).unwrap().1;
                        if regex.is_match( symbol ) {
                            return None;
                        }
                    }

                    return Some( Frame::UserSymbol( binary_id, address, index, Table::Original ) );
                }
            }

            if let Some( address_space ) = address_space {
                if let Some( index ) = address_space.lookup_absolute_symbol_index( &binary_id, address ) {
                    if let Some( ref regex ) = *omit_regex {
                        let symbol = address_space.get_symbol_by_index( &binary_id, index ).1;
                        if regex.is_match( symbol ) {
                            return None;
                        }
                    }

                    return Some( Frame::UserSymbol( binary_id, address, index, Table::AddressSpace ) );
                }
            }

            return Some( Frame::UserBinary( binary_id, address ) );
        }
    }

    Some( Frame::User( address ) )
}

fn get_basename( path: &str ) -> String {
    path[ path.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ].to_owned()
}

struct DemangleCache {
    cache: HashMap< String, Option< String > >
}

impl DemangleCache {
    fn new() -> Self {
        DemangleCache {
            cache: HashMap::new()
        }
    }

    fn demangle_uncached( symbol: &str ) -> Option< String > {
        if !symbol.starts_with( "_Z" ) {
            return None;
        }

        cpp_demangle::Symbol::new( symbol ).ok().and_then( |symbol| {
            symbol.demangle( &cpp_demangle::DemangleOptions::default() ).ok()
        })
    }

    fn demangle< 'a, 'b >( &'a mut self, symbol: &'b str ) -> Option< &'a str > {
        if !symbol.starts_with( "_Z" ) {
            return None;
        }

        if self.cache.contains_key( symbol ) {
            return self.cache.get( symbol ).unwrap().as_ref().map( String::as_str );
        }

        self.cache.insert( symbol.to_owned(), Self::demangle_uncached( symbol ) );
        self.cache.get( symbol ).unwrap().as_ref().map( String::as_str )
    }
}

fn look_through_debug_symbols( debug_symbols: &[&OsStr] ) -> HashMap< String, Symbols< BinaryData > > {
    fn check( path: &Path, results: &mut HashMap< String, Symbols< BinaryData > > ) {
        match BinaryData::load_from_fs( path ) {
            Ok( binary ) => {
                let filename = path.file_name().unwrap();
                let filename = filename.to_string_lossy().into_owned();
                let binary = Arc::new( binary );
                let symbols = Symbols::load_from_binary_data( &binary );
                results.insert( filename, symbols );
            },
            Err( error ) => {
                warn!( "Cannot read debug symbols from {:?}: {}", path, error );
                return;
            }
        }
    }

    let mut results = HashMap::new();
    for path in debug_symbols {
        let path = Path::new( path );
        if !path.exists() {
            continue;
        }

        if path.is_dir() {
            let dir = match path.read_dir() {
                Ok( dir ) => dir,
                Err( error ) => {
                    warn!( "Cannot read debug symbols from {:?}: {}", path, error );
                    continue;
                }
            };

            for entry in dir {
                if let Ok( entry ) = entry {
                    check( &entry.path(), &mut results );
                }
            }
        } else {
            check( path, &mut results );
        }
    }

    results
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
    binary_by_id: HashMap< Inode, Binary >,
    address_space: Option< Box< IAddressSpace > >
}

impl Collation {
    fn get_user_symbol< 'a >( &'a self, demangle_cache: &'a mut DemangleCache, binary_id: &Inode, symbol_index: usize, table: Table ) -> (&'a str, &'a Binary) {
        let binary = self.binary_by_id.get( &binary_id ).unwrap();
        let symbol = match table {
            Table::Original => binary.symbols.as_ref().unwrap().get_symbol_by_index( symbol_index ).unwrap().1,
            Table::Debug => binary.debug_symbols.as_ref().unwrap().get_symbol_by_index( symbol_index ).unwrap().1,
            Table::AddressSpace => self.address_space.as_ref().unwrap().get_symbol_by_index( &binary_id, symbol_index ).1
        };

        (demangle_cache.demangle( symbol ).unwrap_or( symbol ), binary)
    }

    fn get_kernel_symbol( &self, symbol_index: usize ) -> &KernelSymbol {
        self.kallsyms.get_value_by_index( symbol_index ).unwrap()
    }

    fn get_binary( &self, binary_id: &Inode ) -> &Binary {
        self.binary_by_id.get( binary_id ).unwrap()
    }

    fn get_thread_name( &self, tid: u32 ) -> Option< &str > {
        self.thread_names.get( &tid ).map( |str| str.as_str() )
    }

    fn get_process( &self, pid: u32 ) -> Option< &Process > {
        self.process_index_by_pid.get( &pid ).map( |&index| &self.processes[ index ] )
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
        binary_by_id: HashMap::new(),
        address_space: None
    };

    let mut machine_architecture = String::new();
    let mut machine_endianness = Endianness::LittleEndian;
    let mut machine_bitness = Bitness::B64;
    let mut sample_counter = 0;
    let mut binary_source_map = HashMap::new();

    let mut debug_symbols = look_through_debug_symbols( &args.debug_symbols );

    while let Some( packet ) = reader.next() {
        let packet = packet.unwrap();
        match packet {
            Packet::MachineInfo { architecture, bitness, endianness, .. } => {
                collation.address_space = match &*architecture {
                    arch::arm::Arch::NAME => Some( Box::new( AddressSpace::< arch::arm::Arch >::new() ) ),
                    arch::amd64::Arch::NAME => Some( Box::new( AddressSpace::< arch::amd64::Arch >::new() ) ),
                    arch::mips64::Arch::NAME => Some( Box::new( AddressSpace::< arch::mips64::Arch >::new() ) ),
                    _ => None
                };

                machine_architecture = architecture.into_owned();
                machine_bitness = bitness;
                machine_endianness = endianness;
            },
            Packet::ProcessInfo { pid, executable, .. } => {
                let executable = String::from_utf8_lossy( &executable ).into_owned();
                let executable = get_basename( &executable );
                debug!( "New process with PID {}: \"{}\"", pid, executable );

                let process = Process {
                    pid,
                    executable,
                    memory_regions: RangeMap::new(),
                    base_address_for_binary: HashMap::new(),
                    address_space_needs_reload: true
                };

                let process_index = collation.processes.len();
                collation.processes.push( process );
                collation.process_index_by_pid.insert( pid, process_index );
            },
            Packet::BinaryInfo { id, symbol_table_count, path, debuglink, .. } => {
                let debuglink_length = debuglink.iter().position( |&byte| byte == 0 ).unwrap_or( debuglink.len() );
                let debuglink = &debuglink[ 0..debuglink_length ];

                let path = String::from_utf8_lossy( &path ).into_owned();
                let mut binary = Binary {
                    basename: get_basename( &path ),
                    path,
                    string_tables: Arc::new( BinaryChunks::new() ),
                    symbol_table_count,
                    symbol_tables_chunks: BinaryChunks::new(),
                    symbol_tables: Vec::new(),
                    symbols: None,
                    debug_symbols: None
                };

                debug!( "New binary: {:?}", binary.path );
                if !debuglink.is_empty() {
                    let debuglink = String::from_utf8_lossy( &debuglink );
                    if let Some( debug_symbols ) = debug_symbols.remove( &*debuglink ) {
                        binary.debug_symbols = Some( debug_symbols );
                        debug!( "Found debug symbols for '{}': '{}'", binary.path, debuglink );
                    } else {
                        warn!( "Missing external debug symbols for '{}': '{}'", binary.path, debuglink );
                    }
                }

                collation.binary_by_id.insert( id, binary );
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
            Packet::BinaryMap { pid, id, base_address } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

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
            Packet::BinaryUnmap { pid, id, .. } => {
                let process = match collation.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut collation.processes[ index ],
                    None => continue
                };

                let binary = match collation.binary_by_id.get( &id ) {
                    Some( binary ) => binary,
                    None => {
                        warn!( "Unknown binary unmapped for PID {}: {:?}", pid, id );
                        continue;
                    }
                };

                debug!( "Binary unmapped for PID {}: \"{}\"", pid, binary.path );
                process.base_address_for_binary.remove( &id );
                process.address_space_needs_reload = true;
            },
            Packet::StringTable { binary_id, offset, data } => {
                let binary = collation.binary_by_id.get_mut( &binary_id ).unwrap();
                Arc::get_mut( &mut binary.string_tables ).unwrap().add( offset, data.into_owned() );
            },
            Packet::SymbolTable { binary_id, offset, data, string_table_offset, is_dynamic } => {
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

                let process = &collation.processes[ 0 ];
                if process.pid != pid {
                    debug!( "Sample #{} is from different process with PID {}, skipping!", sample_counter, pid );
                    continue;
                }

                if args.without_kernel_callstacks {
                    kernel_backtrace = Vec::new().into();
                }

                on_sample( &collation, timestamp, process, tid, cpu, &user_backtrace, &kernel_backtrace );

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

                let user_backtrace = if let Some( ref mut address_space ) = collation.address_space {
                    let mut process = &mut collation.processes[ 0 ];
                    if process.address_space_needs_reload {
                        process.address_space_needs_reload = false;
                        let binaries = binary_source_map.clone();
                        let regions = process.memory_regions.values().cloned().collect();
                        address_space.reload( binaries, regions, true );
                    }

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
                    address_space.unwind( &mut dwarf_regs, &reader, &mut user_backtrace );
                    Some( user_backtrace )
                } else {
                    None
                };

                if let Some( user_backtrace ) = user_backtrace {
                    on_sample( &collation, timestamp, &collation.processes[ 0 ], tid, cpu, &user_backtrace, &kernel_backtrace );
                }

                sample_counter += 1;
            },
            Packet::BinaryBlob { id, path, data } => {
                let mut data = BinaryData::load_from_owned_bytes( &String::from_utf8_lossy( &path ), data.into_owned() ).unwrap();
                data.set_inode( id );

                let source = BinarySource::Preloaded( Arc::new( data ) );
                binary_source_map.insert( id, source );
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

fn collapse_frames(
    omit_regex: &Option< Regex >,
    collation: &Collation,
    process: &Process,
    tid: u32,
    user_backtrace: &[UserFrame],
    kernel_backtrace: &[u64],
    stacks: &mut HashMap< Vec< Frame >, u64 >
) {
    let mut frames = Vec::with_capacity( user_backtrace.len() + kernel_backtrace.len() + 1 );
    for &addr in kernel_backtrace.iter() {
        if let Some( index ) = collation.kallsyms.get_index( addr ) {
            frames.push( Frame::KernelSymbol( index ) );
        } else {
            frames.push( Frame::Kernel( addr ) );
        }
    }

    for user_frame in user_backtrace.iter() {
        let frame = match decode_user_frame(
            omit_regex,
            collation.address_space.as_ref(),
            process,
            &collation.binary_by_id,
            user_frame
        ) {
            Some( frame ) => frame,
            None => return // Was filtered out.
        };

        frames.push( frame );
    }

    if process.pid == tid {
        frames.push( Frame::MainThread );
    } else {
        frames.push( Frame::Thread( tid ) );
    }

    frames.push( Frame::Process( process.pid ) );

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
    demangle_cache: &mut DemangleCache,
    process: &Process,
    tid: u32,
    user_backtrace: &[UserFrame],
    kernel_backtrace: &[u64],
    cpu: u32,
    timestamp: u64,
    output: &mut T
) -> Result< (), io::Error > {
    let mut frames = Vec::new();
    for user_frame in user_backtrace {
        let frame = decode_user_frame(
            omit_regex,
            collation.address_space.as_ref(),
            process,
            &collation.binary_by_id,
            user_frame
        );

        let frame = match frame {
            Some( frame ) => frame,
            None => return Ok(()) // Was filtered out.
        };

        frames.push( frame );
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
            Frame::User( address ) => {
                writeln!( output, "\t{:16X} 0x{:016X} ([unknown])", address, address )?;
            },
            Frame::UserBinary( ref binary_id, address ) => {
                let binary = collation.get_binary( binary_id );
                writeln!( output, "\t{:16X} 0x{:016X} ({})", address, address, binary.basename )?;
            },
            Frame::UserSymbol( ref binary_id, address, symbol_index, table ) => {
                let (symbol, binary) = collation.get_user_symbol( demangle_cache, binary_id, symbol_index, table );
                writeln!( output, "\t{:16X} {} ({})", address, symbol, binary.basename )?;
            },
            _ => unreachable!()
        }
    }

    writeln!( output )?;

    Ok(())
}

fn write_frame< T: fmt::Write >( collation: &Collation, demangle_cache: &mut DemangleCache, output: &mut T, frame: &Frame ) {
    match *frame {
        Frame::Process( pid ) => {
            if let Some( process ) = collation.get_process( pid ) {
                write!( output, "{} [PID={}]", process.executable, pid ).unwrap()
            } else {
                write!( output, "[PID={}]", pid ).unwrap()
            }
        },
        Frame::MainThread => {
            write!( output, "[MAIN_THREAD]" ).unwrap()
        },
        Frame::Thread( tid ) => {
            if let Some( name ) = collation.get_thread_name( tid ) {
                write!( output, "{} [THREAD={}]", name, tid ).unwrap()
            } else {
                write!( output, "[THREAD={}]", tid ).unwrap()
            }
        },
        Frame::UserSymbol( ref binary_id, _, symbol_index, table ) => {
            let (symbol, binary) = collation.get_user_symbol( demangle_cache, binary_id, symbol_index, table );
            write!( output, "{} [{}]", symbol, binary.basename ).unwrap()
        },
        Frame::UserBinary( ref binary_id, addr ) => {
            let binary = collation.get_binary( binary_id );
            write!( output, "0x{:016X} [{}]", addr, binary.basename ).unwrap()
        },
        Frame::User( addr ) => {
            write!( output, "0x{:016X}", addr ).unwrap()
        },
        Frame::KernelSymbol( symbol_index ) => {
            let symbol = collation.get_kernel_symbol( symbol_index );
            if let Some( module ) = symbol.module.as_ref() {
                write!( output, "{} [linux:{}]_[k]", symbol.name, module ).unwrap()
            } else {
                write!( output, "{} [linux]_[k]", symbol.name ).unwrap()
            }
        },
        Frame::Kernel( addr ) => {
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
            let mut stacks: HashMap< Vec< Frame >, u64 > = HashMap::new();
            let collation = collate( collate_args, |collation, _timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
                collapse_frames(
                    &omit_regex,
                    &collation,
                    process,
                    tid,
                    &user_backtrace,
                    &kernel_backtrace,
                    &mut stacks
                );
            })?;

            let mut demangle_cache = DemangleCache::new();
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

                    write_frame( &collation, &mut demangle_cache, &mut line, frame );
                }

                write!( &mut line, " {}\n", count ).unwrap();
                stdout.write_all( line.as_bytes() ).unwrap();
            }
        },
        CollateFormat::PerfLike => {
            let mut demangle_cache = DemangleCache::new();
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            collate( collate_args, |collation, timestamp, process, tid, cpu, user_backtrace, kernel_backtrace| {
                write_perf_like_output(
                    &omit_regex,
                    &collation,
                    &mut demangle_cache,
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
    use super::{CollateArgs, Frame, DemangleCache, Collation, collate, collapse_frames};
    use std::path::Path;
    use std::collections::HashMap;
    use std::cell::RefCell;
    use env_logger;

    struct Data {
        collation: Collation,
        demangle_cache: RefCell< DemangleCache >,
        stacks: HashMap< Vec< Frame >, u64 >
    }

    fn load( filename: &str ) -> Data {
        let _ = env_logger::try_init();
        let path = Path::new( env!( "CARGO_MANIFEST_DIR" ) ).join( "test-data" ).join( "artifacts" ).join( filename );
        let args = CollateArgs {
            input_path: path.as_os_str(),
            debug_symbols: &[],
            force_stack_size: None,
            only_sample: None,
            without_kernel_callstacks: false
        };

        let mut stacks: HashMap< Vec< Frame >, u64 > = HashMap::new();
        let collation = collate( args, |collation, _timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
            collapse_frames(
                &None,
                &collation,
                process,
                tid,
                &user_backtrace,
                &kernel_backtrace,
                &mut stacks
            );
        }).unwrap();

        Data {
            collation,
            demangle_cache: RefCell::new( DemangleCache::new() ),
            stacks
        }
    }

    fn most_frequent_trace( data: &Data ) -> (&[Frame], u64) {
        let (frames, count) = data.stacks.iter().max_by( |a, b| a.1.cmp( &b.1 ) ).unwrap();
        (&frames, *count)
    }

    fn frame_to_str( data: &Data, frame: &Frame ) -> String {
        match *frame {
            Frame::Process( pid ) => {
                if let Some( process ) = data.collation.get_process( pid ) {
                    format!( "[process:{}]", process.executable )
                } else {
                    format!( "[process]" )
                }
            },
            Frame::MainThread => {
                format!( "[main_thread]" )
            },
            Frame::Thread( tid ) => {
                if let Some( name ) = data.collation.get_thread_name( tid ) {
                    format!( "[thread:{}]", name )
                } else {
                    format!( "[thread]" )
                }
            },
            Frame::UserSymbol( ref binary_id, _, symbol_index, table ) => {
                let mut demangle_cache = data.demangle_cache.borrow_mut();
                let (symbol, binary) = data.collation.get_user_symbol( &mut demangle_cache, binary_id, symbol_index, table );
                format!( "{}:{}", symbol, binary.basename )
            },
            Frame::UserBinary( ref binary_id, _ ) => {
                let binary = data.collation.get_binary( binary_id );
                format!( "?:{}", binary.basename )
            },
            Frame::User( _ ) => {
                format!( "?" )
            },
            Frame::KernelSymbol( symbol_index ) => {
                let symbol = data.collation.get_kernel_symbol( symbol_index );
                if let Some( module ) = symbol.module.as_ref() {
                    format!( "{}:{}:linux", symbol.name, module )
                } else {
                    format!( "{}:linux", symbol.name )
                }
            },
            Frame::Kernel( _ ) => {
                format!( "?" )
            }
        }
    }

    fn frames_to_str< 'a, I: IntoIterator< Item = &'a Frame > >( data: &Data, frames: I, highlighted: Option< usize > ) -> String
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

    fn assert_backtrace( data: &Data, frames: &[Frame], expected_frames: &[&str] ) {
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
            "pause:libc-2.26.so",
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
            "pause:libc-2.26.so",
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
}
