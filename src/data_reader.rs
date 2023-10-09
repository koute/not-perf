use std::fs;
use std::ffi::OsStr;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::ops::{Range, Index};
use std::cmp::{max, min};
use std::fmt;
use std::error::Error;

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
    DebugInfoIndex,
    LoadHint
};

use crate::args::{self, Granularity};
use crate::archive::{Packet, Inode, Bitness, UserFrame, ArchiveReader};
use crate::utils::StableIndex;
use crate::kallsyms::{self, KernelSymbol};
use crate::interner::{StringId, StringInterner};

use crate::stack_reader::StackReader;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub(crate) enum FrameKind {
    Process( u32 ),
    Thread( u32 ),
    MainThread,
    User( u64 ),
    UserBinary( BinaryId, u64 ),
    UserByAddress {
        binary_id: BinaryId,
        is_inline: bool,
        symbol: StringId,
        address: u64
    },
    UserByFunction {
        binary_id: BinaryId,
        is_inline: bool,
        symbol: StringId
    },
    UserByFunctionJit {
        symbol: StringId
    },
    UserByLine {
        binary_id: BinaryId,
        is_inline: bool,
        symbol: StringId,
        file: StringId,
        line: u64
    },
    Kernel( u64 ),
    KernelSymbol( usize )
}

pub(crate) struct Process {
    pid: u32,
    executable: String,
    memory_regions: RangeMap< Region >,
    base_address_for_binary: HashMap< BinaryId, u64 >,
    address_space: Box< dyn IAddressSpace >,
    address_space_needs_reload: bool
}

pub(crate) struct FdeHints {
    use_eh_frame_hdr: bool,
    load_eh_frame: LoadHint,
    load_debug_frame: bool
}

impl Process {
    pub(crate) fn pid( &self ) -> u32 {
        self.pid
    }

    pub(crate) fn executable( &self ) -> &str {
        &self.executable
    }

    fn reload_if_necessary( &mut self, debug_info_index: &mut DebugInfoIndex, binary_by_id: &mut HashMap< BinaryId, Binary >, fde_hints: &FdeHints ) {
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
                            alignment: 1,
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

            handle.should_use_eh_frame_hdr( fde_hints.use_eh_frame_hdr );
            handle.should_load_eh_frame( fde_hints.load_eh_frame );
            handle.should_load_debug_frame( fde_hints.load_debug_frame );
        });
    }
}

pub(crate) struct Binary {
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
    pub fn basename( &self ) -> &str {
        &self.basename
    }

    fn debuglink( &self ) -> Option< &[u8] > {
        self.debuglink.as_ref().map( |debuglink| debuglink.as_slice() )
    }

    fn build_id( &self ) -> Option< &[u8] > {
        self.build_id.as_ref().map( |build_id| build_id.as_slice() )
    }

    fn load_debug_info( &mut self, debug_info_index: &mut DebugInfoIndex ) {
        if self.debug_data.is_some() {
            return;
        }

        if let Some( debug_data ) = debug_info_index.get( &self.path, self.debuglink(), self.build_id() ) {
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

fn get_basename( path: &str ) -> &str {
    &path[ path.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ]
}

pub(crate) struct ReadDataArgs< 'a > {
    input_path: &'a OsStr,
    debug_symbols: Vec< &'a OsStr >,
    force_stack_size: Option< u32 >,
    only_sample: Option< u64 >,
    without_kernel_callstacks: bool,
    fde_hints: FdeHints,
    from: Option< TimestampBound >,
    to: Option< TimestampBound >,
    jitdump_path: Option< &'a OsStr >,
}

#[derive(Copy, Clone)]
enum TimestampBound {
    Relative( f64 ),
    RelativePercent( u8 )
}

fn parse_timestamp_bound( timestamp: impl AsRef< str > ) -> TimestampBound {
    let timestamp = timestamp.as_ref();
    if timestamp.ends_with( "%" ) {
        let timestamp: u8 = timestamp[ ..timestamp.len() - 1 ].parse().unwrap();
        TimestampBound::RelativePercent( timestamp )
    } else {
        let timestamp: f64 = timestamp.parse().unwrap();
        TimestampBound::Relative( timestamp )
    }
}

pub(crate) struct State {
    kallsyms: RangeMap< KernelSymbol >,
    process_index_by_pid: HashMap< u32, usize >,
    processes: Vec< Process >,
    thread_names: HashMap< u32, String >,
    binary_by_id: HashMap< BinaryId, Binary >,
    unfiltered_first_timestamp: Option< u64 >,
    cpu_count: u32,
    frequency: Option< u32 >,
    jitdump_names: RangeMap< String >,
}

impl State {
    fn get_kernel_symbol( &self, symbol_index: usize ) -> &KernelSymbol {
        self.kallsyms.get_value_by_index( symbol_index ).unwrap()
    }

    pub(crate) fn get_kernel_symbol_by_address( &self, address: u64 ) -> Option< &KernelSymbol > {
        self.kallsyms.get_value( address )
    }

    pub(crate) fn get_binary( &self, binary_id: &BinaryId ) -> &Binary {
        self.binary_by_id.get( binary_id ).unwrap()
    }

    pub(crate) fn get_thread_name( &self, tid: u32 ) -> Option< &str > {
        self.thread_names.get( &tid ).map( |str| str.as_str() )
    }

    pub(crate) fn get_process( &self, pid: u32 ) -> Option< &Process > {
        self.process_index_by_pid.get( &pid ).map( |&index| &self.processes[ index ] )
    }

    pub(crate) fn cpu_count( &self ) -> u32 {
        self.cpu_count
    }

    pub(crate) fn frequency( &self ) -> Option< u32 > {
        self.frequency.clone()
    }

    pub(crate) fn unfiltered_first_timestamp( &self ) -> Option< u64 > {
        self.unfiltered_first_timestamp.clone()
    }
}

fn to_binary_id( inode: Inode, name: &str ) -> BinaryId {
    if inode.is_invalid() {
        BinaryId::ByName( name.to_owned() )
    } else {
        BinaryId::ByInode( inode )
    }
}

pub(crate) fn to_s( timestamp: u64 ) -> f64 {
    timestamp as f64 / 1_000_000_000.0
}

pub(crate) struct EventSample< 'a > {
    pub timestamp: u64,
    pub process: &'a Process,
    pub tid: u32,
    pub cpu: u32,
    pub user_backtrace: &'a [UserFrame],
    pub kernel_backtrace: &'a [u64]
}

impl< 'a > EventSample< 'a > {
    pub fn decode(
        &self,
        state: &State,
        opts: &DecodeOpts,
        interner: &mut StringInterner
    ) -> Option< Vec< FrameKind > > {
        let mut frames = Vec::new();

        if !self.try_decode( state, opts, interner, Some( &mut frames ) ) {
            return None;
        }

        Some( frames )
    }

    pub fn try_decode(
        &self,
        state: &State,
        opts: &DecodeOpts,
        interner: &mut StringInterner,
        mut output: Option< &mut Vec< FrameKind > >
    ) -> bool {
        if let Some( ref mut output ) = output {
            let mut length = 0;
            length += self.user_backtrace.len();
            if opts.emit_kernel_frames {
                length += self.kernel_backtrace.len();
            }
            if opts.emit_thread_frames {
                length += 1;
            }
            if opts.emit_process_frames {
                length += 1;
            }
            output.reserve( length );

            if opts.emit_kernel_frames {
                for &addr in self.kernel_backtrace.iter() {
                    if let Some( index ) = state.kallsyms.get_index( addr ) {
                        output.push( FrameKind::KernelSymbol( index ) );
                    } else {
                        output.push( FrameKind::Kernel( addr ) );
                    }
                }
            }
        }

        for (nth_frame, user_frame) in self.user_backtrace.iter().enumerate() {
            let region = match self.process.memory_regions.get_value( user_frame.address ) {
                Some( region ) => region,
                None => {
                    if let Some( ref mut output ) = output {
                        let address = user_frame.initial_address.unwrap_or( user_frame.address );
                        if let Some( name ) = state.jitdump_names.get_value( address ) {
                            let string_id = interner.get_or_intern( name );
                            output.push( FrameKind::UserByFunctionJit {
                                symbol: string_id
                            });
                        } else {
                            output.push( FrameKind::User( address ) );
                        }
                    }
                    continue;
                }
            };

            let binary_id: BinaryId = region.into();
            let mut omit = false;
            self.process.address_space.decode_symbol_while( if nth_frame == 0 { user_frame.address } else { user_frame.address - 1 }, &mut |frame| {
                if let Some( name ) = frame.demangled_name.take().or_else( || frame.name.take() ) {
                    if let Some( ref regex ) = opts.omit_regex {
                        if regex.is_match( &name ) {
                            omit = true;
                            return false;
                        }
                    }

                    if let Some( ref mut output ) = output {
                        let string_id = interner.get_or_intern( name );
                        if opts.granularity == Granularity::Line {
                            if let Some( ref file ) = frame.file {
                                if let Some( line ) = frame.line {
                                    output.push( FrameKind::UserByLine {
                                        binary_id: binary_id.clone(),
                                        is_inline: frame.is_inline,
                                        symbol: string_id,
                                        file: interner.get_or_intern( file ),
                                        line
                                    });
                                    return true;
                                }
                            }
                        }

                        if opts.granularity == Granularity::Line || opts.granularity == Granularity::Function {
                            output.push( FrameKind::UserByFunction {
                                binary_id: binary_id.clone(),
                                is_inline: frame.is_inline,
                                symbol: string_id
                            });
                        } else {
                            output.push( FrameKind::UserByAddress {
                                binary_id: binary_id.clone(),
                                is_inline: frame.is_inline,
                                symbol: string_id,
                                address: frame.absolute_address
                            });
                        }
                    }
                } else {
                    if let Some( ref mut output ) = output {
                        output.push( FrameKind::UserBinary( binary_id.clone(), frame.absolute_address ) );
                    }
                }

                true
            });

            if omit {
                return false;
            }
        }

        if let Some( ref mut output ) = output {
            if opts.emit_thread_frames {
                if self.process.pid == self.tid {
                    output.push( FrameKind::MainThread );
                } else {
                    output.push( FrameKind::Thread( self.tid ) );
                }
            }

            if opts.emit_process_frames {
                output.push( FrameKind::Process( self.process.pid ) );
            }
        }

        true
    }
}

pub(crate) enum EventKind< 'a > {
    Sample( EventSample< 'a > ),

    #[doc(hidden)]
    __NonExhaustive
}

pub(crate) struct Event< 'a > {
    pub state: &'a State,
    pub kind: EventKind< 'a >
}

pub(crate) fn read_data< F >( args: ReadDataArgs, mut on_event: F ) -> Result< State, Box< dyn Error > >
    where F: FnMut( Event )
{
    let input_path = args.input_path;
    let fp = fs::File::open( args.input_path ).map_err( |err| format!( "cannot open {:?}: {}", input_path.clone(), err ) )?;
    let mut reader = ArchiveReader::new( fp ).validate_header().unwrap().skip_unknown();

    let mut state = State {
        kallsyms: RangeMap::new(),
        process_index_by_pid: HashMap::new(),
        processes: Vec::new(),
        thread_names: HashMap::new(),
        binary_by_id: HashMap::new(),
        unfiltered_first_timestamp: None,
        cpu_count: 1,
        frequency: None,
        jitdump_names: RangeMap::new()
    };

    let mut machine_architecture = String::new();
    let mut machine_endianness = Endianness::LittleEndian;
    let mut machine_bitness = Bitness::B64;
    let mut sample_counter = 0;
    let mut first_timestamp = None;
    let mut last_timestamp = None;

    let mut debug_info_index = DebugInfoIndex::new();
    for path in args.debug_symbols {
        debug_info_index.add( path );
    }

    let mut jitdump_events = VecDeque::new();
    if let Some( jitdump_path ) = args.jitdump_path {
        let jitdump = crate::jitdump::JitDump::load( jitdump_path.as_ref() ).map_err( |err| format!( "failed to open jitdump {:?}: {}", jitdump_path, err ) )?;
        for record in jitdump.records {
            match record {
                crate::jitdump::Record::CodeLoad { timestamp, virtual_address, name, code, .. } => {
                    jitdump_events.push_back( (timestamp, virtual_address..virtual_address + code.len() as u64, name) );
                },
                crate::jitdump::Record::Unknown { .. } => {}
            }
        }
    }

    fn process_jitdump( timestamp: u64, jitdump_events: &mut VecDeque< (u64, Range< u64 >, String) >, jitdump_names: &mut RangeMap< String > ) {
        while let Some( (event_timestamp, _, _) ) = jitdump_events.front() {
            if *event_timestamp > timestamp {
                return;
            }

            let (_, range, name) = jitdump_events.pop_front().unwrap();
            jitdump_names.push( range, name ).unwrap();
        }
    }

    if args.from.is_some() || args.to.is_some() {
        while let Some( packet ) = reader.next() {
            let packet = packet.unwrap();
            match packet {
                Packet::Sample { timestamp, .. } | Packet::RawSample { timestamp, .. } => {
                    if let Some( prev ) = first_timestamp {
                        first_timestamp = Some( min( prev, timestamp ) );
                    } else {
                        first_timestamp = Some( timestamp );
                    }

                    if let Some( prev ) = last_timestamp {
                        last_timestamp = Some( max( prev, timestamp ) );
                    } else {
                        last_timestamp = Some( timestamp );
                    }
                },
                _ => {}
            }
        }

        if let Some( last_timestamp ) = last_timestamp {
            let elapsed = last_timestamp - first_timestamp.unwrap();
            info!( "Elapsed: {:.02}s", to_s( elapsed ) );
        }

        let fp = fs::File::open( args.input_path ).map_err( |err| format!( "cannot open {:?}: {}", input_path, err ) )?;
        reader = ArchiveReader::new( fp ).validate_header().unwrap().skip_unknown();
    }

    let from = args.from;
    let to = args.to;
    let in_bounds = |first_timestamp: Option< u64 >, timestamp: u64| -> bool {
        if from.is_none() && to.is_none() {
            return true;
        }

        let relative = timestamp - first_timestamp.unwrap();
        let relative_s = to_s( relative );
        let relative_p = last_timestamp.map( |last_timestamp|
            (relative_s / to_s( last_timestamp - first_timestamp.unwrap() ) * 100.0) as u8
        );

        if let Some( from ) = from {
            match from {
                TimestampBound::Relative( bound ) => if relative_s < bound { return false },
                TimestampBound::RelativePercent( bound ) => if relative_p.unwrap() < bound { return false }
            }
        }

        if let Some( to ) = to {
            match to {
                TimestampBound::Relative( bound ) => if relative_s > bound { return false },
                TimestampBound::RelativePercent( bound ) => if relative_p.unwrap() > bound { return false }
            }
        }

        true
    };

    while let Some( packet ) = reader.next() {
        let packet = packet.unwrap();
        match packet {
            Packet::MachineInfo { architecture, bitness, endianness, cpu_count, .. } => {
                machine_architecture = architecture.into_owned();
                machine_bitness = bitness;
                machine_endianness = endianness;
                state.cpu_count = cpu_count;

                if machine_architecture == arch::native::Arch::NAME &&
                   machine_endianness == Endianness::NATIVE &&
                   machine_bitness == Bitness::NATIVE
                {
                    debug_info_index.enable_auto_load();
                }
            },
            Packet::ProcessInfo { pid, executable, .. } => {
                let executable = String::from_utf8_lossy( &executable ).into_owned();
                let executable = get_basename( &executable ).to_owned();
                debug!( "New process with PID {}: \"{}\"", pid, executable );

                let address_space: Box< dyn IAddressSpace > = match &*machine_architecture {
                    arch::arm::Arch::NAME => Box::new( AddressSpace::< arch::arm::Arch >::new() ),
                    arch::amd64::Arch::NAME => Box::new( AddressSpace::< arch::amd64::Arch >::new() ),
                    arch::mips64::Arch::NAME => Box::new( AddressSpace::< arch::mips64::Arch >::new() ),
                    arch::aarch64::Arch::NAME => Box::new( AddressSpace::< arch::aarch64::Arch >::new() ),
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

                let process_index = state.processes.len();
                state.processes.push( process );
                state.process_index_by_pid.insert( pid, process_index );
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

                let binary = Binary {
                    basename: get_basename( &path ).to_owned(),
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
                    if debug_info_index.get( &binary.path, binary.debuglink(), binary.build_id() ).is_none() {
                        warn!( "Missing external debug symbols for '{}': '{}'", binary.path, String::from_utf8_lossy( debuglink ) );
                    }
                }

                state.binary_by_id.insert( binary_id, binary );
            },
            Packet::BuildId { inode, path, build_id } => {
                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                let binary = state.binary_by_id.get_mut( &binary_id ).unwrap();
                binary.build_id = Some( build_id );
            },
            Packet::MemoryRegionMap { pid, range, is_read, is_write, is_executable, is_shared, file_offset, inode, major, minor, name } => {
                let process = match state.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut state.processes[ index ],
                    None => {
                        warn!( "Memory region mapped for a process with unknown PID={}", pid );
                        continue;
                    }
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
                let process = match state.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut state.processes[ index ],
                    None => {
                        warn!( "Memory region unmapped for a process with unknown PID={}", pid );
                        continue;
                    }
                };

                debug!( "Memory region unmapped for PID {}: 0x{:016X}-0x{:016X}", pid, range.start, range.end );
                process.memory_regions.remove_by_exact_range( range ).expect( "unknown region unmapped" );
                process.address_space_needs_reload = true;
            },
            Packet::Deprecated_BinaryMap { pid, inode, base_address } => {
                let process = match state.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut state.processes[ index ],
                    None => continue
                };

                let id = BinaryId::ByInode( inode );
                let binary = match state.binary_by_id.get( &id ) {
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
                let process = match state.process_index_by_pid.get( &pid ).cloned() {
                    Some( index ) => &mut state.processes[ index ],
                    None => continue
                };

                let binary_id = BinaryId::ByInode( inode );
                let binary = match state.binary_by_id.get( &binary_id ) {
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
                let binary = state.binary_by_id.get_mut( &binary_id ).unwrap();
                Arc::get_mut( &mut binary.string_tables ).unwrap().add( offset, data.into_owned() );
            },
            Packet::SymbolTable { inode, offset, data, string_table_offset, is_dynamic, path } => {
                let binary_name = String::from_utf8_lossy( &path );
                let binary_id = to_binary_id( inode, &binary_name );
                let binary = state.binary_by_id.get_mut( &binary_id ).unwrap();

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
                process_jitdump( timestamp, &mut jitdump_events, &mut state.jitdump_names );

                if first_timestamp.is_none() {
                    first_timestamp = Some( timestamp );
                } else {
                    first_timestamp = first_timestamp.map( |previous| min( previous, timestamp ) );
                }

                if !in_bounds( first_timestamp, timestamp ) {
                    continue;
                }

                if let Some( only_sample ) = args.only_sample {
                    if only_sample != sample_counter {
                        sample_counter += 1;
                        continue;
                    }
                }

                debug!( "Sample #{}", sample_counter );

                if state.processes[ 0 ].pid != pid {
                    debug!( "Sample #{} is from different process with PID {}, skipping!", sample_counter, pid );
                    continue;
                }

                state.processes[ 0 ].reload_if_necessary( &mut debug_info_index, &mut state.binary_by_id, &args.fde_hints );

                if args.without_kernel_callstacks {
                    kernel_backtrace = Vec::new().into();
                }

                on_event( Event {
                    state: &state,
                    kind: EventKind::Sample( EventSample {
                        timestamp,
                        process: &state.processes[ 0 ],
                        tid,
                        cpu,
                        user_backtrace: &user_backtrace,
                        kernel_backtrace: &kernel_backtrace
                    }
                )});

                sample_counter += 1;
            },
            Packet::RawSample { mut kernel_backtrace, pid, tid, stack, regs, cpu, timestamp, .. } => {
                process_jitdump( timestamp, &mut jitdump_events, &mut state.jitdump_names );

                if first_timestamp.is_none() {
                    first_timestamp = Some( timestamp );
                } else {
                    first_timestamp = first_timestamp.map( |previous| min( previous, timestamp ) );
                }

                if !in_bounds( first_timestamp, timestamp ) {
                    continue;
                }

                if let Some( only_sample ) = args.only_sample {
                    if only_sample != sample_counter {
                        sample_counter += 1;
                        continue;
                    }
                }

                debug!( "Sample #{}", sample_counter );

                if state.processes[ 0 ].pid != pid {
                    warn!( "Sample #{} is from different process with PID {}, skipping!", sample_counter, pid );
                    continue;
                }

                if args.without_kernel_callstacks {
                    kernel_backtrace = Vec::new().into();
                }

                let user_backtrace = {
                    let process = &mut state.processes[ 0 ];
                    process.reload_if_necessary( &mut debug_info_index, &mut state.binary_by_id, &args.fde_hints );

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

                on_event( Event {
                    state: &state,
                    kind: EventKind::Sample( EventSample {
                        timestamp,
                        process: &state.processes[ 0 ],
                        tid,
                        cpu,
                        user_backtrace: &user_backtrace,
                        kernel_backtrace: &kernel_backtrace
                    }
                )});

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
                state.binary_by_id.get_mut( &binary_id ).unwrap().data = Some( Arc::new( data ) );
            },
            Packet::FileBlob { ref path, ref data } if path.as_ref() == b"/proc/kallsyms" => {
                state.kallsyms = kallsyms::parse( data.as_ref() );
            },
            Packet::ThreadName { tid, name, .. } => {
                if name.is_empty() {
                    state.thread_names.remove( &tid );
                    continue;
                }

                let name = String::from_utf8_lossy( &name ).into_owned();
                state.thread_names.insert( tid, name );
            },
            Packet::ProfilingFrequency { frequency } => {
                state.frequency = Some( frequency );
            },
            _ => {}
        }
    }

    state.unfiltered_first_timestamp = first_timestamp;
    Ok( state )
}

pub(crate) struct DecodeOpts {
    pub omit_regex: Option< Regex >,
    pub emit_kernel_frames: bool,
    pub emit_thread_frames: bool,
    pub emit_process_frames: bool,
    pub granularity: Granularity
}

fn strip_path( path: &str ) -> &str {
    if let Some( index ) = path.rfind( "/src/" ) {
        return &path[ path[ ..index ].rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ];
    }

    get_basename( path )
}

#[test]
fn test_strip_path() {
    assert_eq!(
        strip_path( "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/log-0.4.14/src/lib.rs" ),
        "log-0.4.14/src/lib.rs"
    );

    assert_eq!(
        strip_path( "/rustc/29ef6cf1637aa8317f8911f93f14e18d404c1b0e/library/core/src/ops/function.rs" ),
        "core/src/ops/function.rs"
    );

    assert_eq!(
        strip_path( "/random/path/project/src/module/runtime.rs" ),
        "project/src/module/runtime.rs"
    );
}

pub(crate) fn write_frame< T: fmt::Write >(
    state: &State,
    interner: &StringInterner,
    output: &mut T,
    frame: &FrameKind
)
{
    match *frame {
        FrameKind::Process( pid ) => {
            if let Some( process ) = state.get_process( pid ) {
                write!( output, "{} [PID={}]", process.executable, pid ).unwrap()
            } else {
                write!( output, "[PID={}]", pid ).unwrap()
            }
        },
        FrameKind::MainThread => {
            write!( output, "[MAIN_THREAD]" ).unwrap()
        },
        FrameKind::Thread( tid ) => {
            if let Some( name ) = state.get_thread_name( tid ) {
                write!( output, "{} [THREAD={}]", name, tid ).unwrap()
            } else {
                write!( output, "[THREAD={}]", tid ).unwrap()
            }
        },
        FrameKind::UserByLine { ref binary_id, is_inline, symbol, file, line } => {
            if is_inline {
                write!( output, "inline " ).unwrap();
            }
            let binary = state.get_binary( binary_id );
            let symbol = interner.resolve( symbol ).unwrap();
            let path = strip_path( interner.resolve( file ).unwrap() );
            write!( output, "{} [{}:{}, {}]", symbol, path, line, binary.basename ).unwrap()
        },
        FrameKind::UserByFunction { ref binary_id, is_inline, symbol } => {
            if is_inline {
                write!( output, "inline " ).unwrap();
            }
            let binary = state.get_binary( binary_id );
            let symbol = interner.resolve( symbol ).unwrap();
            write!( output, "{} [{}]", symbol, binary.basename ).unwrap()
        },
        FrameKind::UserByFunctionJit { symbol } => {
            let symbol = interner.resolve( symbol ).unwrap();
            write!( output, "{} [JIT]", symbol ).unwrap()
        },
        FrameKind::UserByAddress { ref binary_id, is_inline, symbol, address } => {
            write!( output, "0x{:016X} ", address ).unwrap();
            if is_inline {
                write!( output, "inline " ).unwrap();
            }
            let binary = state.get_binary( binary_id );
            let symbol = interner.resolve( symbol ).unwrap();
            write!( output, "{} [{}]", symbol, binary.basename ).unwrap()
        },
        FrameKind::UserBinary( ref binary_id, addr ) => {
            let binary = state.get_binary( binary_id );
            write!( output, "0x{:016X} [{}]", addr, binary.basename ).unwrap()
        },
        FrameKind::User( addr ) => {
            write!( output, "0x{:016X}", addr ).unwrap()
        },
        FrameKind::KernelSymbol( symbol_index ) => {
            let symbol = state.get_kernel_symbol( symbol_index );
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


pub(crate) fn repack_cli_args( args: &args::SharedCollationArgs ) -> (Option< Regex >, ReadDataArgs) {
    let omit_regex = if args.omit.is_empty() {
        None
    } else {
        let regex = args.omit.join( "|" );
        let regex = Regex::new( &regex ).expect( "invalid regexp passed in `--omit`" );
        Some( regex )
    };

    let debug_symbols: Vec< _ > = args.debug_symbols.iter().map( |path| path.as_os_str() ).collect();
    let read_data_args = ReadDataArgs {
        input_path: &args.input,
        debug_symbols,
        force_stack_size: args.force_stack_size,
        only_sample: args.only_sample,
        without_kernel_callstacks: args.without_kernel_callstacks,
        fde_hints: FdeHints {
            use_eh_frame_hdr: false,
            load_eh_frame: LoadHint::Always,
            load_debug_frame: true
        },
        from: args.from.as_ref().map( parse_timestamp_bound ),
        to: args.to.as_ref().map( parse_timestamp_bound ),
        jitdump_path: args.jitdump.as_ref().map( |path| path.as_os_str() ),
    };

    (omit_regex, read_data_args)
}

#[cfg(test)]
mod test {
    use super::{StringInterner, ReadDataArgs, DecodeOpts, EventKind, FrameKind, State, FdeHints, read_data};
    use nwind::LoadHint;
    use std::path::Path;
    use std::collections::HashMap;

    use crate::args::Granularity;

    struct Data {
        state: State,
        stacks: HashMap< Vec< FrameKind >, u64 >,
        interner: StringInterner
    }

    fn load( filename: &str ) -> Data {
        load_with_fde_hints( filename, FdeHints {
            use_eh_frame_hdr: false,
            load_eh_frame: LoadHint::Always,
            load_debug_frame: true
        })
    }

    fn load_with_fde_hints( filename: &str, fde_hints: FdeHints ) -> Data {
        let _ = env_logger::try_init();
        let mut interner = StringInterner::new();
        let path = Path::new( env!( "CARGO_MANIFEST_DIR" ) ).join( "test-data" ).join( "artifacts" ).join( filename );
        let args = ReadDataArgs {
            input_path: path.as_os_str(),
            debug_symbols: Vec::new(),
            force_stack_size: None,
            only_sample: None,
            without_kernel_callstacks: false,
            fde_hints,
            from: None,
            to: None
        };

        let opts = DecodeOpts {
            omit_regex: None,
            emit_kernel_frames: true,
            emit_thread_frames: true,
            emit_process_frames: true,
            granularity: Granularity::Function
        };

        let mut stacks: HashMap< Vec< FrameKind >, u64 > = HashMap::new();
        let state = read_data( args, |event| {
            match event.kind {
                EventKind::Sample( sample ) => {
                    let frames = sample.decode(
                        &event.state,
                        &opts,
                        &mut interner
                    );
                    if let Some( frames ) = frames {
                        *stacks.entry( frames ).or_insert( 0 ) += 1;
                    }
                },
                _ => {}
            }
        }).unwrap();

        Data {
            state,
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
                if let Some( process ) = data.state.get_process( pid ) {
                    format!( "[process:{}]", process.executable )
                } else {
                    format!( "[process]" )
                }
            },
            FrameKind::MainThread => {
                format!( "[main_thread]" )
            },
            FrameKind::Thread( tid ) => {
                if let Some( name ) = data.state.get_thread_name( tid ) {
                    format!( "[thread:{}]", name )
                } else {
                    format!( "[thread]" )
                }
            },
            | FrameKind::UserByFunction { ref binary_id, symbol, .. }
            | FrameKind::UserByLine { ref binary_id, symbol, .. }
            | FrameKind::UserByAddress { ref binary_id, symbol, .. }
            => {
                let binary = data.state.get_binary( binary_id );
                let symbol = data.interner.resolve( symbol ).unwrap();
                format!( "{}:{}", symbol, binary.basename )
            },
            FrameKind::UserBinary( ref binary_id, _ ) => {
                let binary = data.state.get_binary( binary_id );
                format!( "?:{}", binary.basename )
            },
            FrameKind::User( _ ) => {
                format!( "?" )
            },
            FrameKind::KernelSymbol( symbol_index ) => {
                let symbol = data.state.get_kernel_symbol( symbol_index );
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
    fn collate_aarch64_hot_spot_usleep_in_a_loop_no_fp() {
        let data = load( "aarch64-usleep_in_a_loop_no_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 40 );
        assert_backtrace( &data, frames, &[
            "[process:aarch64-usleep_in_a_loop_no_fp]",
            "[main_thread]",
            "__libc_start_main:libc-2.26.so",
            "main:aarch64-usleep_in_a_loop_no_fp",
            "function:aarch64-usleep_in_a_loop_no_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "el0_svc_naked:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_aarch64_perfect_unwinding_usleep_in_a_loop_no_fp() {
        let data = load( "aarch64-usleep_in_a_loop_no_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:aarch64-usleep_in_a_loop_no_fp]",
                "[main_thread]",
                "__libc_start_main:libc-2.26.so",
                "main:aarch64-usleep_in_a_loop_no_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_aarch64_hot_spot_usleep_in_a_loop_fp() {
        let data = load( "aarch64-usleep_in_a_loop_fp.nperf" );

        let (frames, count) = most_frequent_trace( &data );
        assert!( count >= 40 );
        assert_backtrace( &data, frames, &[
            "[process:aarch64-usleep_in_a_loop_fp]",
            "[main_thread]",
            "__libc_start_main:libc-2.26.so",
            "main:aarch64-usleep_in_a_loop_fp",
            "function:aarch64-usleep_in_a_loop_fp",
            "usleep:libc-2.26.so",
            "nanosleep:libc-2.26.so",
            "el0_svc_naked:linux",
            "sys_nanosleep:linux",
            "**"
        ]);
    }

    #[test]
    fn collate_aarch64_perfect_unwinding_usleep_in_a_loop_fp() {
        let data = load( "aarch64-usleep_in_a_loop_fp.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:aarch64-usleep_in_a_loop_fp]",
                "[main_thread]",
                "__libc_start_main:libc-2.26.so",
                "main:aarch64-usleep_in_a_loop_fp",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_aarch64_noreturn() {
        let data = load( "aarch64-noreturn.nperf" );
        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:aarch64-noreturn]",
                "[main_thread]",
                "__libc_start_main:libc-2.26.so",
                "main:aarch64-noreturn",
                "function:aarch64-noreturn",
                "infinite_loop:aarch64-noreturn",
                "usleep:libc-2.26.so",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_aarch64_perfect_unwinding_floating_point() {
        let data = load( "aarch64-floating_point.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:aarch64-floating_point]",
                "[main_thread]",
                "__libc_start_main:libc-2.26.so",
                "main:aarch64-floating_point",
                "**"
            ]);
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
    fn collate_arm_perfect_unwinding_floating_point() {
        let data = load( "arm-floating_point.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:arm-floating_point]",
                "[main_thread]",
                "?:arm-floating_point",
                "__libc_start_main:libc-2.26.so",
                "main:arm-floating_point",
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
    fn collate_amd64_perfect_unwinding_usleep_in_a_loop_fp_only_eh_frame_hdr() {
        let data = load_with_fde_hints(
            "amd64-usleep_in_a_loop_fp.nperf",
            FdeHints {
                use_eh_frame_hdr: true,
                load_eh_frame: LoadHint::Never,
                load_debug_frame: false
            }
        );

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
    fn collate_amd64_perfect_unwinding_usleep_in_a_loop_fp_only_loaded_eh_frame() {
        let data = load_with_fde_hints(
            "amd64-usleep_in_a_loop_fp.nperf",
            FdeHints {
                use_eh_frame_hdr: false,
                load_eh_frame: LoadHint::Always,
                load_debug_frame: false
            }
        );

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
    fn collate_amd64_perfect_unwinding_pthread_cond_wait() {
        let data = load( "amd64-pthread_cond_wait.nperf" );

        let main_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[main_thread]" ).collect();
        let thread_stacks: Vec< _ > = data.stacks.iter().filter( |&(ref frames, _)| frame_to_str( &data, &frames[ frames.len() - 2 ] ) == "[thread:another thread]" ).collect();

        for (frames, _) in main_stacks.iter() {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-pthread_cond_wait]",
                "[main_thread]",
                "_start:amd64-pthread_cond_wait",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-pthread_cond_wait",
                "**"
            ]);
        }

        for (frames, _) in thread_stacks.iter() {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-pthread_cond_wait]",
                "[thread:another thread]",
                "clone:libc-2.26.so",
                "?:libpthread-2.26.so",
                "thread_main:amd64-pthread_cond_wait",
                "**"
            ]);
        }
    }

    #[test]
    fn collate_amd64_perfect_unwinding_floating_point() {
        let data = load( "amd64-floating_point.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:amd64-floating_point]",
                "[main_thread]",
                "_start:amd64-floating_point",
                "__libc_start_main:libc-2.26.so",
                "main:amd64-floating_point",
                "**"
            ]);
        }
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
            "__pthread_cond_wait_common:libpthread-2.26.so",
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
    fn collate_mips64_perfect_unwinding_floating_point() {
        let data = load( "mips64-floating_point.nperf" );

        for (ref frames, _) in &data.stacks {
            assert_backtrace( &data, &frames, &[
                "[process:mips64-floating_point]",
                "[main_thread]",
                "?:mips64-floating_point",
                "__libc_start_main:libc-2.26.so",
                "main:mips64-floating_point",
                "**"
            ]);
        }
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
