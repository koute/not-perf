use std::collections::{HashSet, HashMap};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::borrow::Cow;
use std::slice;
use std::time::Instant;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::ops::{Deref, DerefMut, Range};
use std::error::Error;
use std::path::Path;

use chrono::prelude::*;
use speedy::{Writable, Endianness};
use libc;
use num_cpus;

use nwind::maps::{self, Region};
use nwind::arch::{self, Architecture, Registers};
use nwind::{
    IAddressSpace,
    AddressSpace,
    BinarySource,
    BinaryData,
    DwarfRegs,
    RangeMap
};

use perf::{Event, CommEvent, Mmap2Event, EventSource};
use perf_group::PerfGroup;
use perf_arch::IntoDwarfRegs;
use utils::{SigintHandler, read_string_lossy, get_major, get_minor, get_ms};
use archive::{FramedPacket, Packet, Inode, Bitness, DwarfReg, ARCHIVE_MAGIC, ARCHIVE_VERSION};
use execution_queue::ExecutionQueue;
use ps::{wait_for_process, find_process};
use stack_reader::StackReader;

pub enum TargetProcess {
    ByPid( u32 ),
    ByName( String ),
    ByNameWaiting( String )
}

fn get_vdso() -> Option< &'static [u8] > {
    let maps_str = read_string_lossy( "/proc/self/maps" ).expect( "cannot read /proc/self/maps" );
    let maps = maps::parse( &maps_str );
    for region in &maps {
        if region.is_executable && region.name == "[vdso]" {
            let bytes: &[u8] = unsafe {
                slice::from_raw_parts( region.start as *const u8, (region.end - region.start) as usize )
            };

            return Some( bytes );
        }
    }

    None
}

fn update_maps( maps: &mut RangeMap< Region >, new_maps: &mut Vec< Region > ) {
    let mut overlapping = Vec::new();
    for region in new_maps.drain( .. ) {
        if !region.name.is_empty() {
            maps.retain( |old_region| {
                let is_same =
                    old_region.name == region.name &&
                    old_region.inode == region.inode &&
                    old_region.major == region.major &&
                    old_region.minor == region.minor &&
                    old_region.is_read == region.is_read &&
                    old_region.is_write == region.is_write &&
                    old_region.is_executable == region.is_executable &&
                    old_region.is_shared == region.is_shared &&
                    old_region.file_offset == region.file_offset;
                !is_same
            });
        }

        let range = region.start..region.end;
        while let Some( index ) = maps.get_index_by_any_point( &range ) {
            overlapping.push( maps.remove_by_index( index ).1 );
        }

        maps.push( region.start..region.end, region ).unwrap();
        for mut old_region in overlapping.drain( .. ) {
            if old_region.start < range.start {
                let mut old_region = old_region.clone();
                old_region.end = range.start;
                maps.push( old_region.start..old_region.end, old_region ).unwrap();
            }
            if old_region.end > range.end {
                let offset = range.end - old_region.start;
                old_region.start = range.end;
                if old_region.inode != 0 {
                    old_region.file_offset += offset;
                }

                maps.push( old_region.start..old_region.end, old_region ).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::update_maps;

    use std::collections::HashMap;

    use env_logger;

    use nwind::{arch, RangeMap, IAddressSpace, AddressSpace, BinarySource, Inode};
    use nwind::maps::Region;

    use quickcheck::{Arbitrary, Gen};

    fn region( start: u64, end: u64, file_offset: u64, name: &str ) -> Region {
        Region {
            start,
            end,
            is_read: true,
            is_write: false,
            is_executable: true,
            is_shared: false,
            file_offset,
            major: 0,
            minor: 0,
            inode: 1,
            name: name.to_owned()
        }
    }

    #[test]
    fn test_update_maps_basic() {
        let mut maps = RangeMap::new();
        update_maps( &mut maps, &mut vec![ region( 2, 8, 0x1000, "" ) ] );
        assert_eq!( maps.values().len(), 1 );

        update_maps( &mut maps, &mut vec![ region( 0, 4, 0x1000, "" ) ] );
        assert_eq!( maps.values().len(), 2 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().start, 0 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().end,   4 );
        assert_eq!( maps.get_value_by_index( 1 ).unwrap().start, 4 );
        assert_eq!( maps.get_value_by_index( 1 ).unwrap().end,   8 );
        assert_eq!( maps.get_value_by_index( 1 ).unwrap().file_offset, 0x1002 );

        update_maps( &mut maps, &mut vec![ region( 0, 8, 0x1000, "" ) ] );
        assert_eq!( maps.values().len(), 1 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().start, 0 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().end,   8 );

        update_maps( &mut maps, &mut vec![ region( 0, 8, 0x1000, "foobar" ) ] );
        assert_eq!( maps.values().len(), 1 );

        update_maps( &mut maps, &mut vec![ region( 16, 24, 0x1000, "foobar" ) ] );
        assert_eq!( maps.values().len(), 1 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().start, 16 );
        assert_eq!( maps.get_value_by_index( 0 ).unwrap().end,   24 );
    }

    fn test_reload_with_regions( all_ranges: Vec< Vec< Region > > ) {
        let mut maps = RangeMap::new();
        let mut new_maps = Vec::new();
        let mut address_space = AddressSpace::< arch::amd64::Arch >::new();
        let mut region_map = RangeMap::new();

        let mut binaries = HashMap::new();

        let id = Inode { inode: 1, dev_major: 0, dev_minor: 0 };
        binaries.insert( id.clone(), BinarySource::Slice( (&b"file_1"[..]).into(), id, (&include_bytes!( "../test-data/bin/amd64-usleep_in_a_loop_no_fp" )[..]).into() ) );

        for ranges in all_ranges {
            for region in ranges {
                new_maps.push( region );
            }

            update_maps( &mut maps, &mut new_maps );
            let res = address_space.reload( binaries.clone(), maps.values().cloned().collect(), false );

            for range in res.regions_unmapped {
                region_map.remove_by_exact_range( range ).expect( "unknown region unmapped" );
            }

            for region in res.regions_mapped {
                region_map.push( region.start..region.end, () ).expect( "duplicate memory region" );
            }
        }
    }

    #[test]
    fn spurious_reload_with_no_base_address_does_not_panic() {
        let _ = env_logger::try_init();
        test_reload_with_regions( vec![
            vec![region( 0, 80, 0x1000, "file_1" )],
            vec![]
        ]);
    }

    #[test]
    fn reload_which_clears_base_address_does_not_panic() {
        let _ = env_logger::try_init();
        test_reload_with_regions( vec![
            vec![region( 50, 100, 0, "file_1" )],
            vec![region( 90, 95, 4096, "file_1" )],
            vec![region( 0, 55, 4096, "file_1" )],
            vec![region( 60, 65, 0, "file_1" )]
        ]);
    }

    #[derive(Clone, Debug)]
    struct TestRegion( u64, u64, u64, &'static str );

    impl Arbitrary for TestRegion {
        fn arbitrary< G: Gen >( gen: &mut G ) -> Self {
            let start = u8::arbitrary( gen ) as u64;
            let end = u8::arbitrary( gen ) as u64;
            let (start, end) = if start < end { (start, end) } else { (end, start) };
            let file = match u8::arbitrary( gen ) % 3 {
                0 => "file_1",
                1 => "file_2",
                2 => "",
                _ => unreachable!()
            };

            let c = bool::arbitrary( gen );
            TestRegion( start, end, if c { 0 } else { 0x1000 }, file )
        }
    }

    quickcheck! {
        fn reloading_never_panics( all_regions: Vec< Vec< TestRegion > > ) -> bool {
            let _ = env_logger::try_init();

            let all_regions = all_regions.into_iter().map( |regions| regions.into_iter().map( |entry| {
                region( entry.0, entry.1, entry.2, entry.3 )
            }).collect() ).collect();

            test_reload_with_regions( all_regions );
            true
        }
    }
}

fn process_maps( maps: &RangeMap< Region >, offline: bool, pid: u32, address_space: &mut AddressSpace< arch::native::Arch >, writer: &ExecutionQueue< PacketWriter > ) {
    debug!( "Processing maps..." );

    let reloaded = {
        let mut binaries = HashMap::new();
        let mut regions = Vec::new();
        for region in maps.values() {
            if region.is_executable && region.name == "[vdso]" {
                let vdso = match get_vdso() {
                    Some( vdso ) => vdso,
                    None => continue
                };

                const VDSO_ID: Inode = Inode {
                    // Since real major/minor numbers are not full 32-bit numbers
                    // we can safely do this and not risk any collisions.
                    dev_major: 0xFFFFFFFF,
                    dev_minor: 0xFFFFFFFF,
                    inode: 1
                };

                let mut region = region.clone();
                region.inode = VDSO_ID.inode;
                region.major = VDSO_ID.dev_major;
                region.minor = VDSO_ID.dev_minor;

                binaries.insert( VDSO_ID, BinarySource::Slice( (&b"[vdso]"[..]).into(), VDSO_ID, vdso.into() ) );
                regions.push( region );

                continue;
            }

            if region.is_shared || region.name.is_empty() || region.inode == 0 {
                continue;
            }

            let inode = Inode {
                dev_major: region.major,
                dev_minor: region.minor,
                inode: region.inode
            };

            binaries.insert( inode, BinarySource::Filesystem( Some( inode ), Path::new( &region.name ).into() ) );
            regions.push( region.clone() );
        }

        for region in &regions {
            trace!( "Map: 0x{:016X}-0x{:016X} '{}'", region.start, region.end, region.name );
        }

        address_space.reload( binaries, regions, !offline )
    };

    writer.spawn( move |fp| {
        debug!( "Writing binaries and maps..." );
        for (binary, base_address) in reloaded.binaries_unmapped {
            let inode = binary.inode().unwrap();
            debug!( "Binary unmapped: PID={}, ID={:?}, base_address=0x{:016X}", pid, inode, base_address );
            fp.write_binary_unmap( pid, inode, base_address )?;
        }

        for (binary, base_address) in reloaded.binaries_mapped {
            debug!( "Binary mapped: PID={}, ID={:?}, base_address=0x{:016X}", pid, binary.inode(), base_address );
            fp.write_binary( &binary )?;
            fp.write_binary_map( pid, binary.inode().unwrap(), base_address )?;
        }

        for range in reloaded.regions_unmapped {
            fp.write_region_unmap( pid, range )?;
        }

        for region in reloaded.regions_mapped {
            fp.write_region_map( pid, &region )?;
        }

        Ok(())
    });
}

struct PacketWriter {
    offline: bool,
    fp: BufWriter< File >,
    binaries_written: HashSet< Inode >
}

impl Deref for PacketWriter {
    type Target = BufWriter< File >;

    #[inline]
    fn deref( &self ) -> &Self::Target {
        &self.fp
    }
}

impl DerefMut for PacketWriter {
    #[inline]
    fn deref_mut( &mut self ) -> &mut Self::Target {
        &mut self.fp
    }
}

impl io::Write for PacketWriter {
    fn write( &mut self, buf: &[u8] ) -> io::Result< usize > {
        self.fp.write( buf )
    }

    fn flush( &mut self ) -> io::Result< () > {
        self.fp.flush()
    }
}

impl PacketWriter {
    fn write_packet( &mut self, packet: Packet ) -> io::Result< () > {
        FramedPacket::Known( packet ).write_to_stream( Endianness::LittleEndian, &mut self.fp )
    }

    fn write_header( &mut self ) -> io::Result< () > {
        debug!( "Writing header..." );
        self.write_packet( Packet::Header {
            magic: ARCHIVE_MAGIC,
            version: ARCHIVE_VERSION
        })
    }

    fn write_machine_info( &mut self ) -> io::Result< () > {
        debug!( "Writing machine info..." );
        self.write_packet( Packet::MachineInfo {
            cpu_count: num_cpus::get() as u32,
            endianness: Endianness::NATIVE,
            bitness: Bitness::NATIVE,
            architecture: arch::native::Arch::NAME.into()
        })
    }

    fn write_region_map( &mut self, pid: u32, region: &maps::Region ) -> io::Result< () > {
        self.write_packet( Packet::MemoryRegionMap {
            pid,
            range: region.start..region.end,
            is_read: region.is_read,
            is_write: region.is_write,
            is_executable: region.is_executable,
            is_shared: region.is_shared,
            file_offset: region.file_offset,
            inode: region.inode,
            major: region.major,
            minor: region.minor,
            name: region.name.as_bytes().into()
        })
    }

    fn write_region_unmap( &mut self, pid: u32, range: Range< u64 > ) -> io::Result< () > {
        self.write_packet( Packet::MemoryRegionUnmap {
            pid,
            range
        })
    }

    fn write_binary_map( &mut self, pid: u32, id: Inode, base_address: u64 ) -> io::Result< () > {
        self.write_packet( Packet::BinaryMap {
            pid,
            id,
            base_address
        })
    }

    fn write_binary_unmap( &mut self, pid: u32, id: Inode, base_address: u64 ) -> io::Result< () > {
        self.write_packet( Packet::BinaryUnmap {
            pid,
            id,
            base_address
        })
    }

    fn write_binary( &mut self, binary: &BinaryData ) -> io::Result< () > {
        if self.binaries_written.contains( &binary.inode().unwrap() ) {
            return Ok(());
        }

        self.binaries_written.insert( binary.inode().unwrap() );

        let debuglink = if let Some( range ) = binary.gnu_debuglink_range() {
            &binary.as_bytes()[ range.start as usize..range.end as usize ]
        } else {
            &b""[..]
        };

        self.write_packet( Packet::BinaryInfo {
            id: binary.inode().unwrap(),
            path: binary.name().as_bytes().into(),
            is_shared_object: binary.is_shared_object(),
            debuglink: debuglink.into(),
            symbol_table_count: binary.symbol_tables().len() as u16
        })?;

        if let Some( build_id ) = binary.build_id() {
            self.write_packet( Packet::BuildId {
                id: binary.inode().unwrap(),
                build_id: build_id.to_owned()
            })?;
        }

        if self.offline {
            debug!( "Writing binary '{}'...", binary.name() );
            self.write_packet( Packet::BinaryBlob {
                id: binary.inode().unwrap(),
                path: binary.name().as_bytes().into(),
                data: binary.as_bytes().into(),
            })?;
        } else {
            debug!( "Writing symbols of '{}'...", binary.name() );
            let mut strtab_done = HashSet::new();
            for symbol_table in binary.symbol_tables() {
                let range = symbol_table.range.start as usize..symbol_table.range.end as usize;

                if !strtab_done.contains( &symbol_table.strtab_range ) {
                    strtab_done.insert( symbol_table.strtab_range.clone() );

                    let strtab_range = symbol_table.strtab_range.start as usize..symbol_table.strtab_range.end as usize;
                    self.write_packet( Packet::StringTable {
                        binary_id: binary.inode().unwrap(),
                        offset: symbol_table.strtab_range.start,
                        data: binary.as_bytes()[ strtab_range ].into()
                    })?;
                }

                self.write_packet( Packet::SymbolTable {
                    binary_id: binary.inode().unwrap(),
                    offset: symbol_table.range.start,
                    string_table_offset: symbol_table.strtab_range.start,
                    is_dynamic: symbol_table.is_dynamic,
                    data: binary.as_bytes()[ range ].into()
                })?;
            }
        }

        Ok(())
    }
}

fn initialize(
    sigint_handler: &SigintHandler,
    args: Args
) -> Result< (u32, RangeMap< Region >, PerfGroup, AddressSpace< arch::native::Arch >, ExecutionQueue< PacketWriter >), Box< Error > >
{
    let offline = args.offline;
    let pid = match args.target_process {
        TargetProcess::ByPid( pid ) => pid,
        TargetProcess::ByName( name ) => {
            if let Some( pid ) = find_process( &name ).unwrap() {
                pid
            } else {
                return Err( format!( "no process named '{}' was found", name ).into() );
            }
        },
        TargetProcess::ByNameWaiting( name ) => {
            if let Some( pid ) = wait_for_process( sigint_handler, &name ).unwrap() {
                pid
            } else {
                return Err( format!( "no process named '{}' was found", name ).into() );
            }
        }
    };

    let start_timestamp = Instant::now();

    if args.lock_memory {
        unsafe {
            libc::mlockall( libc::MCL_CURRENT | libc::MCL_FUTURE );
        }
    }

    if !Path::new( &format!( "/proc/{}", pid ) ).exists() {
        return Err( format!( "no process with PID {} was found", pid ).into() );
    }

    let executable = fs::read_link( format!( "/proc/{}/exe", pid ) ).map_err( |err| format!( "cannot read /proc/{}/exe: {}", pid, err ) )?;
    let exec_metadata = fs::metadata( &executable ).map_err( |err| format!( "cannot read the metadata of /proc/{}/exe: {}", pid, err ) )?;
    let exec_ident = Inode {
        inode: exec_metadata.ino(),
        dev_major: get_major( exec_metadata.dev() ),
        dev_minor: get_minor( exec_metadata.dev() )
    };

    let output_path = if let Some( output_path ) = args.output_path {
        output_path.to_os_string()
    } else {
        let executable = executable.to_string_lossy();
        let basename: String = executable[ executable.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ].chars().map( |ch| {
            if ch.is_alphanumeric() {
                ch
            } else {
                '_'
            }
        }).collect();

        let now = Utc::now();
        let filename = format!( "{}{:02}{:02}_{:02}{:02}{:02}_{:05}_{}.nperf", now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second(), pid, basename );
        OsStr::new( &filename ).to_os_string()
    };

    info!( "Opening {:?} for writing...", output_path );
    let fp = File::create( &output_path ).map_err( |err| format!( "cannot open {:?} for writing: {}", output_path, err ) )?;
    let fp = PacketWriter {
        offline,
        fp: BufWriter::new( fp ),
        binaries_written: HashSet::new()
    };

    let writer = ExecutionQueue::new( fp );
    writer.spawn( move |fp| {
        fp.write_header()?;
        fp.write_machine_info()?;

        debug!( "Writing kallsyms..." );
        let kallsyms = fs::read( "/proc/kallsyms" )?;
        fp.write_packet( Packet::FileBlob {
            path: "/proc/kallsyms".as_bytes().into(),
            data: kallsyms.into()
        })?;

        Ok(())
    });

    writer.spawn( move |fp| {
        debug!( "Writing process info..." );
        fp.write_packet( Packet::ProcessInfo {
            pid: pid,
            executable: executable.as_path().as_os_str().as_bytes().into(),
            binary_id: exec_ident
        })?;

        Ok(())
    });

    info!( "Opening perf events for {}...", pid );
    let mut perf = PerfGroup::open( pid, args.frequency, args.stack_size, args.event_source ).map_err( |err| format!( "failed to start profiling: {}", err ) )?;

    let mut maps = RangeMap::new();
    let mut new_maps = Vec::new();
    for event in perf.take_initial_events() {
        match event {
            Event::Mmap2( event ) => {
                handle_mmap2_event( event, &mut new_maps );
            },
            Event::Comm( event ) => handle_comm_event( event, &writer ),
            _ => unreachable!()
        }
    }

    let mut address_space = AddressSpace::< arch::native::Arch >::new();
    address_space.set_panic_on_partial_backtrace( args.panic_on_partial_backtrace );

    update_maps( &mut maps, &mut new_maps );
    process_maps( &maps, offline, pid, &mut address_space, &writer );

    writer.spawn( move |_| {
        info!( "Ready to write profiling data!" );
        Ok(())
    });

    let elapsed = start_timestamp.elapsed();
    debug!( "Initial initialization done; took {}ms", get_ms( elapsed ) );

    Ok( (pid, maps, perf, address_space, writer) )
}

pub struct Args< 'a > {
    pub target_process: TargetProcess,
    pub frequency: u64,
    pub event_source: EventSource,
    pub stack_size: u32,
    pub discard_all: bool,
    pub sample_count_limit: Option< u64 >,
    pub time_limit: Option< u64 >,
    pub output_path: Option< &'a OsStr >,
    pub lock_memory: bool,
    pub offline: bool,
    pub panic_on_partial_backtrace: bool
}

fn handle_comm_event( event: CommEvent, writer: &ExecutionQueue< PacketWriter > ) {
    let packet = Packet::ThreadName {
        pid: event.pid,
        tid: event.tid,
        name: Cow::Borrowed( &event.name )
    };

    let framed = FramedPacket::Known( packet );
    let bytes = framed.write_to_vec( Endianness::LittleEndian ).unwrap();
    writer.spawn( move |fp| {
        fp.write_all( &bytes )
    });
}

fn handle_mmap2_event( event: Mmap2Event, new_maps: &mut Vec< Region > ) -> bool {
    let name = if event.filename == b"//anon" {
        "".to_owned()
    } else {
        String::from_utf8( event.filename ).expect( "mmaped page's name contains invalid UTF-8" )
    };

    let region = Region {
        start: event.address,
        end: event.address + event.length,
        file_offset: event.page_offset,
        major: event.major,
        minor: event.minor,
        inode: event.inode,
        name,
        is_shared: (event.flags & libc::MAP_SHARED as u32) != 0,
        is_read: (event.protection & libc::PROT_READ as u32) != 0,
        is_write: (event.protection & libc::PROT_WRITE as u32) != 0,
        is_executable: (event.protection & libc::PROT_EXEC as u32) != 0
    };

    if region.name.is_empty() || region.is_shared {
        false
    } else {
        new_maps.push( region );
        true
    }
}

pub fn main( args: Args ) -> Result< (), Box< Error > > {
    let sample_count_limit = args.sample_count_limit;
    let time_limit = args.time_limit;
    let discard_all = args.discard_all;
    let offline = args.offline;

    let sigint = SigintHandler::new();
    let (pid, mut maps, mut perf, mut address_space, writer) = initialize( &sigint, args )?;

    info!( "Enabling perf events..." );
    perf.enable();

    info!( "Running..." );
    let mut counter = 0;
    let profiling_started_ts = Instant::now();

    let mut new_maps = Vec::new();
    let mut address_space_needs_reload = false;
    let mut wait = false;
    let mut pending_lost_events = 0;
    let mut total_lost_events = 0;
    let mut dwarf_regs = DwarfRegs::new();
    loop {
        if sigint.was_triggered() || perf.is_empty() {
            break;
        }

        if let Some( limit ) = sample_count_limit {
            if counter >= limit {
                break;
            }
        }

        if let Some( time_limit ) = time_limit {
            if profiling_started_ts.elapsed().as_secs() >= time_limit {
                info!( "Time limit exceeded; stopping!" );
                break;
            }
        }

        if wait {
            wait = false;
            perf.wait();
        }

        let iter = perf.iter();
        if iter.len() == 0 {
            wait = true;
            continue;
        }

        for event_ref in iter {
            let raw_event = event_ref.get();
            if sigint.was_triggered() {
                break;
            }

            if let Some( limit ) = sample_count_limit {
                if counter >= limit {
                    break;
                }
            }

            let event = raw_event.parse();
            debug!( "Recording event: {:#?}", event );

            if discard_all {
                match event {
                    Event::Sample( _ ) => counter += 1,
                    _ => {}
                }

                continue;
            }

            match event {
                Event::Mmap2( event ) => {
                    if event.pid != pid {
                        continue;
                    }

                    if handle_mmap2_event( event, &mut new_maps ) {
                        address_space_needs_reload = true;
                    }
                    continue;
                },
                Event::Comm( event ) => {
                    handle_comm_event( event, &writer );
                    continue;
                },
                Event::Lost( event ) => {
                    pending_lost_events += event.count;
                    total_lost_events += event.count;
                    continue;
                },
                _ => {}
            }

            if address_space_needs_reload {
                address_space_needs_reload = false;
                update_maps( &mut maps, &mut new_maps );
                process_maps( &maps, offline, pid, &mut address_space, &writer );
                new_maps.clear();
            }

            if pending_lost_events > 0 {
                writer.spawn( move |fp| {
                    fp.write_packet( Packet::Lost {
                        count: pending_lost_events
                    })
                });
                pending_lost_events = 0;
            }

            match event {
                Event::Sample( event ) => {
                    counter += 1;
                    let mut user_backtrace = Vec::new();
                    event.regs.copy_to_dwarf_regs( &mut dwarf_regs );

                    let packet;
                    if offline {
                        packet = Packet::RawSample {
                            timestamp: event.timestamp,
                            pid: event.pid,
                            tid: event.tid,
                            cpu: event.cpu,
                            kernel_backtrace: Cow::Borrowed( &event.callchain ),
                            stack: event.stack.into(),
                            regs: Cow::Owned( dwarf_regs.iter().map( |(register, value)| DwarfReg { register, value } ).collect() )
                        };
                    } else {
                        let reader = StackReader { stack: event.stack };
                        address_space.unwind( &mut dwarf_regs, &reader, &mut user_backtrace );

                        packet = Packet::Sample {
                            timestamp: event.timestamp,
                            pid: event.pid,
                            tid: event.tid,
                            cpu: event.cpu,
                            kernel_backtrace: Cow::Borrowed( &event.callchain ),
                            user_backtrace: Cow::Borrowed( &user_backtrace )
                        };
                    }

                    let framed = FramedPacket::Known( packet );
                    let bytes = framed.write_to_vec( Endianness::LittleEndian ).unwrap();
                    writer.spawn( move |fp| {
                        fp.write_all( &bytes )
                    });
                },
                _ => {}
            }
        }
    }

    if total_lost_events > 0 {
        warn!( "Lost {} events!", total_lost_events );
    }

    info!( "Collected {} samples in total!", counter );
    Ok(())
}
