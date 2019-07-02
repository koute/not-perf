use std::collections::HashSet;
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

use proc_maps::{self, Region};
use nwind::arch::{self, Architecture, Registers};
use nwind::{
    IAddressSpace,
    AddressSpace,
    BinaryData,
    DwarfRegs,
    RangeMap,
    BinaryId
};

use crate::args::{self, TargetProcess};
use crate::utils::{SigintHandler, read_string_lossy, get_major, get_minor, get_ms};
use crate::archive::{FramedPacket, Packet, Inode, Bitness, DwarfReg, ARCHIVE_MAGIC, ARCHIVE_VERSION};
use crate::execution_queue::ExecutionQueue;
use crate::ps::{wait_for_process, find_process};
use crate::stack_reader::StackReader;
use crate::mount_info::PathResolver;
use crate::raw_data::CowRawData;

fn get_vdso() -> Option< &'static [u8] > {
    let maps_str = read_string_lossy( "/proc/self/maps" ).expect( "cannot read /proc/self/maps" );
    let maps = proc_maps::parse( &maps_str );
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

    use nwind::{arch, RangeMap, IAddressSpace, AddressSpace, Inode, BinaryData};
    use proc_maps::Region;

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

        let inode = Inode { inode: 1, dev_major: 0, dev_minor: 0 };

        for ranges in all_ranges {
            for region in ranges {
                new_maps.push( region );
            }

            update_maps( &mut maps, &mut new_maps );
            let res = address_space.reload( maps.values().cloned().collect(), &mut |region, handle| {
                handle.should_load_frame_descriptions( false );
                handle.should_load_symbols( false );

                if region.name != "file_1" {
                    return;
                }

                let mut data = BinaryData::load_from_static_slice( &region.name, &include_bytes!( "../test-data/bin/amd64-usleep_in_a_loop_no_fp" )[..] ).unwrap();
                data.set_inode( inode );

                handle.set_binary( data.into() );
            });

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
        #[cfg(feature = "env_logger")]
        let _ = env_logger::try_init();
        test_reload_with_regions( vec![
            vec![region( 0, 80, 0x1000, "file_1" )],
            vec![]
        ]);
    }

    #[test]
    fn reload_which_clears_base_address_does_not_panic() {
        #[cfg(feature = "env_logger")]
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
            #[cfg(feature = "env_logger")]
            let _ = env_logger::try_init();

            let all_regions = all_regions.into_iter().map( |regions| regions.into_iter().map( |entry| {
                region( entry.0, entry.1, entry.2, entry.3 )
            }).collect() ).collect();

            test_reload_with_regions( all_regions );
            true
        }
    }
}

fn resolve_path< 'a >( path_resolver: &Option< PathResolver >, path: &'a dyn AsRef< Path >, expected_major_minor: Option< (u32, u32) > ) -> Cow< 'a, Path > {
    let path = path.as_ref();
    trace!( "Trying to resolve {:?}...", path );

    if path.exists() {
        if let Some( (expected_major, expected_minor) ) = expected_major_minor {
            if let Ok( metadata ) = fs::metadata( &path ) {
                let dev = metadata.dev();
                let dev_major = get_major( dev );
                let dev_minor = get_minor( dev );
                if expected_major == dev_major && expected_minor == dev_minor {
                    return path.into();
                }

                trace!( "Path {:?} exists, however it doesn't match the major/minor!", path );
            }
        } else {
            return path.into();
        }
    }

    trace!( "Path {:?} doesn't exist, trying to resolve...", path );

    if let &Some( ref resolver ) = path_resolver {
        if let Some( iter ) = resolver.resolve( path ) {
            for candidate in iter {
                trace!( "Candidate: {:?}", candidate );
                if candidate.exists() {
                    debug!( "Resolved {:?} into {:?}", path, candidate );
                    return candidate.into();
                }
            }
        }
    }

    trace!( "Path {:?} was not resolved successfully!", path );
    return path.into();
}

fn process_maps(
    maps: &RangeMap< Region >,
    offline: bool,
    pid: u32,
    path_resolver: &Option< PathResolver >,
    address_space: &mut AddressSpace< arch::native::Arch >,
    writer: &ExecutionQueue< PacketWriter >
) {
    debug!( "Processing maps..." );

    let reloaded = {
        let mut regions = Vec::new();
        for region in maps.values() {
            trace!( "Map: 0x{:016X}-0x{:016X} '{}'", region.start, region.end, region.name );
            regions.push( region.clone() );
        }

        address_space.reload( regions, &mut move |region, handle| {
            handle.should_load_frame_descriptions( !offline );
            handle.should_load_symbols( !offline );

            if region.name == "[vdso]" {
                if let Some( vdso ) = get_vdso() {
                    let data = match BinaryData::load_from_static_slice( &region.name, vdso ) {
                        Ok( data ) => data,
                        Err( _ ) => return
                    };

                    handle.set_binary( data.into() );
                    return;
                }
                return;
            }

            let path = resolve_path( path_resolver, &region.name, Some( (region.major, region.minor) ) );
            let data = match BinaryData::load_from_fs( &path ) {
                Ok( data ) => data,
                Err( error ) => {
                    error!( "Failed to load '{}' from {:?}: {}", region.name, path, error );
                    return;
                }
            };

            if let Err( error ) = data.check_inode( Inode { inode: region.inode, dev_major: region.major, dev_minor: region.minor } ) {
                error!( "{}", error );
                return;
            }

            handle.set_binary( data.into() );
        })
    };

    writer.spawn( move |fp| {
        debug!( "Writing binaries and maps..." );
        for (inode, name) in reloaded.binaries_unmapped {
            debug!( "Binary unmapped: PID={}, ID={:?}, name={}", pid, inode, name );
            fp.write_binary_unloaded( pid, inode, &name )?;
        }

        for range in reloaded.regions_unmapped {
            fp.write_region_unmap( pid, range )?;
        }

        for (inode, name, binary) in reloaded.binaries_mapped {
            debug!( "Binary mapped: PID={}, ID={:?}, name={}", pid, inode, name );
            let binary = binary.unwrap();
            fp.write_binary( &binary )?;
            fp.write_binary_loaded( pid, inode, &name )?;
        }

        for region in reloaded.regions_mapped {
            fp.write_region_map( pid, &region )?;
        }

        Ok(())
    });
}

pub struct PacketWriter {
    offline: bool,
    fp: BufWriter< File >,
    binaries_written: HashSet< BinaryId >
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

    fn write_region_map( &mut self, pid: u32, region: &proc_maps::Region ) -> io::Result< () > {
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

    fn write_binary_loaded( &mut self, pid: u32, inode: Option< Inode >, name: &str ) -> io::Result< () > {
        self.write_packet( Packet::BinaryLoaded {
            pid,
            inode,
            name: name.as_bytes().into()
        })
    }

    fn write_binary_unloaded( &mut self, pid: u32, inode: Option< Inode >, name: &str ) -> io::Result< () > {
        self.write_packet( Packet::BinaryUnloaded {
            pid,
            inode,
            name: name.as_bytes().into()
        })
    }

    fn write_binary( &mut self, binary: &BinaryData ) -> io::Result< () > {
        let (inode, binary_id) = if let Some( inode ) = binary.inode() {
            (inode, BinaryId::ByInode( inode ))
        } else {
            (Inode::empty(), BinaryId::ByName( binary.name().to_owned() ))
        };

        if self.binaries_written.contains( &binary_id ) {
            return Ok(());
        }

        self.binaries_written.insert( binary_id );

        let debuglink = if let Some( range ) = binary.gnu_debuglink_range() {
            &binary.as_bytes()[ range.start as usize..range.end as usize ]
        } else {
            &b""[..]
        };

        self.write_packet( Packet::BinaryInfo {
            inode,
            path: binary.name().as_bytes().into(),
            is_shared_object: binary.is_shared_object(),
            debuglink: debuglink.into(),
            symbol_table_count: binary.symbol_tables().len() as u16,
            load_headers: binary.load_headers().into()
        })?;

        if let Some( build_id ) = binary.build_id() {
            self.write_packet( Packet::BuildId {
                inode,
                build_id: build_id.to_owned(),
                path: binary.name().as_bytes().into()
            })?;
        }

        if self.offline {
            debug!( "Writing binary '{}'...", binary.name() );
            self.write_packet( Packet::BinaryBlob {
                inode,
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
                        inode,
                        path: binary.name().as_bytes().into(),
                        offset: symbol_table.strtab_range.start,
                        data: binary.as_bytes()[ strtab_range ].into()
                    })?;
                }

                self.write_packet( Packet::SymbolTable {
                    inode,
                    path: binary.name().as_bytes().into(),
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
    args: &args::GenericProfilerArgs
) -> Result< (u32, AddressSpace< arch::native::Arch >, ExecutionQueue< PacketWriter >, Option< PathResolver >), Box< dyn Error > >
{
    let offline = args.offline;
    let target_process = args.process_filter.clone().into();
    let pid = match target_process {
        TargetProcess::ByPid( pid ) => pid,
        TargetProcess::ByName( name ) => {
            if let Some( pid ) = find_process( &name ).unwrap() {
                pid
            } else {
                return Err( format!( "no process named '{}' was found", name ).into() );
            }
        },
        TargetProcess::ByNameWaiting( name, wait_timeout ) => {
            if let Some( pid ) = wait_for_process( sigint_handler, &name, wait_timeout ).unwrap() {
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

    let path_resolver = match PathResolver::new_for_pid( pid ) {
        Ok( value ) => Some( value ),
        Err( error ) => {
            warn!( "Failed to process the mounts: {}", error );
            warn!( "Support for profiling processes with a different mount point namespace will be broken!" );

            None
        }
    };

    let executable = fs::read_link( format!( "/proc/{}/exe", pid ) ).map_err( |err| format!( "cannot read /proc/{}/exe: {}", pid, err ) )?;
    let executable = resolve_path( &path_resolver, &executable, None ).into_owned();

    let exec_metadata = fs::metadata( &executable ).map_err( |err| format!( "cannot read the metadata of /proc/{}/exe: {}", pid, err ) )?;
    let exec_ident = Inode {
        inode: exec_metadata.ino(),
        dev_major: get_major( exec_metadata.dev() ),
        dev_minor: get_minor( exec_metadata.dev() )
    };

    let output_path = if let Some( ref output_path ) = args.output {
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
            executable: executable.as_os_str().as_bytes().into(),
            binary_id: exec_ident
        })?;

        Ok(())
    });

    let mut address_space = AddressSpace::< arch::native::Arch >::new();
    address_space.set_panic_on_partial_backtrace( args.panic_on_partial_backtrace );

    writer.spawn( move |_| {
        info!( "Ready to write profiling data!" );
        Ok(())
    });

    let elapsed = start_timestamp.elapsed();
    debug!( "Initial initialization done; took {}ms", get_ms( elapsed ) );

    Ok( (pid, address_space, writer, path_resolver) )
}

pub struct ProfilingController {
    pid: u32,
    sigint: SigintHandler,
    address_space: AddressSpace< arch::native::Arch >,
    writer: ExecutionQueue< PacketWriter >,
    path_resolver: Option< PathResolver >,
    offline: bool,
    sample_count_limit: Option< u64 >,
    time_limit: Option< u64 >,
    sample_counter: u64,
    profiling_started_ts: Instant,
    maps: RangeMap< Region >
}

pub struct Sample< 'a > {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub kernel_backtrace: Cow< 'a, [u64] >,
    pub stack: CowRawData< 'a >
}

impl ProfilingController {
    pub fn new( args: &args::GenericProfilerArgs ) -> Result< Self, Box< dyn Error > > {
        let sigint = SigintHandler::new();
        let (pid, address_space, writer, path_resolver) = initialize( &sigint, args )?;

        Ok( ProfilingController {
            sigint,
            pid,
            address_space,
            writer,
            path_resolver,
            offline: args.offline,
            sample_count_limit: args.sample_count,
            time_limit: args.time_limit,
            sample_counter: 0,
            profiling_started_ts: Instant::now(),
            maps: RangeMap::new()
        })
    }

    pub fn pid( &self ) -> u32 {
        self.pid
    }

    pub fn write_packet( &mut self, packet: Packet< 'static > ) {
        self.writer.spawn( move |fp| {
            fp.write_packet( packet )
        })
    }

    pub fn write_borrowed_packet( &self, packet: Packet ) {
        let framed = FramedPacket::Known( packet );
        let bytes = framed.write_to_vec( Endianness::LittleEndian ).unwrap();
        self.writer.spawn( move |fp| {
            fp.write_all( &bytes )
        });
    }

    pub fn update_maps( &mut self, new_maps: &mut Vec< Region > ) {
        if new_maps.is_empty() {
            return;
        }

        update_maps( &mut self.maps, new_maps );
        process_maps( &self.maps, self.offline, self.pid, &self.path_resolver, &mut self.address_space, &self.writer );
        new_maps.clear();
    }

    pub fn should_stop( &self ) -> bool {
        if self.sigint.was_triggered() {
            return true;
        }

        if let Some( limit ) = self.sample_count_limit {
            if self.sample_counter >= limit {
                return true;
            }
        }

        if let Some( time_limit ) = self.time_limit {
            if self.profiling_started_ts.elapsed().as_secs() >= time_limit {
                info!( "Time limit exceeded; stopping!" );
                return true;
            }
        }

        false
    }

    pub fn skip_sample( &mut self ) {
        self.sample_counter += 1;
    }

    pub fn generate_sample( &mut self, dwarf_regs: &mut DwarfRegs, event: Sample ) {
        self.sample_counter += 1;

        let mut user_backtrace = Vec::new();
        let packet;
        if self.offline {
            packet = Packet::RawSample {
                timestamp: event.timestamp,
                pid: event.pid,
                tid: event.tid,
                cpu: event.cpu,
                kernel_backtrace: event.kernel_backtrace,
                stack: event.stack,
                regs: Cow::Owned( dwarf_regs.iter().map( |(register, value)| DwarfReg { register, value } ).collect() )
            };
        } else {

            let stack = (&event.stack).into();
            let reader = StackReader { stack };
            self.address_space.unwind( dwarf_regs, &reader, &mut user_backtrace );

            packet = Packet::Sample {
                timestamp: event.timestamp,
                pid: event.pid,
                tid: event.tid,
                cpu: event.cpu,
                kernel_backtrace: event.kernel_backtrace,
                user_backtrace: Cow::Borrowed( &user_backtrace )
            };
        }

        let framed = FramedPacket::Known( packet );
        let bytes = framed.write_to_vec( Endianness::LittleEndian ).unwrap();
        self.writer.spawn( move |fp| {
            fp.write_all( &bytes )
        });

        dwarf_regs.clear();
    }
}

impl Drop for ProfilingController {
    fn drop( &mut self ) {
        info!( "Collected {} samples in total!", self.sample_counter );
    }
}
