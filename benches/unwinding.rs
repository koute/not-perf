#[macro_use]
extern crate criterion;

extern crate nperf;
extern crate nwind;
extern crate proc_maps;

use std::fs;
use std::collections::HashMap;
use std::sync::Arc;
use std::path::Path;

use criterion::{Criterion, Bencher};

use nperf::{Packet, ArchiveReader, StackReader};
use nwind::arch::{self, Registers};
use nwind::{AddressSpace, IAddressSpace, BinaryData, DwarfRegs, RangeMap};
use proc_maps::Region;

fn benchmark_unwind( b: &mut Bencher, filename: &str ) {
    let path = Path::new( env!( "CARGO_MANIFEST_DIR" ) ).join( "test-data" ).join( "artifacts" ).join( filename );
    let fp = fs::File::open( path ).unwrap();
    let mut reader = ArchiveReader::new( fp ).validate_header().unwrap().skip_unknown();
    let mut address_space = AddressSpace::< arch::amd64::Arch >::new();
    let mut binary_source_map = HashMap::new();
    let mut memory_regions = RangeMap::new();
    let mut samples = Vec::new();

    while let Some( packet ) = reader.next() {
        let packet = packet.unwrap();
        match packet {
            Packet::RawSample { stack, regs, .. } => {
                samples.push( (stack, regs) );
            },
            Packet::BinaryBlob { inode, path, data } => {
                let path = String::from_utf8_lossy( &path );
                let mut data = BinaryData::load_from_owned_bytes( &path, data.into_owned() ).unwrap();
                if !inode.is_invalid() {
                    data.set_inode( inode );
                }
                binary_source_map.insert( path.into_owned(), Arc::new( data ) );
            },
            Packet::MemoryRegionMap { range, is_read, is_write, is_executable, is_shared, file_offset, inode, major, minor, name, .. } => {
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

                memory_regions.push( range.clone(), region ).unwrap();
            },
            Packet::MemoryRegionUnmap { range, .. } => {
                memory_regions.remove_by_exact_range( range.clone() ).unwrap();
            },
            _ => {}
        }
    }

    let regions = memory_regions.values().cloned().collect();
    address_space.reload( regions, &mut |region, handle| {
        if let Some( binary_data ) = binary_source_map.get( &region.name ) {
            handle.set_binary( binary_data.clone() );
        }
    });

    let mut user_backtrace = Vec::new();
    let mut dwarf_regs = DwarfRegs::new();

    b.iter( move || {
        for &(ref stack, ref regs) in samples.iter() {
            dwarf_regs.clear();
            for reg in regs.iter() {
                dwarf_regs.append( reg.register, reg.value );
            }

            let mut stack = &stack.as_slice()[..];
            let reader = StackReader { stack: stack.into() };

            address_space.unwind( &mut dwarf_regs, &reader, &mut user_backtrace );
            user_backtrace.clear();
        }
    });
}

fn criterion_benchmark( c: &mut Criterion ) {
    c.bench_function( "unwind_amd64_no_fp", |b| benchmark_unwind( b, "amd64-usleep_in_a_loop_no_fp.nperf" ) );
    c.bench_function( "unwind_amd64_fp", |b| benchmark_unwind( b, "amd64-usleep_in_a_loop_fp.nperf" ) );
}

criterion_group!( benches, criterion_benchmark );
criterion_main!( benches );
