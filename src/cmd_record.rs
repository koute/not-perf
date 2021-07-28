use std::borrow::Cow;
use std::error::Error;

use libc;

use proc_maps::Region;
use nwind::arch::Registers;
use nwind::DwarfRegs;

use crate::args;
use perf_event_open::{Event, EventSource, CommEvent, Mmap2Event};
use crate::perf_group::PerfGroup;
use crate::perf_arch;
use crate::archive::{ContextSwitchKind, Packet};
use crate::profiler::{ProfilingController, Sample};

fn handle_comm_event( event: CommEvent, controller: &ProfilingController ) {
    let packet = Packet::ThreadName {
        pid: event.pid,
        tid: event.tid,
        name: Cow::Borrowed( &event.name )
    };

    controller.write_borrowed_packet( packet );
}

fn handle_mmap2_event( event: Mmap2Event, new_maps: &mut Vec< Region > ) {
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

    if !region.name.is_empty() && !region.is_shared {
        new_maps.push( region );
    }
}

pub fn main( args: args::RecordArgs ) -> Result< (), Box< dyn Error > > {
    let discard_all = args.discard_all;

    let mut controller = ProfilingController::new( &args.profiler_args )?;
    controller.write_packet( Packet::ProfilingFrequency {
        frequency: args.frequency
    });

    info!( "Opening perf events for process with PID {}...", controller.pid() );
    let mut perf = PerfGroup::open( controller.pid(), args.frequency, args.stack_size, args.event_source.unwrap_or( EventSource::HwCpuCycles ) );
    if perf.is_err() && args.event_source.is_none() {
        perf = PerfGroup::open( controller.pid(), args.frequency, args.stack_size, args.event_source.unwrap_or( EventSource::SwCpuClock ) );
    }

    let mut perf = match perf {
        Ok( perf ) => perf,
        Err( error ) => {
            error!( "Failed to start profiling: {}", error );
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                if let Ok( perf_event_paranoid ) = crate::utils::read_string_lossy( "/proc/sys/kernel/perf_event_paranoid" ) {
                    let perf_event_paranoid = perf_event_paranoid.trim();
                    match perf_event_paranoid {
                        "2" => {
                            warn!( "The '/proc/sys/kernel/perf_event_paranoid' is set to '{}', which is probably why you can't start the profiling", perf_event_paranoid );
                            warn!( "You can try lowering it before trying to start the profiling again:" );
                            warn!( "    echo '1' | sudo tee /proc/sys/kernel/perf_event_paranoid" );
                        },
                        _ => {}
                    }
                }
            }

            let _ = std::fs::remove_file( controller.output_path() );
            return Err( format!( "failed to start profiling: {}", error ).into() );
        }
    };

    let mut new_maps = Vec::new();
    for event in perf.take_initial_events() {
        match event {
            Event::Mmap2( event ) => handle_mmap2_event( event, &mut new_maps ),
            Event::Comm( event ) => handle_comm_event( event, &controller ),
            _ => unreachable!()
        }
    }

    controller.update_maps( &mut new_maps );

    info!( "Enabling perf events..." );
    perf.enable();

    info!( "Running..." );

    let mut wait = false;
    let mut pending_lost_events = 0;
    let mut total_lost_events = 0;
    let mut dwarf_regs = DwarfRegs::new();
    loop {
        if perf.is_empty() || controller.should_stop() {
            break;
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
            if controller.should_stop() {
                break;
            }

            let event = event_ref.get();
            debug!( "Recording event: {:#?}", event );

            if discard_all {
                match event {
                    Event::Sample( _ ) => controller.skip_sample(),
                    _ => {}
                }

                continue;
            }

            match event {
                Event::Mmap2( event ) => {
                    if event.pid != controller.pid() {
                        continue;
                    }

                    handle_mmap2_event( event, &mut new_maps );
                    continue;
                },
                Event::Comm( event ) => {
                    handle_comm_event( event, &controller );
                    continue;
                },
                Event::Lost( event ) => {
                    pending_lost_events += event.count;
                    total_lost_events += event.count;
                    continue;
                },
                _ => {}
            }

            controller.update_maps( &mut new_maps );

            if pending_lost_events > 0 {
                controller.write_packet( Packet::Lost {
                    count: pending_lost_events
                });
                pending_lost_events = 0;
            }

            match event {
                Event::Sample( event ) => {
                    if let Some( regs ) = event.regs {
                        perf_arch::native::into_dwarf_regs( &regs, &mut dwarf_regs );
                    } else {
                        dwarf_regs.clear();
                    }

                    controller.generate_sample( &mut dwarf_regs, Sample {
                        timestamp: event.timestamp,
                        pid: event.pid,
                        tid: event.tid,
                        cpu: event.cpu,
                        kernel_backtrace: Cow::Borrowed( &event.callchain ),
                        stack: event.stack.into()
                    });
                },
                Event::ContextSwitch( kind ) => {
                    let kind = match kind {
                        perf_event_open::ContextSwitchKind::In => ContextSwitchKind::In,
                        perf_event_open::ContextSwitchKind::OutWhileIdle => ContextSwitchKind::OutWhileIdle,
                        perf_event_open::ContextSwitchKind::OutWhileRunning => ContextSwitchKind::OutWhileRunning
                    };

                    controller.write_packet( Packet::ContextSwitch {
                        pid: event_ref.pid(),
                        cpu: event_ref.cpu(),
                        kind
                    });
                },
                _ => {}
            }
        }
    }

    if total_lost_events > 0 {
        warn!( "Lost {} events!", total_lost_events );
    }

    Ok(())
}
