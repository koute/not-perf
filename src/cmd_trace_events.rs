use std::error::Error;
use std::io::{self, Write};
use std::fs::File;
use std::collections::{HashMap, HashSet};
use std::cmp::{max, min};

use crate::args;
use crate::interner::StringInterner;
use crate::cmd_collate::{FrameKind, CollapseOpts, collate, decode, repack_cli_args, write_frame};

#[derive(PartialEq, Debug)]
struct TraceEvent< T > {
    frame: T,
    timestamp: u64,
    is_end: bool
}

fn emit_events< T >( raw_events: Vec< (u64, Vec< T >) >, period: Option< u64 > ) -> Vec< TraceEvent< T > > where T: PartialEq + Clone {
    let mut events = Vec::with_capacity( raw_events.len() * 2 );
    let mut current_frames: Vec< T > = Vec::new();
    let mut last_timestamp = raw_events.first().map( |&(timestamp, _)| timestamp ).unwrap_or( 0 );
    for (timestamp, frames) in raw_events {
        let (is_timeout, period) = period.map( |period| ((timestamp - last_timestamp) > period, period) ).unwrap_or( (false, 0) );
        let common_length =
            if is_timeout {
                0
            } else {
                current_frames.iter().zip( frames.iter().rev() ).take_while( |(lhs, rhs)| lhs == rhs ).count()
            };

        let stale_length = current_frames.len() - common_length;
        for _ in 0..stale_length {
            let frame = current_frames.pop().unwrap();

            events.push( TraceEvent {
                frame,
                timestamp: if is_timeout { last_timestamp + period } else { timestamp },
                is_end: true
            });
        }

        for frame in frames.into_iter().rev().skip( common_length ) {
            events.push( TraceEvent {
                frame: frame.clone(),
                timestamp,
                is_end: false
            });

            current_frames.push( frame );
        }

        last_timestamp = timestamp;
    }

    for frame in current_frames.into_iter().rev() {
        events.push( TraceEvent {
            frame,
            timestamp: if let Some( period ) = period { last_timestamp + period } else { last_timestamp },
            is_end: true
       });
    }

    events
}

#[cfg(test)]
fn ev_s< T >( timestamp: u64, frame: T ) -> TraceEvent< T > {
    TraceEvent {
        frame,
        timestamp,
        is_end: false
    }
}

#[cfg(test)]
fn ev_e< T >( timestamp: u64, frame: T ) -> TraceEvent< T > {
    TraceEvent {
        frame,
        timestamp,
        is_end: true
    }
}

#[cfg(test)]
fn assert_emit_events( period: Option< u64 >, raw_events: &[(u64, Vec< char >)], expected: Vec< TraceEvent< char > > ) {
    let actual = emit_events( raw_events.iter().cloned().collect(), period );
    if actual == expected {
        return;
    }

    eprintln!( "Expected:" );
    for event in expected {
        eprintln!( "{} {} {}", if event.is_end { ' ' } else { '>' }, event.frame, event.timestamp );
    }

    eprintln!( "Actual:" );
    for event in actual {
        eprintln!( "{} {} {}", if event.is_end { ' ' } else { '>' }, event.frame, event.timestamp );
    }

    panic!();
}

#[test]
fn test_emit_events_1() {
    assert_emit_events(
        None,
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (1, vec![      'B', 'A' ])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 1, 'C' ),
            ev_e( 1, 'B' ),
            ev_e( 1, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_2() {
    assert_emit_events(
        None,
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (1, vec![      'B', 'A' ]),
            (2, vec![]),
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 1, 'C' ),
            ev_e( 2, 'B' ),
            ev_e( 2, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_3() {
    assert_emit_events(
        None,
        &[
            (0, vec![      'B', 'A' ]),
            (1, vec![ 'C', 'B', 'A' ]),
            (2, vec![])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 1, 'C' ),
            ev_e( 2, 'C' ),
            ev_e( 2, 'B' ),
            ev_e( 2, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_4() {
    assert_emit_events(
        None,
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (1, vec![ 'D', 'B', 'A' ]),
            (2, vec![])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 1, 'C' ),
            ev_s( 1, 'D' ),
            ev_e( 2, 'D' ),
            ev_e( 2, 'B' ),
            ev_e( 2, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_5() {
    assert_emit_events(
        None,
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (1, vec![      'D', 'A' ]),
            (2, vec![])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 1, 'C' ),
            ev_e( 1, 'B' ),
            ev_s( 1, 'D' ),
            ev_e( 2, 'D' ),
            ev_e( 2, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_6() {
    assert_emit_events(
        Some( 1 ),
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (1, vec![ 'C', 'B', 'A' ]),
            (2, vec![])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 2, 'C' ),
            ev_e( 2, 'B' ),
            ev_e( 2, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_7() {
    assert_emit_events(
        Some( 1 ),
        &[
            (0, vec![ 'C', 'B', 'A' ]),
            (2, vec![ 'C', 'B', 'A' ]),
            (3, vec![])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 1, 'C' ),
            ev_e( 1, 'B' ),
            ev_e( 1, 'A' ),

            ev_s( 2, 'A' ),
            ev_s( 2, 'B' ),
            ev_s( 2, 'C' ),
            ev_e( 3, 'C' ),
            ev_e( 3, 'B' ),
            ev_e( 3, 'A' )
        ]
    );
}

#[test]
fn test_emit_events_8() {
    assert_emit_events(
        Some( 5 ),
        &[
            (0, vec![ 'C', 'B', 'A' ])
        ],
        vec![
            ev_s( 0, 'A' ),
            ev_s( 0, 'B' ),
            ev_s( 0, 'C' ),
            ev_e( 5, 'C' ),
            ev_e( 5, 'B' ),
            ev_e( 5, 'A' )
        ]
    );
}

pub fn main( args: args::TraceEventsArgs ) -> Result< (), Box< dyn Error > > {
    let (omit_regex, collate_args) = repack_cli_args( &args.collation_args );
    let opts = CollapseOpts {
        merge_threads: false,
        granularity: args.arg_granularity.granularity
    };
    let mut period = args.period;

    let mut raw_events_for_thread = HashMap::new();
    let mut interner = StringInterner::new();
    let collation = collate( collate_args, |collation, timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
        let frames = decode(
            &omit_regex,
            &collation,
            process,
            tid,
            &user_backtrace,
            &kernel_backtrace,
            &opts,
            &mut interner
        );
        if let Some( frames ) = frames {
            raw_events_for_thread.entry( (process.pid(), tid) ).or_insert_with( Vec::new ).push( (timestamp, frames) );
        }
    })?;

    if period.is_none() {
        if let Some( frequency ) = collation.frequency() {
            let profiling_period = (1.0 / frequency as f64) * 1000_000_000.0;
            let overhead =
                max(
                    min(
                        ((frequency as f64).log10() * 10_000.0) as u64,
                        40_000
                    ),
                    min(
                        (profiling_period * 0.01) as u64,
                        100_000
                    )
                );
            period = Some( profiling_period as u64 + overhead );
            info!( "Profiling data frequency: {}", frequency );
            info!( "Trace period for frame collapsing: {}us", period.unwrap() / 1000 );
        }
    }

    let mut wrote_pid = HashSet::new();
    let mut wrote_tid = HashSet::new();
    let mut wrote_header = false;
    let mut last_pid = 0;

    let mut stream = io::BufWriter::new( File::create( args.output )? );
    write!( stream, "[" )?;
    for ((pid, tid), mut raw_events) in raw_events_for_thread {
        raw_events.sort_by_key( |(timestamp, _)| *timestamp );
        let events = emit_events( raw_events, period.clone() );
        for event in events {

            match event.frame {
                FrameKind::Process( pid ) => {
                    last_pid = pid;

                    if !wrote_header {
                        if args.absolute_time {
                            writeln!(
                                stream,
                                r#"{{"name": "<start>", "ph": "X", "ts": 1, "pid": {}, "tid": {}}},"#,
                                pid,
                                pid
                            )?;
                        }

                        writeln!(
                            stream,
                            r#"{{"pid":{},"tid":{},"ts":0,"ph":"M","cat":"__metadata","name":"IsTimeTicksHighResolution","args":{{"value":true}}}}"#,
                            pid,
                            pid
                        )?;
                        writeln!(
                            stream,
                            r#",{{"pid":{},"tid":{},"ts":0,"ph":"M","cat":"__metadata","name":"num_cpus","args":{{"number":{}}}}}"#,
                            pid,
                            pid,
                            collation.cpu_count()
                        )?;
                        wrote_header = true;
                    }

                    if !wrote_pid.contains( &pid ) {
                        if let Some( process ) = collation.get_process( pid ) {
                            let name = serde_json::to_string( process.executable() ).map_err( |error| io::Error::new( io::ErrorKind::Other, error ) )?;
                            writeln!(
                                stream,
                                r#",{{"pid":{},"tid":{},"ts":0,"ph":"M","cat":"__metadata","name":"process_name","args":{{"name":{}}}}}"#,
                                pid,
                                pid,
                                name
                            )?;
                            wrote_pid.insert( pid );
                        }
                    }
                    continue;
                },
                FrameKind::Thread( tid ) => {
                    if !wrote_tid.contains( &tid ) {
                        if let Some( name ) = collation.get_thread_name( tid ) {
                            let name = serde_json::to_string( &name ).map_err( |error| io::Error::new( io::ErrorKind::Other, error ) )?;
                            writeln!(
                                stream,
                                r#",{{"pid":{},"tid":{},"ts":0,"ph":"M","cat":"__metadata","name":"thread_name","args":{{"name":{}}}}}"#,
                                last_pid,
                                tid,
                                name
                            )?;
                            wrote_tid.insert( tid );
                        }
                    }
                    continue;
                },
                FrameKind::MainThread => {
                    if !wrote_tid.contains( &last_pid ) {
                        if let Some( name ) = collation.get_thread_name( last_pid ).or_else( || collation.get_process( last_pid ).map( |process| process.executable() ) ) {
                            let name = serde_json::to_string( &name ).map_err( |error| io::Error::new( io::ErrorKind::Other, error ) )?;
                            writeln!(
                                stream,
                                r#",{{"pid":{},"tid":{},"ts":0,"ph":"M","cat":"__metadata","name":"thread_name","args":{{"name":{}}}}}"#,
                                last_pid,
                                last_pid,
                                name
                            )?;
                            wrote_tid.insert( last_pid );
                        }
                    }
                    continue;
                },
                _ => {}
            }

            write!( stream, ",{{" )?;
            write!( stream, "\"name\": " )?;
            let mut name = String::new();
            write_frame( &collation, &interner, &mut name, &event.frame );
            serde_json::to_writer( &mut stream, &name ).map_err( |error| io::Error::new( io::ErrorKind::Other, error ) )?;
            write!( stream, ",\"ph\": \"{}\"", if event.is_end { "E" } else { "B" } )?;
            write!( stream, ",\"ts\": {}", event.timestamp as f64 / 1000.0 )?;
            write!( stream, ",\"pid\": {}", pid )?;
            write!( stream, ",\"tid\": {}", tid )?;
            write!( stream, "}}\n" )?;
        }
    }
    write!( stream, "]" )?;

    Ok(())
}
