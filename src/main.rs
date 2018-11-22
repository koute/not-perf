extern crate libc;
extern crate regex;
extern crate clap;
extern crate env_logger;
extern crate parking_lot;
extern crate num_cpus;
extern crate chrono;
extern crate speedy;
#[macro_use]
extern crate speedy_derive;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

extern crate nwind;
extern crate proc_maps;
extern crate perf_event_open;

mod utils;

mod raw_data;
mod perf_group;
mod perf_arch;
mod archive;
mod execution_queue;
mod kallsyms;
mod ps;
mod stack_reader;
mod metadata;
mod mount_info;
mod cmd_record;
mod cmd_collate;
mod cmd_metadata;

use std::env;
use std::error::Error;
use std::process::exit;
use clap::{Arg, App, AppSettings, SubCommand};

use cmd_record::TargetProcess;
use cmd_collate::CollateFormat;

fn main_impl() -> Result< (), Box< Error >  > {
    if env::var( "RUST_LOG" ).is_err() {
        env::set_var( "RUST_LOG", "nperf=info" );
    }

    env_logger::init();

    let app = App::new( "nperf" )
        .author( "Jan Bujak <jan.bujak@nokia.com>" )
        .setting( AppSettings::ArgRequiredElseHelp )
        .subcommand(
            SubCommand::with_name( "record" )
                .about( "Records profiling information" )
                .arg(
                    Arg::with_name( "frequency" )
                        .short( "F" )
                        .long( "frequency" )
                        .takes_value( true )
                        .default_value( "900" )
                        .help( "The frequency with which the measurements will be gathered" )
                )
                .arg(
                    Arg::with_name( "event-source" )
                        .short( "s" )
                        .long( "event-source" )
                        .takes_value( true )
                        .possible_values( &[
                            "hw_cpu_cycles",
                            "hw_ref_cpu_cycles",
                            "sw_cpu_clock",
                            "sw_page_faults"
                        ])
                        .default_value( "hw_cpu_cycles" )
                        .help( "The source of perf events" )
                )
                .arg(
                    Arg::with_name( "stack-size" )
                        .long( "stack-size" )
                        .takes_value( true )
                        .default_value( "24576" )
                        .help( "Size of the gathered stack payloads (in bytes)" )
                )
                .arg(
                    Arg::with_name( "output" )
                        .short( "o" )
                        .long( "output" )
                        .takes_value( true )
                        .help( "The file to which the profiling data will be written" )
                )
                .arg(
                    Arg::with_name( "sample-count" )
                        .long( "sample-count" )
                        .takes_value( true )
                        .help( "The number of samples to gather; unlimited by default" )
                )
                .arg(
                    Arg::with_name( "time-limit" )
                        .short( "l" )
                        .long( "time-limit" )
                        .takes_value( true )
                        .help( "Determines for how many seconds the measurements will be gathered" )
                )
                .arg(
                    Arg::with_name( "discard-all" )
                        .long( "discard-all" )
                        .help( "Gather data but do not do anything with it; useful only for testing" )
                )
                .arg(
                    Arg::with_name( "lock-memory" )
                        .long( "lock-memory" )
                        .help( "Prevents anything in the profiler's address space from being swapped out; might increase memory usage significantly" )
                )
                .arg(
                    Arg::with_name( "pid" )
                        .short( "p" )
                        .long( "pid" )
                        .required_unless_one( &[ "process" ] )
                        .takes_value( true )
                        .help( "Profiles a process with a given PID (conflicts with --process)" )
                )
                .arg(
                    Arg::with_name( "process" )
                        .short( "P" )
                        .long( "process" )
                        .required_unless_one( &[ "pid" ] )
                        .takes_value( true )
                        .help( "Profiles a process with a given name (conflicts with --pid)" )
                )
                .arg(
                    Arg::with_name( "wait" )
                        .short( "w" )
                        .long( "wait" )
                        .conflicts_with( "pid" )
                        .help( "Will wait for the profiled process to appear" )
                )
                .arg(
                    Arg::with_name( "offline" )
                        .long( "offline" )
                        .help( "Disable online backtracing" )
                )
                .arg(
                    Arg::with_name( "panic-on-partial-backtrace" )
                        .long( "panic-on-partial-backtrace" )
                        .hidden( true )
                )
        )
        .subcommand(
            SubCommand::with_name( "collate" )
                .about( "Emits collated stack traces for use with Brendan Gregg's flamegraph script" )
                .arg(
                    Arg::with_name( "debug-symbols" )
                        .short( "d" )
                        .long( "debug-symbols" )
                        .multiple( true )
                        .takes_value( true )
                        .help( "A file or directory with extra debugging symbols; can be specified multiple times" )
                )
                .arg(
                    Arg::with_name( "force-stack-size" )
                        .long( "force-stack-size" )
                        .takes_value( true )
                        .hidden( true )
                )
                .arg(
                    Arg::with_name( "omit" )
                        .long( "omit" )
                        .multiple( true )
                        .takes_value( true )
                        .hidden( true )
                )
                .arg(
                    Arg::with_name( "only-sample" )
                        .long( "only-sample" )
                        .takes_value( true )
                        .hidden( true )
                )
                .arg(
                    Arg::with_name( "without-kernel-callstacks" )
                        .long( "without-kernel-callstacks" )
                        .help( "Completely ignores kernel callstacks" )
                )
                .arg(
                    Arg::with_name( "format" )
                        .long( "format" )
                        .takes_value( true )
                        .possible_values( &[
                            "collapsed",
                            "perf-like"
                        ])
                        .default_value( "collapsed" )
                        .help( "Selects the output format" )
                )
                .arg(
                    Arg::with_name( "INPUT" )
                        .required( true )
                        .help( "The input file to use; record it with the `record` subcommand" )
                )
        )
        .subcommand(
            SubCommand::with_name( "metadata" )
                .about( "Outputs rudimentary JSON-formatted metadata" )
                .arg(
                    Arg::with_name( "INPUT" )
                        .required( true )
                        .help( "The input file to use; record it with the `record` subcommand" )
                )
        );

    let matches = app.get_matches();

    if let Some( matches ) = matches.subcommand_matches( "record" ) {
        let pid = matches.value_of( "pid" );
        let process = matches.value_of( "process" );
        let wait = matches.occurrences_of( "wait" ) > 0;

        let target_process = if let Some( process ) = process {
            let process = process.to_owned();
            if wait {
                TargetProcess::ByNameWaiting( process )
            } else {
                TargetProcess::ByName( process )
            }
        } else if let Some( pid ) = pid {
            let pid = pid.parse().map_err( |_| "invalid PID specified in -p/--pid" )?;
            TargetProcess::ByPid( pid )
        } else {
            unreachable!();
        };

        let frequency = matches.value_of( "frequency" ).unwrap().parse().map_err( |_| "invalid frequency specified in -F/--frequency" )?;
        let stack_size = matches.value_of( "stack-size" ).unwrap().parse().map_err( |_| "invalid stack size specified in --stack-size" )?;
        let sample_count_limit = if let Some( value ) = matches.value_of( "sample-count" ) {
            Some( value.parse().map_err( |_| "invalid sample count specified in --sample-count" )? )
        } else {
            None
        };
        let time_limit = if let Some( value ) = matches.value_of( "time-limit" ){
            Some( value.parse().map_err( |_| "invalid time limit specified in -l/--time-limit" )? )
        } else {
            None
        };
        let discard_all = matches.occurrences_of( "discard-all" ) > 0;
        let lock_memory = matches.occurrences_of( "lock_memory" ) > 0;
        let output_path = matches.value_of_os( "output" );
        let offline = matches.occurrences_of( "offline" ) > 0;
        let panic_on_partial_backtrace = matches.occurrences_of( "panic-on-partial-backtrace" ) > 0;

        if panic_on_partial_backtrace {
            warn!( "Will panic on partial backtraces!" );
            if env::var( "RUST_BACKTRACE" ).is_err() {
                env::set_var( "RUST_BACKTRACE", "1" );
            }
        }

        use perf_event_open::EventSource;

        let event_source = match matches.value_of( "event-source" ).unwrap() {
            "hw_cpu_cycles" => EventSource::HwCpuCycles,
            "hw_ref_cpu_cycles" => EventSource::HwRefCpuCycles,
            "sw_cpu_clock" => EventSource::SwCpuClock,
            "sw_page_faults" => EventSource::SwPageFaults,
            _ => unreachable!()
        };

        let args = cmd_record::Args {
            target_process,
            frequency,
            event_source,
            stack_size,
            discard_all,
            sample_count_limit,
            time_limit,
            output_path,
            lock_memory,
            offline,
            panic_on_partial_backtrace
        };

        cmd_record::main( args )?;
    } else if let Some( matches ) = matches.subcommand_matches( "collate" ) {
        let input_path = matches.value_of_os( "INPUT" ).unwrap();
        let debug_symbols = matches.values_of_os( "debug-symbols" ).map( |args| args.collect() ).unwrap_or( Vec::new() );
        let force_stack_size = if let Some( size ) = matches.value_of( "force-stack-size" ) {
            Some( size.parse().map_err( |_| "invalid size specified in --force-stack-size" )? )
        } else {
            None
        };
        let omit_symbols = matches.values_of( "omit" ).map( |args| args.collect() ).unwrap_or( Vec::new() );
        let only_sample = if let Some( value ) = matches.value_of( "only-sample" ) {
            Some( value.parse().map_err( |_| "invalid number specified in --only-sample" )? )
        } else {
            None
        };

        let format = match matches.value_of( "format" ).unwrap() {
            "collapsed" => CollateFormat::Collapsed,
            "perf-like" => CollateFormat::PerfLike,
            _ => unreachable!()
        };

        let without_kernel_callstacks = matches.occurrences_of( "without-kernel-callstacks" ) > 0;
        let args = cmd_collate::Args {
            input_path,
            debug_symbols,
            force_stack_size,
            omit_symbols,
            only_sample,
            without_kernel_callstacks,
            format
        };

        cmd_collate::main( args )?;
    } else if let Some( matches ) = matches.subcommand_matches( "metadata" ) {
        let input_path = matches.value_of_os( "INPUT" ).unwrap();

        let args = cmd_metadata::Args {
            input_path
        };

        cmd_metadata::main( args )?;
    }

    Ok(())
}

fn main() {
    if let Err( error ) = main_impl() {
        eprintln!( "error: {}", error );
        exit( 1 );
    }
}
