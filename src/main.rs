extern crate libc;
extern crate regex;
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
extern crate structopt;

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
use std::ffi::OsString;
use structopt::StructOpt;

use perf_event_open::EventSource;

use cmd_record::TargetProcess;
use cmd_collate::CollateFormat;

fn parse_event_source( source: &str ) -> EventSource {
    match source {
        "hw_cpu_cycles" => EventSource::HwCpuCycles,
        "hw_ref_cpu_cycles" => EventSource::HwRefCpuCycles,
        "sw_cpu_clock" => EventSource::SwCpuClock,
        "sw_page_faults" => EventSource::SwPageFaults,
        "sw_dummy" => EventSource::SwDummy,
        _ => unreachable!()
    }
}

fn parse_collate_format( format: &str ) -> CollateFormat {
    match format {
        "collapsed" => CollateFormat::Collapsed,
        "perf-like" => CollateFormat::PerfLike,
        _ => unreachable!()
    }
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
struct RecordArgs {
    /// The frequency with which the measurements will be gathered
    #[structopt(long, short = "F", default_value = "900")]
    frequency: u64,
    /// The source of perf events
    #[structopt(
        long,
        short = "s",
        default_value = "hw_cpu_cycles",
        parse(from_str = "parse_event_source"),
        raw(possible_values = r#"&[
            "hw_cpu_cycles",
            "hw_ref_cpu_cycles",
            "sw_cpu_clock",
            "sw_page_faults",
            "sw_dummy"
        ]"#)
    )]
    event_source: EventSource,
    /// Size of the gathered stack payloads (in bytes)
    #[structopt(long, default_value = "24576")]
    stack_size: u32,
    /// The file to which the profiling data will be written
    #[structopt(long, short = "o", parse(from_os_str))]
    output: Option< OsString >,
    /// The number of samples to gather; unlimited by default
    #[structopt(long)]
    sample_count: Option< u64 >,
    /// Determines for how many seconds the measurements will be gathered
    #[structopt(long, short = "l")]
    time_limit: Option< u64 >,
    /// Gather data but do not do anything with it; useful only for testing
    #[structopt(long)]
    discard_all: bool,
    /// Prevents anything in the profiler's address space from being swapped out; might increase memory usage significantly
    #[structopt(long)]
    lock_memory: bool,
    /// Profiles a process with a given PID (conflicts with --process)
    #[structopt(
        long,
        short = "p",
        raw(required_unless_one = r#"&[
            "process"
        ]"#)
    )]
    pid: Option< u32 >,
    /// Profiles a process with a given name (conflicts with --pid)
    #[structopt(
        long,
        short = "P",
        raw(required_unless_one = r#"&[
            "pid"
        ]"#)
    )]
    process: Option< String >,
    /// Will wait for the profiled process to appear
    #[structopt(
        long,
        short = "w",
        raw(conflicts_with = r#"
            "pid"
        "#)
    )]
    wait: bool,
    /// Disable online backtracing
    #[structopt(long)]
    offline: bool,
    #[structopt(long, raw(hidden = "true"))]
    panic_on_partial_backtrace: bool
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
struct CollateArgs {
    /// A file or directory with extra debugging symbols; can be specified multiple times
    #[structopt(long, short = "d", parse(from_os_str))]
    debug_symbols: Vec< OsString >,

    #[structopt(long, raw(hidden = "true"))]
    force_stack_size: Option< u32 >,

    #[structopt(long, raw(hidden = "true"))]
    omit: Vec< String >,

    #[structopt(long, raw(hidden = "true"))]
    only_sample: Option< u64 >,

    /// Completely ignores kernel callstacks
    #[structopt(long)]
    without_kernel_callstacks: bool,

    /// Selects the output format
    #[structopt(
        long,
        default_value = "collapsed",
        parse(from_str = "parse_collate_format"),
        raw(possible_values = r#"&[
            "collapsed",
            "perf-like"
        ]"#)
    )]
    format: CollateFormat,

    /// The input file to use; record it with the `record` subcommand
    #[structopt(parse(from_os_str))]
    input: OsString
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
struct MetadataArgs {
    /// The input file to use; record it with the `record` subcommand
    #[structopt(parse(from_os_str))]
    input: OsString
}

#[derive(StructOpt, Debug)]
#[structopt(
    raw(author = "\"Jan Bujak <jan.bujak@nokia.com>\""),
    raw(setting = "structopt::clap::AppSettings::ArgRequiredElseHelp")
)]
enum Opt {
    /// Records profiling information
    #[structopt(name = "record")]
    Record( RecordArgs ),

    /// Emits collated stack traces for use with Brendan Gregg's flamegraph script
    #[structopt(name = "collate")]
    Collate( CollateArgs ),

    /// Outputs rudimentary JSON-formatted metadata
    #[structopt(name = "metadata")]
    Metadata( MetadataArgs )
}

fn main_impl() -> Result< (), Box< Error >  > {
    if env::var( "RUST_LOG" ).is_err() {
        env::set_var( "RUST_LOG", "nperf=info" );
    }

    env_logger::init();

    let opt = Opt::from_args();

    match opt {
        Opt::Record( RecordArgs {
            frequency,
            event_source,
            stack_size,
            discard_all,
            sample_count,
            time_limit,
            output,
            lock_memory,
            offline,
            panic_on_partial_backtrace,
            process,
            pid,
            wait
        }) => {
            let target_process = if let Some( process ) = process {
                if wait {
                    TargetProcess::ByNameWaiting( process )
                } else {
                    TargetProcess::ByName( process )
                }
            } else if let Some( pid ) = pid {
                TargetProcess::ByPid( pid )
            } else {
                unreachable!();
            };

            if panic_on_partial_backtrace {
                warn!( "Will panic on partial backtraces!" );
                if env::var( "RUST_BACKTRACE" ).is_err() {
                    env::set_var( "RUST_BACKTRACE", "1" );
                }
            }

            let args = cmd_record::Args {
                target_process,
                frequency,
                event_source,
                stack_size,
                discard_all,
                sample_count_limit: sample_count,
                time_limit,
                output_path: output.as_ref().map( |path| path.as_os_str() ),
                lock_memory,
                offline,
                panic_on_partial_backtrace
            };

            cmd_record::main( args )?;
        },
        Opt::Collate( CollateArgs {
            input,
            debug_symbols,
            force_stack_size,
            omit,
            only_sample,
            without_kernel_callstacks,
            format
        }) => {
            let args = cmd_collate::Args {
                input_path: &input,
                debug_symbols,
                force_stack_size,
                omit_symbols: omit,
                only_sample,
                without_kernel_callstacks,
                format
            };

            cmd_collate::main( args )?;
        },
        Opt::Metadata( MetadataArgs { input } ) => {
            let args = cmd_metadata::Args {
                input_path: &input
            };

            cmd_metadata::main( args )?;
        }
    }

    Ok(())
}

fn main() {
    if let Err( error ) = main_impl() {
        eprintln!( "error: {}", error );
        exit( 1 );
    }
}
