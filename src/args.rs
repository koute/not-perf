use std::ffi::OsString;
use structopt::StructOpt;

use perf_event_open::EventSource;

use crate::cmd_collate::CollateFormat;

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

fn try_parse_period( period: &str ) -> Result< u64, <u64 as std::str::FromStr>::Err > {
    let period = if period.ends_with( "ms" ) {
        period[ 0..period.len() - 2 ].parse::< u64 >()? * 1000_000
    } else if period.ends_with( "us" ) {
        period[ 0..period.len() - 2 ].parse::< u64 >()? * 1000
    } else if period.ends_with( "ns" ) {
        period[ 0..period.len() - 2 ].parse::< u64 >()?
    } else if period.ends_with( "s" ) {
        period[ 0..period.len() - 1 ].parse::< u64 >()? * 1000_000_000
    } else {
        period.parse::< u64 >()? * 1000_000_000
    };

    Ok( period )
}

fn parse_period( period: &str ) -> u64 {
    match try_parse_period( period ) {
        Ok( period ) => period,
        Err( _ ) => {
            eprintln!( "error: invalid '--period' specified" );
            std::process::exit( 1 );
        }
    }
}

pub enum TargetProcess {
    ByPid( u32 ),
    ByName( String ),
    ByNameWaiting( String, u64 )
}

#[derive(StructOpt, Clone, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct ProcessFilter {
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
    /// Specifies the number of seconds which the profiler should wait
    /// for the process to appear; makes sense only when used with the `--wait` option
    #[structopt(
        long,
        default_value = "60"
    )]
    wait_timeout: u32,
}

impl From< ProcessFilter > for TargetProcess {
    fn from( args: ProcessFilter ) -> Self {
        if let Some( process ) = args.process {
            if args.wait {
                TargetProcess::ByNameWaiting( process, args.wait_timeout as u64 )
            } else {
                TargetProcess::ByName( process )
            }
        } else if let Some( pid ) = args.pid {
            TargetProcess::ByPid( pid )
        } else {
            unreachable!();
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, StructOpt)]
pub enum Granularity {
    Address,
    Function,
    Line
}

impl Default for Granularity {
    fn default() -> Self {
        Granularity::Function
    }
}

fn parse_granularity( value: &str ) -> Granularity {
    match value {
        "address" => Granularity::Address,
        "function" => Granularity::Function,
        "line" => Granularity::Line,
        _ => unreachable!()
    }
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct GenericProfilerArgs {
    /// The file to which the profiling data will be written
    #[structopt(long, short = "o", parse(from_os_str))]
    pub output: Option< OsString >,

    /// The number of samples to gather; unlimited by default
    #[structopt(long)]
    pub sample_count: Option< u64 >,

    /// Determines for how many seconds the measurements will be gathered
    #[structopt(long, short = "l")]
    pub time_limit: Option< u64 >,

    /// Prevents anything in the profiler's address space from being swapped out; might increase memory usage significantly
    #[structopt(long)]
    pub lock_memory: bool,

    /// Disable online backtracing
    #[structopt(long)]
    pub offline: bool,

    #[structopt(long, raw(hidden = "true"))]
    pub panic_on_partial_backtrace: bool,

    #[structopt(flatten)]
    pub process_filter: ProcessFilter
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct RecordArgs {
    /// The frequency with which the measurements will be gathered
    #[structopt(long, short = "F", default_value = "900")]
    pub frequency: u32,

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
    pub event_source: EventSource,

    /// Size of the gathered stack payloads (in bytes)
    #[structopt(long, default_value = "24576")]
    pub stack_size: u32,

    /// Gather data but do not do anything with it; useful only for testing
    #[structopt(long)]
    pub discard_all: bool,

    #[structopt(flatten)]
    pub profiler_args: GenericProfilerArgs
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct SharedCollationArgs {
    /// A file or directory with extra debugging symbols; can be specified multiple times
    #[structopt(long, short = "d", parse(from_os_str))]
    pub debug_symbols: Vec< OsString >,

    #[structopt(long, raw(hidden = "true"))]
    pub force_stack_size: Option< u32 >,

    #[structopt(long, raw(hidden = "true"))]
    pub omit: Vec< String >,

    #[structopt(long, raw(hidden = "true"))]
    pub only_sample: Option< u64 >,

    /// Completely ignores kernel callstacks
    #[structopt(long)]
    pub without_kernel_callstacks: bool,

    /// Only process the samples generated *after* this many seconds after launch.
    #[structopt(long)]
    pub from: Option< String >,

    /// Only process the samples generated *before* this many seconds after launch.
    #[structopt(long)]
    pub to: Option< String >,

    /// The input file to use; record it with the `record` subcommand
    #[structopt(parse(from_os_str))]
    pub input: OsString
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct ArgMergeThreads {
    /// Merge callstacks from all threads
    #[structopt(long)]
    pub merge_threads: bool
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct ArgGranularity {
    /// Specifies at what granularity the call frames will be merged
    #[structopt(
        long,
        default_value = "function",
        parse(from_str = "parse_granularity"),
        raw(possible_values = r#"&[
            "address",
            "function",
            "line"
        ]"#)
    )]
    pub granularity: Granularity
}

#[cfg(feature = "inferno")]
#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct FlamegraphArgs {
    #[structopt(flatten)]
    pub collation_args: SharedCollationArgs,

    #[structopt(flatten)]
    pub arg_merge_threads: ArgMergeThreads,

    #[structopt(flatten)]
    pub arg_granularity: ArgGranularity,

    /// The file to which the flamegraph will be written to (instead of the stdout)
    #[structopt(long, short = "o", parse(from_os_str))]
    pub output: Option< OsString >
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct CsvArgs {
    #[structopt(flatten)]
    pub collation_args: SharedCollationArgs,

    /// The sampling interval, in seconds
    #[structopt(long, short = "t")]
    pub sampling_interval: Option< f64 >,

    /// The file to which the CSV will be written to (instead of the stdout)
    #[structopt(long, short = "o", parse(from_os_str))]
    pub output: Option< OsString >
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct TraceEventsArgs {
    #[structopt(flatten)]
    pub collation_args: SharedCollationArgs,

    #[structopt(flatten)]
    pub arg_granularity: ArgGranularity,

    #[structopt(long)]
    pub absolute_time: bool,

    /// The sampling period; samples within one sampling period will be merged together
    #[structopt(long, short = "p", parse(from_str = "parse_period"))]
    pub period: Option< u64 >,

    /// The file to which the trace events will be written to
    #[structopt(long, short = "o", parse(from_os_str))]
    pub output: OsString
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct CollateArgs {
    #[structopt(flatten)]
    pub collation_args: SharedCollationArgs,

    #[structopt(flatten)]
    pub arg_merge_threads: ArgMergeThreads,

    #[structopt(flatten)]
    pub arg_granularity: ArgGranularity,

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
    pub format: CollateFormat
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct MetadataArgs {
    /// The input file to use; record it with the `record` subcommand
    #[structopt(parse(from_os_str))]
    pub input: OsString
}

#[derive(StructOpt, Debug)]
#[structopt(
    raw(author = "\"Jan Bujak <jan.bujak@nokia.com>\""),
    raw(setting = "structopt::clap::AppSettings::ArgRequiredElseHelp")
)]
pub enum Opt {
    /// Records profiling information with perf_event_open
    #[structopt(name = "record")]
    Record( RecordArgs ),

    /// Emits an SVG flamegraph
    #[cfg(feature = "inferno")]
    #[structopt(name = "flamegraph")]
    Flamegraph( FlamegraphArgs ),

    /// Emits a CSV file
    #[structopt(name = "csv")]
    Csv( CsvArgs ),

    /// Emits trace events for use with Chromium's Trace Viewer
    #[structopt(name = "trace-events")]
    TraceEvents( TraceEventsArgs ),

    /// Emits collated stack traces for use with Brendan Gregg's flamegraph script
    #[structopt(name = "collate")]
    Collate( CollateArgs ),

    /// Outputs rudimentary JSON-formatted metadata
    #[structopt(name = "metadata")]
    Metadata( MetadataArgs )
}
