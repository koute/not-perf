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
}

impl From< ProcessFilter > for TargetProcess {
    fn from( args: ProcessFilter ) -> Self {
        if let Some( process ) = args.process {
            if args.wait {
                TargetProcess::ByNameWaiting( process )
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

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct RecordArgs {
    /// The frequency with which the measurements will be gathered
    #[structopt(long, short = "F", default_value = "900")]
    pub frequency: u64,
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
    /// The file to which the profiling data will be written
    #[structopt(long, short = "o", parse(from_os_str))]
    pub output: Option< OsString >,
    /// The number of samples to gather; unlimited by default
    #[structopt(long)]
    pub sample_count: Option< u64 >,
    /// Determines for how many seconds the measurements will be gathered
    #[structopt(long, short = "l")]
    pub time_limit: Option< u64 >,
    /// Gather data but do not do anything with it; useful only for testing
    #[structopt(long)]
    pub discard_all: bool,
    /// Prevents anything in the profiler's address space from being swapped out; might increase memory usage significantly
    #[structopt(long)]
    pub lock_memory: bool,

    #[structopt(flatten)]
    pub process_filter: ProcessFilter,

    /// Disable online backtracing
    #[structopt(long)]
    pub offline: bool,
    #[structopt(long, raw(hidden = "true"))]
    pub panic_on_partial_backtrace: bool
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
pub struct CollateArgs {
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
    pub format: CollateFormat,

    /// The input file to use; record it with the `record` subcommand
    #[structopt(parse(from_os_str))]
    pub input: OsString
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

    /// Emits collated stack traces for use with Brendan Gregg's flamegraph script
    #[structopt(name = "collate")]
    Collate( CollateArgs ),

    /// Outputs rudimentary JSON-formatted metadata
    #[structopt(name = "metadata")]
    Metadata( MetadataArgs )
}
