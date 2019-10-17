#[macro_use]
extern crate log;

use std::env;
use std::error::Error;
use std::process::exit;
use structopt::StructOpt;

use nperf_core::{
    args,
    cmd_collate,
    cmd_csv,
    cmd_metadata,
    cmd_record,
    cmd_trace_events
};

#[cfg(feature = "inferno")]
use nperf_core::cmd_flamegraph;

fn main_impl() -> Result< (), Box< dyn Error > > {
    if env::var( "RUST_LOG" ).is_err() {
        env::set_var( "RUST_LOG", "nperf=info" );
    }

    #[cfg(feature = "env_logger")]
    env_logger::init();

    let opt = args::Opt::from_args();
    match opt {
        args::Opt::Record( args ) => {
            if args.profiler_args.panic_on_partial_backtrace {
                warn!( "Will panic on partial backtraces!" );
                if env::var( "RUST_BACKTRACE" ).is_err() {
                    env::set_var( "RUST_BACKTRACE", "1" );
                }
            }

            cmd_record::main( args )?;
        },
        #[cfg(feature = "inferno")]
        args::Opt::Flamegraph( args ) => {
            cmd_flamegraph::main( args )?;
        },
        args::Opt::Csv( args ) => {
            cmd_csv::main( args )?;
        },
        args::Opt::Collate( args ) => {
            cmd_collate::main( args )?;
        },
        args::Opt::Metadata( args ) => {
            cmd_metadata::main( args )?;
        },
        args::Opt::TraceEvents( args ) => {
            cmd_trace_events::main( args )?;
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
