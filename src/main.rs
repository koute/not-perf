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

mod args;
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
mod profiler;
mod cmd_record;
mod cmd_collate;
mod cmd_metadata;

use std::env;
use std::error::Error;
use std::process::exit;
use structopt::StructOpt;

fn main_impl() -> Result< (), Box< Error >  > {
    if env::var( "RUST_LOG" ).is_err() {
        env::set_var( "RUST_LOG", "nperf=info" );
    }

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
        args::Opt::Collate( args ) => {
            cmd_collate::main( args )?;
        },
        args::Opt::Metadata( args ) => {
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
