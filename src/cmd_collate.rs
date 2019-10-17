use std::io::{self, Write};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::error::Error;
use std::borrow::Cow;

use regex::Regex;

use crate::args::{self, Granularity};
use crate::archive::UserFrame;
use crate::interner::StringInterner;

use crate::data_reader::{Collation, CollapseOpts, Process, FrameKind, collate, decode, decode_user_frames, repack_cli_args, write_frame};

#[derive(Debug)]
pub enum CollateFormat {
    Collapsed,
    PerfLike
}

fn escape< 'a >( string: &'a str ) -> Cow< 'a, str > {
    let mut output: Cow< str > = string.into();
    if output.contains( " " ) {
        output = output.replace( " ", "_" ).into();
    }
    output
}

fn write_perf_like_output< T: io::Write >(
    omit_regex: &Option< Regex >,
    collation: &Collation,
    process: &Process,
    tid: u32,
    user_backtrace: &[UserFrame],
    kernel_backtrace: &[u64],
    cpu: u32,
    timestamp: u64,
    output: &mut T
) -> Result< (), io::Error > {
    let mut interner = StringInterner::new();
    let mut frames = Vec::new();
    if !decode_user_frames( omit_regex, Granularity::Address, process, user_backtrace, &mut interner, Some( &mut frames ) ) {
        return Ok(()); // Was filtered out.
    }

    let secs = timestamp / 1000_000_000;
    let nsecs = timestamp - (secs * 1000_000_000);
    write!( output, "{}", escape( process.executable() ) )?;
    writeln!( output, " {}/{} [{:03}] {}.{:09}: cpu-clock: ", process.pid(), tid, cpu, secs, nsecs )?;

    for &address in kernel_backtrace {
        if let Some( symbol ) = collation.get_kernel_symbol_by_address( address ) {
            if let Some( module ) = symbol.module.as_ref() {
                writeln!( output, "\t{:16X} {} ([linux:{}])", address, symbol.name, module ).unwrap()
            } else {
                writeln!( output, "\t{:16X} {} ([linux])", address, symbol.name ).unwrap()
            }
        } else {
            writeln!( output, "\t{:16X} 0x{:016X} ([linux])", address, address )?;
        }
    }

    for frame in frames {
        match frame {
            FrameKind::User( address ) => {
                writeln!( output, "\t{:16X} 0x{:016X} ([unknown])", address, address )?;
            },
            FrameKind::UserBinary( ref binary_id, address ) => {
                let binary = collation.get_binary( binary_id );
                writeln!( output, "\t{:16X} 0x{:016X} ({})", address, address, binary.basename() )?;
            },
            FrameKind::UserByAddress { ref binary_id, address, is_inline, symbol } => {
                let binary = collation.get_binary( binary_id );
                let symbol = interner.resolve( symbol ).unwrap();
                if is_inline {
                    writeln!( output, "\t{:16X} inline {} ({})", address, symbol, binary.basename() )?;
                } else {
                    writeln!( output, "\t{:16X} {} ({})", address, symbol, binary.basename() )?;
                }
            },
            _ => unreachable!()
        }
    }

    writeln!( output )?;

    Ok(())
}

pub fn collapse_into_sorted_vec(
    args: &args::SharedCollationArgs,
    arg_granularity: &args::ArgGranularity,
    arg_merge_threads: &args::ArgMergeThreads
) -> Result< Vec< String >, Box< dyn Error > > {
    let (omit_regex, collate_args) = repack_cli_args( args );
    let opts = CollapseOpts {
        merge_threads: arg_merge_threads.merge_threads,
        granularity: arg_granularity.granularity
    };

    let mut stacks: HashMap< Vec< FrameKind >, u64 > = HashMap::new();
    let mut interner = StringInterner::new();
    let collation = collate( collate_args, |collation, _timestamp, process, tid, _cpu, user_backtrace, kernel_backtrace| {
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
            *stacks.entry( frames ).or_insert( 0 ) += 1;
        }
    })?;

    let mut output = Vec::with_capacity( stacks.len() );
    for (ref frames, count) in &stacks {
        let mut line = String::new();
        let mut is_first = true;
        for frame in frames.into_iter().rev() {
            if is_first {
                is_first = false;
            } else {
                line.push( ';' );
            }

            write_frame( &collation, &interner, &mut line, frame );
        }

        write!( &mut line, " {}", count ).unwrap();
        output.push( line );
    }

    output.sort_unstable();
    Ok( output )
}

pub fn main( args: args::CollateArgs ) -> Result< (), Box< dyn Error > > {
    match args.format {
        CollateFormat::Collapsed => {
            let output = collapse_into_sorted_vec( &args.collation_args, &args.arg_granularity, &args.arg_merge_threads )?;
            let output = output.join( "\n" );
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            stdout.write_all( output.as_bytes() ).unwrap();
        },
        CollateFormat::PerfLike => {
            let (omit_regex, collate_args) = repack_cli_args( &args.collation_args );
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            collate( collate_args, |collation, timestamp, process, tid, cpu, user_backtrace, kernel_backtrace| {
                write_perf_like_output(
                    &omit_regex,
                    &collation,
                    process,
                    tid,
                    &user_backtrace,
                    &kernel_backtrace,
                    cpu,
                    timestamp,
                    &mut stdout
                ).unwrap();
            })?;
        }
    }

    Ok(())
}
