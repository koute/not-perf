use std::io::{self, Write};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::error::Error;
use std::borrow::Cow;

use crate::args::{self, Granularity};
use crate::interner::StringInterner;

use crate::data_reader::{State, DecodeOpts, EventKind, EventSample, FrameKind, read_data, repack_cli_args, write_frame};

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
    state: &State,
    sample: EventSample,
    frames: &[FrameKind],
    interner: &mut StringInterner,
    output: &mut T
) -> Result< (), io::Error > {
    let timestamp = sample.timestamp;
    let secs = timestamp / 1000_000_000;
    let nsecs = timestamp - (secs * 1000_000_000);
    write!( output, "{}", escape( sample.process.executable() ) )?;
    writeln!( output, " {}/{} [{:03}] {}.{:09}: cpu-clock: ", sample.process.pid(), sample.tid, sample.cpu, secs, nsecs )?;

    for &address in sample.kernel_backtrace {
        if let Some( symbol ) = state.get_kernel_symbol_by_address( address ) {
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
                let binary = state.get_binary( binary_id );
                writeln!( output, "\t{:16X} 0x{:016X} ({})", address, address, binary.basename() )?;
            },
            FrameKind::UserByAddress { ref binary_id, address, is_inline, symbol } => {
                let binary = state.get_binary( binary_id );
                let symbol = interner.resolve( *symbol ).unwrap();
                if *is_inline {
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
    let (omit_regex, read_data_args) = repack_cli_args( args );
    let opts = DecodeOpts {
        omit_regex,
        emit_kernel_frames: true,
        emit_thread_frames: !arg_merge_threads.merge_threads,
        emit_process_frames: true,
        granularity: arg_granularity.granularity
    };

    let mut stacks: HashMap< Vec< FrameKind >, u64 > = HashMap::new();
    let mut interner = StringInterner::new();
    let state = read_data( read_data_args, |event| {
        match event.kind {
            EventKind::Sample( sample ) => {
                let frames = sample.decode( &event.state, &opts, &mut interner );
                if let Some( frames ) = frames {
                    *stacks.entry( frames ).or_insert( 0 ) += 1;
                }
            },
            _ => {}
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

            write_frame( &state, &interner, &mut line, frame );
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
            let (omit_regex, read_data_args) = repack_cli_args( &args.collation_args );
            let stdout = io::stdout();
            let mut stdout = stdout.lock();

            let mut interner = StringInterner::new();
            let mut frames = Vec::new();
            let opts = DecodeOpts {
                omit_regex,
                emit_kernel_frames: false,
                emit_thread_frames: false,
                emit_process_frames: false,
                granularity: Granularity::Address
            };

            read_data( read_data_args, |event| {
                match event.kind {
                    EventKind::Sample( sample ) => {
                        if !sample.try_decode( &event.state, &opts, &mut interner, Some( &mut frames ) ) {
                            return; // Was filtered out.
                        }

                        write_perf_like_output(
                            &event.state,
                            sample,
                            &frames,
                            &mut interner,
                            &mut stdout
                        ).unwrap();

                        frames.clear();
                    },
                    _ => {}
                }
            })?;
        }
    }

    Ok(())
}
