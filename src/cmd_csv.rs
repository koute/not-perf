use std::error::Error;
use std::io::{self, Write};
use std::fs::File;

use crate::args::{self, Granularity};
use crate::interner::StringInterner;
use crate::data_reader::{DecodeOpts, EventKind, read_data, repack_cli_args, to_s};

pub struct GraphSample {
    pub timestamp: u64,
    pub user: u32,
    pub kernel: u32
}

impl GraphSample {
    pub fn timestamp_s( &self ) -> f64 {
        to_s( self.timestamp )
    }
}

pub fn into_graph( args: &args::SharedCollationArgs, sampling_interval: Option< f64 > ) -> Result< Vec< GraphSample >, Box< dyn Error > > {
    let (omit_regex, read_data_args) = repack_cli_args( args );
    let opts = DecodeOpts {
        omit_regex,
        emit_kernel_frames: true,
        emit_thread_frames: false,
        emit_process_frames: false,
        granularity: Granularity::Address
    };

    let mut interner = StringInterner::new();
    let mut samples = Vec::new();
    let state = read_data( read_data_args, |event| {
        match event.kind {
            EventKind::Sample( sample ) => {
                if !sample.try_decode( event.state, &opts, &mut interner, None ) {
                    return;
                }

                let (user, kernel) = if sample.kernel_backtrace.is_empty() {
                    (0, 1)
                } else {
                    (1, 0)
                };

                let sample = GraphSample { timestamp: sample.timestamp, user, kernel };
                samples.push( sample );
            },
            _ => {}
        }
    })?;

    if samples.is_empty() {
        return Ok( Vec::new() );
    }

    samples.sort_by_key( |sample| sample.timestamp );
    let total_elapsed = samples.last().unwrap().timestamp - samples.first().unwrap().timestamp;

    let interval =
        if let Some( interval ) = sampling_interval {
            (interval * 1_000_000_000.0) as u64
        } else if total_elapsed >= 3_000_000_000 {
            1_000_000_000
        } else if total_elapsed >= 3_000_000 {
            1_000_000
        } else if total_elapsed >= 3_000 {
            1_000
        } else {
            1
        };

    let unfiltered_first_timestamp = state.unfiltered_first_timestamp().unwrap();
    let first_timestamp = samples.first().unwrap().timestamp - unfiltered_first_timestamp;

    let mut output = Vec::new();
    let mut current = GraphSample {
        timestamp: first_timestamp - (first_timestamp % interval),
        user: 0,
        kernel: 0
    };

    'outer: for mut sample in samples {
        sample.timestamp -= unfiltered_first_timestamp;
        loop {
            if (sample.timestamp - current.timestamp) < interval {
                current.user += sample.user;
                current.kernel += sample.kernel;
                continue 'outer;
            }

            let next = GraphSample {
                timestamp: current.timestamp + interval,
                user: 0,
                kernel: 0
            };

            output.push( current );
            current = next;
        }
    }

    output.push( current );
    Ok( output )
}

fn write( samples: Vec< GraphSample >, mut fp: impl Write ) -> Result< (), io::Error > {
    writeln!( fp, "Timestamp,Samples" )?;
    for sample in samples {
        writeln!( fp, "{},{}", sample.timestamp_s(), sample.user + sample.kernel )?;
    }

    Ok(())
}

pub fn main( args: args::CsvArgs ) -> Result< (), Box< dyn Error > > {
    let samples = into_graph( &args.collation_args, args.sampling_interval )?;

    if let Some( output ) = args.output {
        let fp = io::BufWriter::new( File::create( output )? );
        write( samples, fp )?;
    } else {
        let stdout = io::stdout();
        let stdout = stdout.lock();
        write( samples, stdout )?;
    }

    Ok(())
}
