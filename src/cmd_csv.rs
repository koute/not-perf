use std::error::Error;
use std::io::{self, Write};
use std::fs::File;

use crate::args;
use crate::cmd_collate::{GraphSample, into_graph};

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
