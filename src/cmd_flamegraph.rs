use std::error::Error;
use std::io;
use std::fs::File;

use inferno::flamegraph;

use crate::args;
use crate::cmd_collate::collapse_into_sorted_vec;

pub fn main( args: args::FlamegraphArgs ) -> Result< (), Box< dyn Error > > {
    let lines = collapse_into_sorted_vec( &args.collation_args, &args.formatting_args )?;
    let iter = lines.iter().map( |line| line.as_str() );
    let mut options = flamegraph::Options::default();

    if let Some( output ) = args.output {
        let fp = io::BufWriter::new( File::create( output )? );
        flamegraph::from_lines( &mut options, iter, fp ).unwrap();
    } else {
        let stdout = io::stdout();
        let stdout = stdout.lock();
        flamegraph::from_lines( &mut options, iter, stdout ).unwrap();
    }

    Ok(())
}
