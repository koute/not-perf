use std::error::Error;
use std::io;

use inferno::flamegraph;

use args;
use cmd_collate::collapse_into_sorted_vec;

pub fn main( args: args::FlamegraphArgs ) -> Result< (), Box< Error > > {
    let lines = collapse_into_sorted_vec( &args.collation_args )?;
    let mut options = flamegraph::Options::default();

    let stdout = io::stdout();
    let stdout = stdout.lock();
    flamegraph::from_lines( &mut options, lines.iter().map( |line| line.as_str() ), stdout ).unwrap();

    Ok(())
}
