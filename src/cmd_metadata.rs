use std::fs;
use std::ffi::OsStr;
use std::error::Error;

use serde_json;

use archive::{Packet, ArchiveReader};
use metadata::{self, Metadata};

pub struct Args< 'a > {
    pub input_path: &'a OsStr
}

pub fn main( args: Args ) -> Result< (), Box< Error > > {
    let fp = fs::File::open( args.input_path ).map_err( |err| format!( "cannot open {:?}: {}", args.input_path, err ) )?;
    let mut reader = ArchiveReader::new( fp ).validate_header().unwrap().skip_unknown();

    let mut is_valid = false;
    let mut metadata = Metadata::default();

    while let Some( packet ) = reader.next() {
        let packet = packet.unwrap();
        is_valid = true;

        match packet {
            Packet::MachineInfo { architecture, .. } => {
                metadata.machine_info = Some( metadata::MachineInfo { architecture: architecture.into() } );
            },
            Packet::ProcessInfo { pid, executable, .. } => {
                metadata.processes.push( metadata::Process {
                    pid,
                    executable: String::from_utf8_lossy( &executable ).into()
                });
            },
            Packet::BinaryInfo { path, debuglink, .. } => {
                let path = String::from_utf8_lossy( &path ).into_owned();

                let debuglink_length = debuglink.iter().position( |&byte| byte == 0 ).unwrap_or( debuglink.len() );
                let debuglink = &debuglink[ 0..debuglink_length ];
                let debuglink = if debuglink.is_empty() {
                    None
                } else {
                    Some( String::from_utf8_lossy( &debuglink ).into_owned() )
                };

                metadata.binaries.push( metadata::Binary {
                    path,
                    debuglink
                });
            },
            _ => {}
        }
    }

    if !is_valid {
        return Err( format!( "input {:?} is not a valid archive", args.input_path ).into() )
    }

    println!( "{}", serde_json::to_string_pretty( &metadata ).unwrap() );
    Ok(())
}
