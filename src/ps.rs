use std::io;
use std::fs;
use std::time::{Duration, Instant};
use std::thread::sleep;

use utils::SigintHandler;

struct ProcessName {
    from_cmdline: Option< String >,
    from_executable: Option< String >
}

fn read_name( pid: u32 ) -> io::Result< ProcessName > {
    let mut cmdline = fs::read( format!( "/proc/{}/cmdline", pid ) )?;
    let executable = match fs::read_link( format!( "/proc/{}/exe", pid ) ) {
        Ok( path ) => Some( path ),
        Err( ref err ) if err.kind() == io::ErrorKind::PermissionDenied => None,
        Err( err ) => return Err( err )
    }.map( |executable| {
        let executable = match executable.into_os_string().into_string() {
            Ok( string ) => string,
            Err( os_string ) => os_string.to_string_lossy().into_owned()
        };

        executable[ executable.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ].to_owned()
    });

    let name_length = cmdline.iter().position( |&byte| byte == 0 ).unwrap_or( cmdline.len() );
    cmdline.truncate( name_length );

    let cmdline = if cmdline.is_empty() {
        None
    } else {
        let string = match String::from_utf8( cmdline ) {
            Ok( string ) => string,
            Err( err ) => String::from_utf8_lossy( &err.into_bytes() ).into_owned()
        };
        Some( string )
    };

    Ok( ProcessName {
        from_cmdline: cmdline,
        from_executable: executable
    })
}

pub fn find_process( pattern: &str ) -> io::Result< Option< u32 > > {
    let result = fs::read_dir( "/proc" )?.into_iter()
        .filter_map( |entry| entry.ok() )
        .filter_map( |entry| entry.file_name().into_string().ok() )
        .filter_map( |filename| filename.parse().ok() )
        .filter_map( |pid| read_name( pid ).ok().map( |name| (name, pid) ) )
        .filter( |&(ref name, _)| {
            name.from_cmdline.as_ref().map( |name| name == pattern ).unwrap_or( false ) ||
            name.from_executable.as_ref().map( |name| name == pattern ).unwrap_or( false )
        })
        .map( |(_, pid)| pid )
        .next();

    Ok( result )
}

pub fn wait_for_process( sigint: &SigintHandler, process: &str ) -> io::Result< Option< u32 > > {
    info!( "Waiting for process named '{}'...", process );

    let timestamp = Instant::now();
    loop {
        if let Some( _ ) = find_process( process )? {
            // Sometimes this matches the wrong process for some reason,
            // so let's retry after a delay to be sure.
            sleep( Duration::from_millis( 100 ) );
            if let Some( pid ) = find_process( process )? {
                info!( "Process '{}' found with PID {}!", process, pid );
                return Ok( Some( pid ) );
            }
        }

        sleep( Duration::from_millis( 50 ) );
        if timestamp.elapsed() >= Duration::from_secs( 60 ) {
            return Err( io::Error::new( io::ErrorKind::Other, format!( "process '{}' not found", process ) ) );
        }

        if sigint.was_triggered() {
            return Ok( None );
        }
    }
}
