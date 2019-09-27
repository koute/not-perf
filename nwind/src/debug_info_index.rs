use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;

use crate::binary::BinaryData;
use crate::utils::HexString;

pub struct DebugInfoIndex {
    by_filename: HashMap< Vec< u8 >, Vec< Arc< BinaryData > > >,
    by_build_id: HashMap< Vec< u8 >, Vec< Arc< BinaryData > > >,
    auto_load: bool
}

fn check_build_id< 'a >( data: &'a Arc< BinaryData >, expected_build_id: Option< &[u8] > ) -> bool {
    let build_id = data.build_id();
    expected_build_id.is_none() || build_id.is_none() || build_id == expected_build_id
}

impl DebugInfoIndex {
    pub fn new() -> Self {
        DebugInfoIndex {
            by_filename: HashMap::new(),
            by_build_id: HashMap::new(),
            auto_load: false
        }
    }

    pub fn enable_auto_load( &mut self ) {
        self.auto_load = true;
    }

    pub fn add< P: AsRef< Path > >( &mut self, path: P ) {
        let mut done = HashSet::new();
        self.add_impl( &mut done, path.as_ref(), true );
    }

    pub fn get( &mut self, path: &str, debuglink: Option< &[u8] >, build_id: Option< &[u8] > ) -> Option< Arc< BinaryData > > {
        let (bin, dbg) = self.get_pair( path, debuglink, build_id );
        dbg.or( bin )
    }

    pub fn get_pair( &mut self, path: &str, debuglink: Option< &[u8] >, build_id: Option< &[u8] > ) -> (Option< Arc< BinaryData > >, Option< Arc< BinaryData > >) {
        debug!( "Requested debug info for '{}'; debuglink = {:?}, build_id = {:?}", path, debuglink.map( String::from_utf8_lossy ), build_id.map( HexString ) );
        let basename = &path[ path.rfind( "/" ).map( |index| index + 1 ).unwrap_or( 0 ).. ];
        let basename: &[u8] = basename.as_ref();

        let mut candidates: Vec< Arc< BinaryData > > = Vec::new();
        if let Some( build_id ) = build_id {
            if let Some( entries ) = self.by_build_id.get( build_id ) {
                candidates.extend( entries.iter().cloned() );

                for entry in entries {
                    if let Some( debuglink ) = entry.debuglink() {
                        if let Some( debug_entries ) = self.by_filename.get( debuglink ) {
                            candidates.extend( debug_entries.iter().filter( |data| check_build_id( data, Some( build_id ) ) ).cloned() );
                        }
                    }
                }
            }
        }

        if let Some( entries ) = self.by_filename.get( basename ) {
            candidates.extend( entries.iter().filter( |data| check_build_id( data, build_id ) ).cloned() );

            for entry in entries {
                if let Some( debuglink ) = entry.debuglink() {
                    if let Some( debug_entries ) = self.by_filename.get( debuglink ) {
                        candidates.extend( debug_entries.iter().filter( |data| check_build_id( data, build_id ) ).cloned() );
                    }
                }
            }
        }

        if let Some( debuglink ) = debuglink {
            if let Some( entries ) = self.by_filename.get( debuglink ) {
                candidates.extend( entries.iter().filter( |data| check_build_id( data, build_id ) ).cloned() );
            }
        }

        if candidates.is_empty() && debuglink.is_none() {
            if let Some( build_id ) = build_id {
                if let Some( binary ) = self.try_auto_load( path, build_id ) {
                    candidates.push( binary );
                }
            }
        }

        candidates.sort_by_key( |entry| entry.as_ptr() );
        candidates.dedup_by_key( |entry| entry.as_ptr() );
        let matching: Vec< _ > = candidates.iter().filter( |entry| entry.build_id().is_some() && entry.build_id() == build_id ).cloned().collect();
        if !matching.is_empty() {
            candidates = matching;
        }

        let (bin, dbg) = match candidates.len() {
            0 => (None, None),
            1 => (candidates.pop(), None),
            _ => {
                candidates.sort_by_key( |entry| entry.as_bytes().len() );
                let dbg = candidates.pop();
                let bin = candidates.pop();
                (bin, dbg)
            }
        };

        debug!( "Debug info lookup result: bin = {:?}, dbg = {:?}", bin.as_ref().map( |data| data.name() ), dbg.as_ref().map( |data| data.name() ) );
        (bin, dbg)
    }

    fn try_auto_load( &mut self, path: &str, build_id: &[u8] ) -> Option< Arc< BinaryData > > {
        if !self.auto_load || !path.starts_with( "/" ) {
            return None;
        }

        let path = Path::new( path );
        if !path.exists() {
            return None;
        }

        let binary = BinaryData::load_from_fs( path ).ok()?;
        if build_id != binary.build_id()? {
            return None;
        }

        let binary = Arc::new( binary );
        self.by_build_id.entry( build_id.to_vec() ).or_default().push( binary.clone() );

        Some( binary )
    }

    fn add_impl( &mut self, done: &mut HashSet< PathBuf >, path: &Path, is_toplevel: bool ) {
        if !path.exists() {
            warn!( "Failed to load {:?}: file not found", path );
            return;
        }

        let target_path;
        let mut path: &Path = &path;

        target_path = path.read_link();
        let target_path: Result< &Path, _ > = target_path.as_ref().map( |target_path| target_path.as_ref() );
        if let Ok( target_path ) = target_path {
            path = target_path;
        }

        if done.contains( path ) {
            return;
        }

        done.insert( path.into() );

        if path.is_dir() {
            let dir = match path.read_dir() {
                Ok( dir ) => dir,
                Err( error ) => {
                    warn!( "Cannot read the contents of {:?}: {}", path, error );
                    return;
                }
            };

            for entry in dir {
                if let Ok( entry ) = entry {
                    let path = entry.path();
                    self.add_impl( done, &path, false );
                }
            }
        } else if path.is_file() {
            match path.metadata() {
                Ok( metadata ) => {
                    if metadata.len() == 0 {
                        return;
                    }
                },
                Err( error ) => {
                    warn!( "Cannot get the metadata of {:?}: {}", path, error );
                    return;
                }
            };

            let is_elf = File::open( &path ).and_then( |mut fp| {
                let mut buffer = [0; 4];
                fp.read_exact( &mut buffer )?;
                Ok( buffer )
            }).map( |buffer| {
                &buffer == b"\x7FELF"
            });
            match is_elf {
                Ok( false ) => return,
                Ok( true ) => self.add_file( &path ),
                Err( error ) => {
                    if is_toplevel {
                        warn!( "Cannot read the first four bytes of {:?}: {}", path, error );
                    }

                    return;
                }
            }
        }
    }

    fn add_file( &mut self, path: &Path ) {
        match BinaryData::load_from_fs( path ) {
            Ok( binary ) => {
                let filename = path.file_name().unwrap();
                let binary = Arc::new( binary );
                let filename_key = filename.to_string_lossy().into_owned();
                debug!( "Adding a new binary by filename: \"{}\"", filename_key );

                self.by_filename.entry( filename_key.into_bytes() ).or_default().push( binary.clone() );
                if let Some( build_id ) = binary.build_id() {
                    debug!( "Adding a new binary by build_id: {:?}", HexString( build_id ) );
                    self.by_build_id.entry( build_id.to_owned() ).or_default().push( binary.clone() );
                }
            },
            Err( error ) => {
                warn!( "Cannot read debug symbols from {:?}: {}", path, error );
                return;
            }
        }
    }
}
