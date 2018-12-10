use std::collections::HashMap;
use std::sync::Arc;
use std::path::Path;

use binary::BinaryData;

pub struct DebugInfoIndex {
    by_filename: HashMap< Vec< u8 >, Vec< Arc< BinaryData > > >,
    by_build_id: HashMap< Vec< u8 >, Vec< Arc< BinaryData > > >
}

fn check_build_id< 'a >( data: &'a Arc< BinaryData >, expected_build_id: Option< &[u8] > ) -> bool {
    let build_id = data.build_id();
    expected_build_id.is_none() || build_id.is_none() || build_id == expected_build_id
}

impl DebugInfoIndex {
    pub fn new() -> Self {
        DebugInfoIndex {
            by_filename: HashMap::new(),
            by_build_id: HashMap::new()
        }
    }

    pub fn add< P: AsRef< Path > >( &mut self, path: P ) {
        self.add_impl( path.as_ref() );
    }

    pub fn get( &self, basename: &str, debuglink: Option< &[u8] >, build_id: Option< &[u8] > ) -> Option< &Arc< BinaryData > > {
        let (bin, dbg) = self.get_pair( basename, debuglink, build_id );
        dbg.or( bin )
    }

    pub fn get_pair( &self, basename: &str, debuglink: Option< &[u8] >, build_id: Option< &[u8] > ) -> (Option< &Arc< BinaryData > >, Option< &Arc< BinaryData > >) {
        let basename: &[u8] = basename.as_ref();

        let mut candidates = Vec::new();
        if let Some( build_id ) = build_id {
            if let Some( entries ) = self.by_build_id.get( build_id ) {
                candidates.extend( entries );

                for entry in entries {
                    if let Some( debuglink ) = entry.debuglink() {
                        if let Some( debug_entries ) = self.by_filename.get( debuglink ) {
                            candidates.extend( debug_entries.iter().filter( |data| check_build_id( data, Some( build_id ) ) ) );
                        }
                    }
                }
            }
        }

        if let Some( entries ) = self.by_filename.get( basename ) {
            candidates.extend( entries.iter().filter( |data| check_build_id( data, build_id ) ) );

            for entry in entries {
                if let Some( debuglink ) = entry.debuglink() {
                    if let Some( debug_entries ) = self.by_filename.get( debuglink ) {
                        candidates.extend( debug_entries.iter().filter( |data| check_build_id( data, build_id ) ) );
                    }
                }
            }
        }

        if let Some( debuglink ) = debuglink {
            if let Some( entries ) = self.by_filename.get( debuglink ) {
                candidates.extend( entries.iter().filter( |data| check_build_id( data, build_id ) ) );
            }
        }

        candidates.sort_by_key( |entry| entry.as_ptr() );
        candidates.dedup_by_key( |entry| entry.as_ptr() );
        let matching: Vec< _ > = candidates.iter().filter( |entry| entry.build_id().is_some() && entry.build_id() == build_id ).cloned().collect();
        if !matching.is_empty() {
            candidates = matching;
        }

        match candidates.len() {
            0 => return (None, None),
            1 => return (candidates.pop(), None),
            _ => {
                candidates.sort_by_key( |entry| entry.as_bytes().len() );
                let dbg = candidates.pop();
                let bin = candidates.pop();
                (bin, dbg)
            }
        }
    }

    fn add_impl( &mut self, path: &Path ) {
        if !path.exists() {
            return;
        }

        if path.is_dir() {
            let dir = match path.read_dir() {
                Ok( dir ) => dir,
                Err( error ) => {
                    warn!( "Cannot read debug symbols from {:?}: {}", path, error );
                    return;
                }
            };

            for entry in dir {
                if let Ok( entry ) = entry {
                    self.add_file( &entry.path() );
                }
            }
        } else {
            self.add_file( path );
        }
    }

    fn add_file( &mut self, path: &Path ) {
        match BinaryData::load_from_fs( path ) {
            Ok( binary ) => {
                let filename = path.file_name().unwrap();
                let binary = Arc::new( binary );
                self.by_filename.entry( filename.to_string_lossy().into_owned().into_bytes() ).or_default().push( binary.clone() );
                if let Some( build_id ) = binary.build_id() {
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
