use std::collections::HashMap;
use std::sync::Arc;
use std::path::Path;

use binary::BinaryData;

pub struct DebugInfoIndex {
    by_filename: HashMap< String, Arc< BinaryData > >,
    by_build_id: HashMap< Vec< u8 >, Arc< BinaryData > >
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

    pub fn get_by_basename( &self, basename: &str ) -> Option< &Arc< BinaryData > > {
        self.by_filename.get( basename )
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
                let filename = filename.to_string_lossy().into_owned();
                let binary = Arc::new( binary );
                self.by_filename.insert( filename, binary.clone() );
                if let Some( build_id ) = binary.build_id() {
                    self.by_build_id.insert( build_id.to_owned(), binary.clone() );
                }
            },
            Err( error ) => {
                warn!( "Cannot read debug symbols from {:?}: {}", path, error );
                return;
            }
        }
    }
}
