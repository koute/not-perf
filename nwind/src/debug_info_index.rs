use std::collections::HashMap;
use std::sync::Arc;
use std::path::Path;

use binary::BinaryData;

pub struct DebugInfoIndex {
    by_filename: HashMap< Vec< u8 >, Arc< BinaryData > >,
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

    pub fn get( &self, basename: &str, debuglink: Option< &[u8] >, build_id: Option< &[u8] > ) -> Option< &Arc< BinaryData > > {
        let basename: &[u8] = basename.as_ref();
        if let Some( debuglink ) = debuglink {
            if let Some( data ) = self.by_filename.get( debuglink ) {
                if build_id == data.build_id() {
                    return Some( data );
                }
            }
        }

        let data = self.by_filename.get( basename )?;
        if build_id == data.build_id() {
            return Some( data );
        }

        if let Some( build_id ) = build_id {
            if let Some( data ) = self.by_build_id.get( build_id ) {
                return Some( data );
            }
        }

        None
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
                self.by_filename.insert( filename.to_string_lossy().into_owned().into_bytes(), binary.clone() );
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
