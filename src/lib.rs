#[macro_use]
extern crate log;
#[macro_use]
extern crate speedy_derive;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

mod args;
mod archive;
mod stack_reader;
mod raw_data;
mod cmd_collate;
mod cmd_metadata;
mod kallsyms;
mod utils;
mod metadata;

pub use crate::archive::*;
pub use crate::stack_reader::StackReader;
pub use crate::cmd_collate::collapse_into_sorted_vec;
pub use crate::cmd_metadata::generate_metadata;
pub use crate::metadata::Metadata;
pub use crate::args::{MetadataArgs, SharedCollationArgs};
