#![cfg_attr(
    all(feature = "local-unwinding"),
    feature(unwind_attributes)
)]

#[cfg(feature = "log")]
extern crate log;

#[macro_use]
extern crate speedy_derive;
#[cfg(feature = "addr2line")]
extern crate addr2line;

pub extern crate proc_maps;

#[allow(unused_macros)]
#[cfg(any(not(feature = "log"), not(feature = "debug-logs")))]
macro_rules! trace { ($($token:expr),*) => {{ $( let _ = &$token; )+ }} }

#[cfg(any(not(feature = "log"), not(feature = "debug-logs")))]
macro_rules! debug { ($($token:expr),*) => {{ $( let _ = &$token; )+ }} }

#[allow(unused_macros)]
#[cfg(not(feature = "log"))]
macro_rules! info { ($($token:expr),*) => {{ $( let _ = &$token; )+ }} }

#[cfg(not(feature = "log"))]
macro_rules! warn { ($($token:expr),*) => {{ $( let _ = &$token; )+ }} }

#[cfg(not(feature = "log"))]
macro_rules! error { ($($token:expr),*) => {{ $( let _ = &$token; )+ }} }

#[cfg(any(not(feature = "log"), not(feature = "debug-logs")))]
macro_rules! debug_logs_enabled { () => { false } }


#[allow(unused_macros)]
#[cfg(all(feature = "log", feature = "debug-logs"))]
macro_rules! trace { ($($token:expr),*) => { log::trace!( $($token),* ) } }

#[cfg(all(feature = "log", feature = "debug-logs"))]
macro_rules! debug { ($($token:expr),*) => { log::debug!( $($token),* ) } }

#[allow(unused_macros)]
#[cfg(feature = "log")]
macro_rules! info { ($($token:expr),*) => { log::info!( $($token),* ) } }

#[cfg(feature = "log")]
macro_rules! warn { ($($token:expr),*) => { log::warn!( $($token),* ) } }

#[cfg(feature = "log")]
macro_rules! error { ($($token:expr),*) => { log::error!( $($token),* ) } }

#[cfg(all(feature = "log", feature = "debug-logs"))]
macro_rules! debug_logs_enabled { () => { log::log_enabled!( log::Level::Debug ) } }

#[macro_use]
mod elf;

mod address_space;
pub mod arch;
mod arm_extab;
mod binary;
mod dwarf;
mod dwarf_regs;
mod frame_descriptions;
mod range_map;
mod symbols;
mod types;
pub mod utils;
mod unwind_context;
mod debug_info_index;
#[cfg(feature = "local-unwinding")]
mod local_unwinding;
mod interner;

pub use crate::address_space::{
    BufferReader,
    Primitive,
    IAddressSpace,
    AddressSpace,
    Frame
};
pub use crate::dwarf_regs::DwarfRegs;
pub use crate::range_map::RangeMap;
pub use crate::binary::{BinaryData, BinaryDataReader, SymbolTable, LoadHeader};
pub use crate::symbols::Symbols;
pub use crate::types::{
    Inode,
    Bitness,
    UserFrame,
    BinaryId
};

pub use crate::debug_info_index::DebugInfoIndex;
pub use crate::frame_descriptions::LoadHint;

#[cfg(feature = "local-unwinding")]
pub use crate::local_unwinding::{
    LocalAddressSpace,
    LocalAddressSpaceOptions,
    UnwindControl,
    nwind_on_ret_trampoline,
    nwind_ret_trampoline_personality,

    _Unwind_RaiseException
};

pub use crate::interner::{StringInterner, StringId};
