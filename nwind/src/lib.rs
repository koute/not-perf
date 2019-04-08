#![cfg_attr(
    all(feature = "local-unwinding"),
    feature(unwind_attributes)
)]

#[cfg(feature = "log")]
#[macro_use]
extern crate log;
#[macro_use]
extern crate speedy_derive;
#[cfg(feature = "addr2line")]
extern crate addr2line;

pub extern crate proc_maps;

#[cfg(not(feature = "log"))]
macro_rules! trace { ($($token:tt)*) => {} }

#[cfg(not(feature = "log"))]
macro_rules! debug { ($($token:tt)*) => {} }

#[cfg(not(feature = "log"))]
macro_rules! warn { ($($token:tt)*) => {} }

#[cfg(not(feature = "log"))]
macro_rules! info { ($($token:tt)*) => {} }

#[cfg(not(feature = "log"))]
macro_rules! error { ($($token:tt)*) => {} }

#[cfg(not(feature = "log"))]
macro_rules! log_enabled { ($($token:tt)*) => { false } }

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
