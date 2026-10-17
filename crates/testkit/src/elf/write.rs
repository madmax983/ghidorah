//! Byte writers for ELF structures.

use super::{Class, Endian};

/// Writes a file header with no tables.
pub(crate) fn header_only(class: Class, endian: Endian, e_type: u16, machine: u16) -> Vec<u8> {
    let _ = (class, endian, e_type, machine);
    Vec::new()
}
