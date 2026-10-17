//! Byte helpers and the file header writer.

use std::collections::BTreeMap;

use super::consts::{ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB};
use super::{Class, Endian};

/// Converts a `usize` to `u64`. A value that does not fit gives `u64::MAX`.
pub(crate) fn u64_of(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Converts a `u64` to `usize`. A value that does not fit gives `usize::MAX`.
pub(crate) fn usize_of(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Converts a `u64` to `u32`. A value that does not fit gives `u32::MAX`.
pub(crate) fn u32_of(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Converts a `u64` to `u16`. A value that does not fit gives `u16::MAX`.
pub(crate) fn u16_of(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// Rounds `value` up to a multiple of `align`. An alignment of 0 acts as 1.
pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    let unit = align.max(1);
    value.div_ceil(unit).saturating_mul(unit)
}

/// Appends a little-endian `u16`.
pub(crate) fn p16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian `u32`.
pub(crate) fn p32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian `i32`.
pub(crate) fn pi32(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian `u64`.
pub(crate) fn p64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Returns the 32-bit displacement from `next_ip` to `target`. The function drops the high bits.
pub(crate) fn rel32(target: u64, next_ip: u64) -> i32 {
    let diff = target.wrapping_sub(next_ip) & 0xffff_ffff;
    i32::from_le_bytes(u32_of(diff).to_le_bytes())
}

/// Writes `bytes` at `offset`. The function drops bytes past the end of `buf`.
pub(crate) fn put(buf: &mut [u8], offset: u64, bytes: &[u8]) {
    let start = usize_of(offset);
    let Some(end) = start.checked_add(bytes.len()) else {
        return;
    };
    if let Some(dst) = buf.get_mut(start..end) {
        dst.copy_from_slice(bytes);
    }
}

/// Reads a little-endian `u64` at `offset`, or `None` when the bytes are short.
pub(crate) fn get_u64(buf: &[u8], offset: u64) -> Option<u64> {
    let start = usize_of(offset);
    let chunk = buf.get(start..start.checked_add(8)?)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(chunk);
    Some(u64::from_le_bytes(word))
}

/// Reads a little-endian `u32` at `offset`, or `None` when the bytes are short.
pub(crate) fn get_u32(buf: &[u8], offset: u64) -> Option<u32> {
    let start = usize_of(offset);
    let chunk = buf.get(start..start.checked_add(4)?)?;
    let mut word = [0u8; 4];
    word.copy_from_slice(chunk);
    Some(u32::from_le_bytes(word))
}

/// Reads a little-endian `u16` at `offset`, or `None` when the bytes are short.
pub(crate) fn get_u16(buf: &[u8], offset: u64) -> Option<u16> {
    let start = usize_of(offset);
    let chunk = buf.get(start..start.checked_add(2)?)?;
    let mut word = [0u8; 2];
    word.copy_from_slice(chunk);
    Some(u16::from_le_bytes(word))
}

/// A string table: NUL-terminated names with the empty name at offset 0.
#[derive(Debug, Clone)]
pub(crate) struct StrTab {
    bytes: Vec<u8>,
    seen: BTreeMap<String, u32>,
}

impl StrTab {
    /// Makes a table that holds only the empty name.
    pub(crate) fn new() -> Self {
        Self {
            bytes: vec![0],
            seen: BTreeMap::new(),
        }
    }

    /// Adds `name` and returns its offset. The same name gives the same offset.
    pub(crate) fn add(&mut self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        if let Some(&offset) = self.seen.get(name) {
            return offset;
        }
        let offset = u32_of(u64_of(self.bytes.len()));
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.seen.insert(name.to_string(), offset);
        offset
    }

    /// Returns the table bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Appends `value` as an unsigned integer of `width` bytes in the byte order `endian`.
fn put_uint(buf: &mut Vec<u8>, endian: Endian, value: u64, width: usize) {
    let little = value.to_le_bytes();
    match endian {
        Endian::Little => buf.extend(little.iter().take(width)),
        Endian::Big => buf.extend(little.iter().take(width).rev()),
    }
}

/// Writes a file header with no tables.
pub(crate) fn header_only(class: Class, endian: Endian, e_type: u16, machine: u16) -> Vec<u8> {
    let (class_byte, word, ehsize, phentsize, shentsize) = match class {
        Class::Elf32 => (ELFCLASS32, 4, 52u16, 32u16, 40u16),
        Class::Elf64 => (ELFCLASS64, 8, 64, 56, 64),
    };
    let data_byte = match endian {
        Endian::Little => ELFDATA2LSB,
        Endian::Big => ELFDATA2MSB,
    };
    let mut out = b"\x7fELF".to_vec();
    out.extend_from_slice(&[class_byte, data_byte, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_uint(&mut out, endian, u64::from(e_type), 2);
    put_uint(&mut out, endian, u64::from(machine), 2);
    put_uint(&mut out, endian, 1, 4);
    put_uint(&mut out, endian, 0, word);
    put_uint(&mut out, endian, 0, word);
    put_uint(&mut out, endian, 0, word);
    put_uint(&mut out, endian, 0, 4);
    put_uint(&mut out, endian, u64::from(ehsize), 2);
    put_uint(&mut out, endian, u64::from(phentsize), 2);
    put_uint(&mut out, endian, 0, 2);
    put_uint(&mut out, endian, u64::from(shentsize), 2);
    put_uint(&mut out, endian, 0, 2);
    put_uint(&mut out, endian, 0, 2);
    out
}
