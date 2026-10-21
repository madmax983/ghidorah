//! Raw x86-64 test blobs and a test memory over their bytes.

use ghidorah_db::Program;
use ghidorah_ir::Memory;
use ghidorah_loader::LoadOpts;

use crate::support::program_of;

/// The load address of the test blobs.
pub const BASE: u64 = 0x40_0000;

/// Loads `bytes` at [`BASE`] with the entry at the blob offset `entry`.
pub fn load(bytes: &[u8], entry: u64) -> Program {
    program_of(bytes, &LoadOpts::raw(BASE, Some(BASE + entry)))
}

/// A read-only memory over the bytes of a blob at [`BASE`].
pub struct Rom<'a>(pub &'a [u8]);

impl Memory for Rom<'_> {
    fn read(&self, addr: u64) -> Option<u8> {
        let off = usize::try_from(addr.checked_sub(BASE)?).ok()?;
        self.0.get(off).copied()
    }

    fn mapped(&self, addr: u64) -> bool {
        self.read(addr).is_some()
    }
}

/// Gives `bytes` padded with `int3` up to the offset `off`.
pub fn pad(mut bytes: Vec<u8>, off: usize) -> Vec<u8> {
    assert!(bytes.len() <= off, "the blob is past {off:#x}");
    bytes.resize(off, 0xcc);
    bytes
}
