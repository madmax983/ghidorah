//! A small x86-64 writer for raw test blobs, and the raw loads of the tests.

use ghidorah_db::Program;
use ghidorah_loader::LoadOpts;

use crate::support::program_of;

/// The load address of the test blobs.
pub const BASE: u64 = 0x40_0000;

/// A raw x86-64 blob. Offsets are relative to [`BASE`].
#[derive(Debug, Clone, Default)]
pub struct Blob {
    bytes: Vec<u8>,
}

impl Blob {
    /// Makes an empty blob.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pads the blob with `int3` up to the offset `off`.
    pub fn at(mut self, off: u64) -> Self {
        let off = usize::try_from(off).expect("a small offset");
        assert!(self.bytes.len() <= off, "the blob is past {off:#x}");
        self.bytes.resize(off, 0xcc);
        self
    }

    fn here(&self) -> i64 {
        i64::try_from(self.bytes.len()).expect("a small blob")
    }

    fn rel32(mut self, opcode: &[u8], target: u64) -> Self {
        let end = self.here() + i64::try_from(opcode.len()).expect("short") + 4;
        let rel = i64::try_from(target).expect("a small target") - end;
        let rel = i32::try_from(rel).expect("a near target");
        self.bytes.extend_from_slice(opcode);
        self.bytes.extend_from_slice(&rel.to_le_bytes());
        self
    }

    /// `call target`.
    pub fn call(self, target: u64) -> Self {
        self.rel32(&[0xe8], target)
    }

    /// `jmp target`.
    pub fn jmp(self, target: u64) -> Self {
        self.rel32(&[0xe9], target)
    }

    /// `je target`.
    pub fn je(self, target: u64) -> Self {
        self.rel32(&[0x0f, 0x84], target)
    }

    /// `jmp [rip+slot]` with `slot` relative to [`BASE`].
    pub fn jmp_slot(self, slot: u64) -> Self {
        self.rel32(&[0xff, 0x25], slot)
    }

    /// `jmp rax`.
    pub fn jmp_rax(mut self) -> Self {
        self.bytes.extend_from_slice(&[0xff, 0xe0]);
        self
    }

    /// Any raw bytes.
    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.bytes.extend_from_slice(bytes);
        self
    }

    /// `ret`.
    pub fn ret(self) -> Self {
        self.raw(&[0xc3])
    }

    /// `hlt`.
    pub fn hlt(self) -> Self {
        self.raw(&[0xf4])
    }

    /// `endbr64`.
    pub fn endbr(self) -> Self {
        self.raw(&[0xf3, 0x0f, 0x1e, 0xfa])
    }

    /// `mov eax, imm`.
    pub fn mov_eax(self, imm: u32) -> Self {
        let mut b = vec![0xb8];
        b.extend_from_slice(&imm.to_le_bytes());
        self.raw(&b)
    }

    /// Loads the blob at [`BASE`] with the entry at `entry` (relative to [`BASE`]).
    pub fn load(&self, entry: Option<u64>) -> Program {
        program_of(&self.bytes, &LoadOpts::raw(BASE, entry.map(|e| BASE + e)))
    }
}
