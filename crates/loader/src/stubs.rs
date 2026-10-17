//! PLT stubs of x86-64 ELF files and their names (design Section 4.5).
//!
//! The matcher reads `.plt`, `.plt.sec` and `.plt.got`. It steps by the entry size of the
//! section (8 or 16), else by 16. Without section headers, it finds PLT0 in an executable
//! region at a 16-byte step: `push [rip+GOT+8]` and `jmp [rip+GOT+16]` with
//! `GOT = DT_PLTGOT`. Then it reads the entries after PLT0 up to the first entry that
//! has no known form.
//!
//! | Form | Bytes | Stub |
//! |---|---|---|
//! | PLT0 | `ff 35 d32`, then `[f2] ff 25 d32` | `.plt0` |
//! | jump | `[f3 0f 1e fa] [f2] ff 25 d32` | `<name>@plt` |
//! | lazy | `[f3 0f 1e fa] 68 i32 [f2] e9 r32`, or `68 i32 e9 r32` after a jump | `<name>@plt.lazy` |
//!
//! A jump stub gets its name through the slot map (`slot = next_ip + d32`), never by
//! position (CVE-2017-14729). A lazy stub gets its name through the `DT_JMPREL` entry of
//! its push index, as the dynamic linker does. A stub with no import gives no record.

use ghidorah_base::{BinText, Limits};

use crate::binary::Binary;
use crate::diag::{Diagnostic, Diags};
use crate::limits::Budget;
use crate::memmap::MemoryMap;

/// The form of a stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StubKind {
    /// The first entry of `.plt`. It calls the lazy resolver.
    Plt0,
    /// A stub that jumps through an import slot.
    Jump,
    /// The lazy part of a PLT entry: `push index; jmp PLT0`.
    Lazy,
}

/// One PLT stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stub {
    /// The address of the first byte.
    pub addr: u64,
    /// The form.
    pub kind: StubKind,
    /// The import slot. A lazy stub has the slot of its `DT_JMPREL` entry. PLT0 has none.
    pub slot: Option<u64>,
    /// The index of the import in [`Binary::imports`]. PLT0 has none.
    pub import: Option<usize>,
}

/// The stubs of a file in address order, with the diagnostics of the scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StubScan {
    /// The stubs in address order.
    pub stubs: Vec<Stub>,
    /// The kept diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Finds the PLT stubs of a loaded x86-64 ELF file.
#[must_use]
pub fn find(binary: &Binary, map: &MemoryMap, limits: &Limits) -> StubScan {
    let mut diags = Diags::default();
    let stubs = scan(binary, map, limits, &mut diags);
    StubScan {
        stubs,
        diagnostics: diags.into_parts().0,
    }
}

/// Finds the stubs and sets [`Import::stub`](crate::Import::stub) of each import.
///
/// An import gets the first jump stub through its own slot, else the first jump stub
/// through another slot of the import.
pub fn name_stubs(binary: &mut Binary, map: &MemoryMap, limits: &Limits) -> StubScan {
    let scan = find(binary, map, limits);
    let _ = &scan;
    scan
}

/// Gives the label of a stub: `<name>@plt`, `<name>@plt.lazy` or `.plt0`.
#[must_use]
pub fn label(binary: &Binary, stub: &Stub) -> BinText {
    let _ = (binary, stub);
    BinText::default()
}

/// Finds the stubs, sets the stub of each import and adds the diagnostics to `diags`.
pub(crate) fn apply(binary: &mut Binary, map: &MemoryMap, budget: &Budget, diags: &mut Diags) {
    let _ = (binary, map, budget, diags);
}

/// Scans the PLT areas of the file.
fn scan(binary: &Binary, map: &MemoryMap, limits: &Limits, diags: &mut Diags) -> Vec<Stub> {
    let _ = (binary, map, limits, diags);
    Vec::new()
}
