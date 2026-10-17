//! The renderers of the read tools: the sections of `func_get`, the disassembly rows, the
//! names and the binary text (design Sections 5.4, 9.6, 10.4, 10.9 and 10.16).
//!
//! A disassembly row is `{ a, n, b, m, t, f, c? }`: the address, the length, the bytes in
//! hex, the canonical mnemonic, the display text, the flow kind and the comments at the
//! address. `func_get` and `mem_read { as: "insn" }` give the same rows (AC-216).

/// The output names of the row members in row order.
pub const ROW_MEMBERS: [&str; 7] = ["a", "n", "b", "m", "t", "f", "c"];

/// Every fixed text of the renderers that an agent reads.
pub const TEXTS: &[&str] = &[];
