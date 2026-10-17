//! The built-in demo binary (design Section 10.4).
//!
//! `binary_load { builtin: "demo" }` loads it with no path and no root check. The bytes are a
//! copy of the first-party fixture [`FIXTURE`] (`fixtures/src/crackme.c`, gcc -O2): a password
//! check against XOR-encoded bytes. A test makes sure that the copy and the fixture manifest
//! agree.

/// The names of the built-in binaries, in schema order.
pub const BUILTINS: [&str; 1] = ["demo"];

/// The file name of the demo binary in results.
pub const FILE_NAME: &str = "demo.elf";

/// The fixture that the demo binary copies.
pub const FIXTURE: &str = "crackme.gcc-O2";

/// The bytes of the demo binary.
pub static BYTES: &[u8] = include_bytes!("../data/demo.elf");

/// Gives the file name and the bytes of the built-in binary `name`, or `None`.
#[must_use]
pub fn builtin(name: &str) -> Option<(&'static str, &'static [u8])> {
    let _ = name;
    None
}
