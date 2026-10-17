//! The host tools of the fixture build: versions, commands and file transforms.
//!
//! The build needs gcc 13, clang 18 and GNU binutils 2.42 (`readelf`, `objdump`, `strip`,
//! `objcopy`). It runs each tool with an explicit working directory, so the outputs hold no
//! absolute path.

use std::collections::BTreeMap;
use std::path::Path;

use super::spec::Compiler;
use crate::Error;

/// The versions of the build tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    /// The gcc version, for example `13.3.0`.
    pub gcc: String,
    /// The clang version, for example `18.1.3`.
    pub clang: String,
    /// The binutils version, for example `2.42`.
    pub binutils: String,
}

impl Tools {
    /// Gives the version of a compiler.
    #[must_use]
    pub fn compiler(&self, c: Compiler) -> &str {
        let _ = c;
        ""
    }

    /// Gives the tool versions for the manifest.
    #[must_use]
    pub fn map(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}

/// Finds the build tools and their versions.
///
/// # Errors
///
/// Returns [`Error::Command`] when a tool is missing, or [`Error::Data`] for an unknown output.
pub fn detect() -> Result<Tools, Error> {
    Err(Error::data("toolchain", "no tool search yet"))
}

/// Runs a program in a directory and gives its standard output.
///
/// # Errors
///
/// Returns [`Error::Command`] when the program does not start or exits with another code than 0.
pub fn run_in(dir: &Path, program: &str, args: &[String]) -> Result<String, Error> {
    Err(Error::data(
        dir.display().to_string(),
        format!("no run of {program} {args:?} yet"),
    ))
}

/// Runs a fixture binary and gives its standard output and exit code.
///
/// # Errors
///
/// Returns [`Error::Command`] when the binary does not start.
pub fn run_fixture(path: &Path, args: &[String]) -> Result<(String, Option<i32>), Error> {
    Err(Error::data(
        path.display().to_string(),
        format!("no run with {args:?} yet"),
    ))
}

/// Removes the section header table of an ELF64 file (the `noshdr` variant).
///
/// The table must sit at the end of the file, as GNU ld writes it. The function cuts the file
/// at `e_shoff` and sets `e_shoff`, `e_shnum` and `e_shstrndx` to 0.
///
/// # Errors
///
/// Returns a message when the header is short or the table is not at the end of the file.
pub fn drop_section_headers(bytes: &[u8]) -> Result<Vec<u8>, String> {
    Err(format!("no transform yet ({} bytes)", bytes.len()))
}
