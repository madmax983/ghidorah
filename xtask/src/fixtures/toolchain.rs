//! The host tools of the fixture build: versions, commands and file transforms.
//!
//! The build needs gcc 13, clang 18 and GNU binutils 2.42 (`readelf`, `objdump`, `strip`,
//! `objcopy`). It runs each tool with an explicit working directory, so the outputs hold no
//! absolute path.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::spec::Compiler;
use crate::{Error, proc};

/// The versions of the build tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    /// The gcc version, for example `13.3.0`.
    pub gcc: String,
    /// The clang version, for example `18.1.3`.
    pub clang: String,
    /// The binutils version, for example `2.42`.
    pub binutils: String,
    /// The GCC installation that gcc uses, for example `/usr/lib/gcc/x86_64-linux-gnu/13`.
    ///
    /// clang takes the newest GCC installation that it finds. A host with several GCC
    /// versions then gives other crt and libgcc bytes. The build pins clang to this one.
    pub gcc_dir: String,
}

impl Tools {
    /// Gives the version of a compiler.
    #[must_use]
    pub fn compiler(&self, c: Compiler) -> &str {
        match c {
            Compiler::Gcc => &self.gcc,
            Compiler::Clang => &self.clang,
        }
    }

    /// Gives the tool versions for the manifest.
    #[must_use]
    pub fn map(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("binutils".to_owned(), self.binutils.clone()),
            ("clang".to_owned(), self.clang.clone()),
            ("gcc".to_owned(), self.gcc.clone()),
        ])
    }
}

/// Gives the first word of `text` that starts with a digit and holds a dot.
fn version_word(text: &str) -> Option<String> {
    text.lines()
        .next()?
        .split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.'))
        .map(str::to_owned)
}

fn tool_version(program: &str, args: &[&str]) -> Result<String, Error> {
    let out = proc::run_ok(Command::new(program).args(args))?;
    version_word(&out.stdout).ok_or_else(|| Error::data(program, "no version in the output"))
}

/// Gives the extra driver flags of a compiler.
///
/// clang gets `--gcc-install-dir` with the GCC installation of gcc, so both drivers link the
/// same crt files and libgcc.
#[must_use]
pub fn driver_flags(compiler: Compiler, gcc_dir: &str) -> Vec<String> {
    match compiler {
        Compiler::Gcc => Vec::new(),
        Compiler::Clang => vec![format!("--gcc-install-dir={gcc_dir}")],
    }
}

/// Finds the GCC installation directory of gcc from the path of its libgcc.
fn gcc_install_dir() -> Result<String, Error> {
    let out = proc::run_ok(Command::new("gcc").arg("-print-libgcc-file-name"))?;
    let lib = out.stdout.trim();
    Path::new(lib)
        .parent()
        .map(|d| d.display().to_string())
        .filter(|d| !d.is_empty())
        .ok_or_else(|| Error::data("gcc", "no directory in the libgcc path"))
}

/// Finds the build tools and their versions.
///
/// # Errors
///
/// Returns [`Error::Command`] when a tool is missing, or [`Error::Data`] for an unknown output.
pub fn detect() -> Result<Tools, Error> {
    let gcc = proc::run_ok(Command::new("gcc").arg("-dumpfullversion"))?
        .stdout
        .trim()
        .to_owned();
    Ok(Tools {
        gcc,
        clang: tool_version("clang", &["--version"])?,
        binutils: tool_version("readelf", &["--version"])?
            .trim_end_matches(')')
            .to_owned(),
        gcc_dir: gcc_install_dir()?,
    })
}

/// Runs a program in a directory and gives its standard output.
///
/// # Errors
///
/// Returns [`Error::Command`] when the program does not start or exits with another code than 0.
pub fn run_in(dir: &Path, program: &str, args: &[String]) -> Result<String, Error> {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(dir);
    Ok(proc::run_ok(&mut cmd)?.stdout)
}

/// Runs a fixture binary and gives its standard output and exit code.
///
/// # Errors
///
/// Returns [`Error::Command`] when the binary does not start.
pub fn run_fixture(path: &Path, args: &[String]) -> Result<(String, Option<i32>), Error> {
    let mut cmd = Command::new(path);
    cmd.args(args);
    if let Some(dir) = path.parent() {
        cmd.current_dir(dir);
    }
    let out = proc::run(&mut cmd)?;
    Ok((out.stdout, out.code))
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
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
    let shoff = read_u64(bytes, 0x28).ok_or("short ELF header")?;
    let entsize = read_u16(bytes, 0x3a).ok_or("short ELF header")?;
    let count = read_u16(bytes, 0x3c).ok_or("short ELF header")?;
    let start = usize::try_from(shoff).map_err(|e| e.to_string())?;
    let table = usize::from(entsize) * usize::from(count);
    if start.checked_add(table) != Some(bytes.len()) {
        return Err("the section header table is not at the end of the file".to_owned());
    }
    let mut out = bytes.get(..start).ok_or("short file")?.to_vec();
    for range in [0x28..0x30, 0x3c..0x40] {
        if let Some(slot) = out.get_mut(range) {
            slot.fill(0);
        }
    }
    Ok(out)
}
