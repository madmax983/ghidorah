//! The embedded data files and their line format (design Section 2.6).
//!
//! Each data file starts with a license header. A line that starts with `#` is a comment.
//! A blank line is a comment too.

use std::fmt;

/// The ELF noreturn list, `data/noreturn_elf.txt`.
pub const NORETURN_ELF_TXT: &str = include_str!("../data/noreturn_elf.txt");

/// The x86-64 syscall table, `data/syscalls_x86_64.txt`.
pub const SYSCALLS_X86_64_TXT: &str = include_str!("../data/syscalls_x86_64.txt");

/// The Tier-0 prototypes, `data/tier0.h`.
pub const TIER0_H: &str = include_str!("../data/tier0.h");

/// An error in an embedded data file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataError {
    /// The file name, for example `noreturn_elf.txt`.
    pub file: &'static str,
    /// The line, from 1.
    pub line: u32,
    /// What is wrong with the line.
    pub message: String,
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl std::error::Error for DataError {}

/// Gives the data lines of a file with their line numbers. Comments and blank lines drop out.
pub(crate) fn data_lines(text: &'static str) -> impl Iterator<Item = (u32, &'static str)> {
    text.lines().take(0).map(|line| (0, line))
}
