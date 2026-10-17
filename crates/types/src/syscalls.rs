//! The x86-64 Linux syscall table (design Section 7.11).
//!
//! The analysis reads the number in `rax` at a `syscall` site. The table gives the name.
//! The arguments use the registers of [`ARG_REGS`].

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ghidorah_base::SyscallId;

use crate::data::{DataError, SYSCALLS_X86_64_TXT, data_lines, error};

/// The register that holds the syscall number.
pub const NUMBER_REG: &str = "rax";

/// The argument registers of a syscall in order.
pub const ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

/// A syscall table: numbers and names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyscallTable {
    by_number: BTreeMap<u16, &'static str>,
    by_name: BTreeMap<&'static str, u16>,
}

impl SyscallTable {
    /// Parses a table file. Each data line holds a decimal number and a name.
    ///
    /// # Errors
    ///
    /// Returns [`DataError`] for a bad number, a name outside `[a-z_][a-z0-9_]*`, or a number
    /// or a name that comes twice.
    pub fn parse(file: &'static str, text: &'static str) -> Result<Self, DataError> {
        let mut table = Self::default();
        for (line, data) in data_lines(text) {
            let mut words = data.split_whitespace();
            let (Some(number), Some(name), None) = (words.next(), words.next(), words.next())
            else {
                return Err(error(file, line, "a line holds a number and a name"));
            };
            let Ok(number) = number.parse::<u16>() else {
                return Err(error(file, line, format!("bad number `{number}`")));
            };
            if SyscallId::by_name(name).is_err() {
                return Err(error(file, line, format!("bad name `{name}`")));
            }
            if table.by_number.contains_key(&number) || table.by_name.contains_key(name) {
                return Err(error(file, line, format!("`{number} {name}` comes twice")));
            }
            table.by_number.insert(number, name);
            table.by_name.insert(name, number);
        }
        Ok(table)
    }

    /// Gives the name of the syscall `number`.
    #[must_use]
    pub fn name(&self, number: u64) -> Option<&'static str> {
        let number = u16::try_from(number).ok()?;
        self.by_number.get(&number).copied()
    }

    /// Gives the number of the syscall `name`.
    #[must_use]
    pub fn number(&self, name: &str) -> Option<u16> {
        self.by_name.get(name).copied()
    }

    /// Gives the syscalls in number order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &'static str)> + '_ {
        self.by_number.iter().map(|(n, s)| (*n, *s))
    }

    /// Gives the number of syscalls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    /// Tells if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }
}

/// Gives the x86-64 table of `data/syscalls_x86_64.txt`.
///
/// # Errors
///
/// Returns the [`DataError`] of the embedded file.
pub fn x86_64() -> Result<&'static SyscallTable, &'static DataError> {
    static TABLE: OnceLock<Result<SyscallTable, DataError>> = OnceLock::new();
    TABLE
        .get_or_init(|| SyscallTable::parse("syscalls_x86_64.txt", SYSCALLS_X86_64_TXT))
        .as_ref()
}
