//! Lists of functions that do not return (design Section 7.7).
//!
//! A list name has no leading underscore. The match removes a symbol version
//! (`@GLIBC_2.2.5`) and the leading underscores of a name first. So `__stack_chk_fail`
//! matches `stack_chk_fail`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::data::{DataError, NORETURN_ELF_TXT, data_lines, error};

/// A list of function names that do not return.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoreturnList {
    names: BTreeSet<&'static str>,
}

impl NoreturnList {
    /// Parses a list file. Each data line holds one name.
    ///
    /// # Errors
    ///
    /// Returns [`DataError`] for a name with a leading underscore, a character outside
    /// `[A-Za-z0-9_]` or a name that comes twice.
    pub fn parse(file: &'static str, text: &'static str) -> Result<Self, DataError> {
        let mut names = BTreeSet::new();
        for (line, name) in data_lines(text) {
            let good = !name.starts_with('_')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !good {
                return Err(error(file, line, format!("bad name `{name}`")));
            }
            if !names.insert(name) {
                return Err(error(file, line, format!("`{name}` comes twice")));
            }
        }
        Ok(Self { names })
    }

    /// Tells if the function `name` does not return.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(match_name(name))
    }

    /// Gives the names in byte order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.names.iter().copied()
    }

    /// Gives the number of names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Tells if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Gives the name part that a list match uses: no symbol version and no leading underscore.
#[must_use]
pub fn match_name(name: &str) -> &str {
    let bare = name.split_once('@').map_or(name, |(head, _)| head);
    bare.trim_start_matches('_')
}

/// Gives the ELF list of `data/noreturn_elf.txt`.
///
/// # Errors
///
/// Returns the [`DataError`] of the embedded file.
pub fn elf() -> Result<&'static NoreturnList, &'static DataError> {
    static LIST: OnceLock<Result<NoreturnList, DataError>> = OnceLock::new();
    LIST.get_or_init(|| NoreturnList::parse("noreturn_elf.txt", NORETURN_ELF_TXT))
        .as_ref()
}
