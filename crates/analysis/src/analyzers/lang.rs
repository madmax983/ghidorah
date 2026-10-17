//! Language hints of `binary_survey.languages` (design Section 9.6).
//!
//! The hints are derived data of the input: they read the symbols, the imports and the section
//! names. They have no band and no work state.
//!
//! | Language | Evidence |
//! |---|---|
//! | C++ | a name that starts with `_Z` and is not a Rust name, a name that starts with `__cxa_` except `__cxa_finalize`, `__gxx_personality_v0` |
//! | Rust | a name that starts with `_R`, a `_ZN` name that ends with `17h`, 16 hex digits and `E`, a name with `rust_panic`, `rust_begin_unwind` or `rust_eh_personality` |
//! | Go | a name that starts with `runtime.`, the sections `.gopclntab`, `.go.buildinfo` and `.note.go.buildid` |
//!
//! The count of a language is the number of distinct names with its evidence, plus one for each
//! distinct section. The names come from the symbol tables and the imports, without a symbol
//! version after `@`. The C runtime of every ELF file imports `__cxa_finalize`, so it is no
//! evidence. A hint with a count of 0 does not exist.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_db::Program;

/// The hint text of each language: no demangler is in the MVP.
pub const HINT: &str = "Names are not demangled in this version.";

/// The largest number of example names of one hint.
pub const MAX_EXAMPLES: usize = 3;

/// The parts of a name that show Rust code.
const RUST_PARTS: [&str; 3] = ["rust_panic", "rust_begin_unwind", "rust_eh_personality"];

/// The sections of Go files.
const GO_SECTIONS: [&str; 3] = [".gopclntab", ".go.buildinfo", ".note.go.buildid"];

/// A source language that a binary can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lang {
    /// C++.
    Cpp,
    /// Rust.
    Rust,
    /// Go.
    Go,
}

impl Lang {
    /// All languages in output order.
    pub const ALL: [Self; 3] = [Self::Cpp, Self::Rust, Self::Go];

    /// Gives the output name: `c++`, `rust` or `go`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpp => "c++",
            Self::Rust => "rust",
            Self::Go => "go",
        }
    }
}

/// The hint of one language.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LangHint {
    /// The language.
    pub lang: Lang,
    /// The number of names and sections with evidence.
    pub count: u64,
    /// The first names with evidence in byte order, at most [`MAX_EXAMPLES`].
    pub examples: Vec<String>,
}

/// Tells if `name` ends with the hash of the old Rust form: `17h`, 16 hex digits and `E`.
fn rust_hash(name: &str) -> bool {
    let Some(body) = name.strip_suffix('E') else {
        return false;
    };
    let Some(cut) = body.len().checked_sub(19) else {
        return false;
    };
    body.get(cut..).is_some_and(|tail| {
        tail.strip_prefix("17h")
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// Gives the language of the evidence in the name `name`, or `None` for no evidence.
#[must_use]
pub fn classify(name: &str) -> Option<Lang> {
    if name.starts_with("_R")
        || RUST_PARTS.iter().any(|p| name.contains(p))
        || (name.starts_with("_ZN") && rust_hash(name))
    {
        return Some(Lang::Rust);
    }
    let cxa = name.starts_with("__cxa_") && name != "__cxa_finalize";
    if name.starts_with("_Z") || cxa || name == "__gxx_personality_v0" {
        return Some(Lang::Cpp);
    }
    name.starts_with("runtime.").then_some(Lang::Go)
}

/// Gives the language of the section named `name`, or `None` for no evidence.
#[must_use]
pub fn section_lang(name: &str) -> Option<Lang> {
    GO_SECTIONS.contains(&name).then_some(Lang::Go)
}

/// Gives the hints of `program` in the order of [`Lang::ALL`].
#[must_use]
pub fn hints(program: &Program) -> Vec<LangHint> {
    let b = program.binary();
    let mut found: BTreeMap<Lang, BTreeSet<String>> = BTreeMap::new();
    let names = b
        .symbols
        .iter()
        .map(|s| &s.name)
        .chain(b.imports.iter().filter_map(|i| i.name.as_ref()));
    for name in names {
        let text = name
            .as_str()
            .map(|t| t.split_once('@').map_or(t, |(head, _)| head));
        if let Some(text) = text
            && let Some(lang) = classify(text)
        {
            found.entry(lang).or_default().insert(text.to_owned());
        }
    }
    for s in &b.sections {
        if let Some(text) = s.name.as_str()
            && let Some(lang) = section_lang(text)
        {
            found.entry(lang).or_default().insert(text.to_owned());
        }
    }
    Lang::ALL
        .into_iter()
        .filter_map(|lang| {
            let set = found.remove(&lang)?;
            Some(LangHint {
                lang,
                count: u64::try_from(set.len()).unwrap_or(u64::MAX),
                examples: set.into_iter().take(MAX_EXAMPLES).collect(),
            })
        })
        .collect()
}
