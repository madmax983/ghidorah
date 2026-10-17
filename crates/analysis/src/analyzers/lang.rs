//! Language hints of `binary_survey.languages` (design Section 9.6).
//!
//! The hints are derived data of the input: they read the symbols, the imports and the section
//! names. They have no band and no work state.
//!
//! | Language | Evidence |
//! |---|---|
//! | C++ | a symbol or import that starts with `_Z` and is not a Rust name, an import that starts with `__cxa_`, `__gxx_personality_v0` |
//! | Rust | a symbol that starts with `_R`, a `_ZN` name that ends with `17h` and 16 hex digits and `E`, a name with `rust_panic`, `rust_begin_unwind` or `rust_eh_personality` |
//! | Go | a symbol that starts with `runtime.`, the sections `.gopclntab`, `.go.buildinfo` and `.note.go.buildid` |
//!
//! The count of a language is the number of distinct names with its evidence, plus one for each
//! section. A hint with a count of 0 does not exist.

use ghidorah_db::Program;

/// The hint text of each language: no demangler is in the MVP.
pub const HINT: &str = "Names are not demangled in this version.";

/// The largest number of example names of one hint.
pub const MAX_EXAMPLES: usize = 3;

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

/// Gives the language of the evidence in the name `name`, or `None` for no evidence.
#[must_use]
pub fn classify(name: &str) -> Option<Lang> {
    let _ = name;
    None
}

/// Gives the language of the section named `name`, or `None` for no evidence.
#[must_use]
pub fn section_lang(name: &str) -> Option<Lang> {
    let _ = name;
    None
}

/// Gives the hints of `program` in the order of [`Lang::ALL`].
#[must_use]
pub fn hints(program: &Program) -> Vec<LangHint> {
    let _ = program;
    Vec::new()
}
