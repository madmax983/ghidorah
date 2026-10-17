//! The Tier-0 prototype database (design Section 9.4).
//!
//! `data/tier0.h` holds about 150 hand-written libc prototypes. Each line holds one prototype
//! in the `sig` mode of the C parser and a line comment with a category and attributes.
//! The file header gives the attribute grammar. The index keys are linked names, for example
//! `__isoc23_scanf`, `__printf_chk` and `open64`. A lookup removes a symbol version first.

mod attrs;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use crate::cparse::{CParseError, parse_sig};
use crate::data::TIER0_H;
use crate::store::TypeStore;
use crate::ty::{Sig, TypeId};

/// The capability category of a prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Files and directories.
    File,
    /// Sockets and name lookup.
    Network,
    /// Processes, threads, signals and the C runtime.
    Process,
    /// Heap and memory blocks.
    Memory,
    /// Strings and characters.
    String,
    /// Random numbers and password hashes.
    Crypto,
    /// The environment, users and the host.
    Environment,
    /// Debugger detection.
    AntiDebug,
    /// Clocks and sleeps.
    Time,
    /// Streams and terminal input and output.
    Io,
}

impl Category {
    /// All categories in order.
    pub const ALL: [Self; 10] = [
        Self::File,
        Self::Network,
        Self::Process,
        Self::Memory,
        Self::String,
        Self::Crypto,
        Self::Environment,
        Self::AntiDebug,
        Self::Time,
        Self::Io,
    ];

    /// Gives the category name of the data file, for example `anti_debug`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Network => "network",
            Self::Process => "process",
            Self::Memory => "memory",
            Self::String => "string",
            Self::Crypto => "crypto",
            Self::Environment => "environment",
            Self::AntiDebug => "anti_debug",
            Self::Time => "time",
            Self::Io => "io",
        }
    }

    /// Finds the category with the name `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// The kind of a format string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FmtKind {
    /// A `printf` format.
    Printf,
    /// A `scanf` format.
    Scanf,
}

/// A format string parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fmt {
    /// The format kind.
    pub kind: FmtKind,
    /// The parameter number of the format string, from 1.
    pub index: u16,
}

/// One effect of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// The function reads parameter `.0` as a C string.
    ReadsStr(u16),
    /// The function writes the buffer of parameter `arg`.
    Writes {
        /// The parameter number of the buffer.
        arg: u16,
        /// The parameter number of the length, if one exists.
        len_arg: Option<u16>,
    },
    /// The function returns new heap memory.
    Allocates,
    /// The function returns parameter `.0`.
    ReturnsArg(u16),
}

/// The attributes of a prototype.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attrs {
    /// The function does not return.
    pub noreturn: bool,
    /// The format string parameter.
    pub fmt: Option<Fmt>,
    /// The parameter numbers that must not be null, in order.
    pub nonnull: Vec<u16>,
    /// The effects in the order of the data file.
    pub effects: Vec<Effect>,
}

/// One Tier-0 prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proto {
    /// The function name.
    pub name: String,
    /// The C text of the prototype.
    pub text: String,
    /// The function type in the store of the [`Tier0`] database.
    pub ty: TypeId,
    /// The signature.
    pub sig: Sig,
    /// The capability category.
    pub category: Category,
    /// The attributes.
    pub attrs: Attrs,
    /// The other linked names of the function.
    pub aliases: Vec<String>,
}

/// An error in a Tier-0 file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier0Error {
    /// The prelude does not install.
    Prelude(String),
    /// The prototype text does not parse.
    Parse {
        /// The line, from 1.
        line: u32,
        /// The parser error.
        error: CParseError,
    },
    /// The attribute comment is bad.
    Attr {
        /// The line, from 1.
        line: u32,
        /// The bad word, or the line part with the problem.
        word: String,
    },
    /// A name or an alias comes twice.
    Duplicate {
        /// The line, from 1.
        line: u32,
        /// The name.
        name: String,
    },
}

impl fmt::Display for Tier0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prelude(message) => {
                write!(f, "tier0.h: the prelude does not install: {message}")
            }
            Self::Parse { line, error } => write!(f, "tier0.h line {line}: {error}"),
            Self::Attr { line, word } => {
                write!(f, "tier0.h line {line}: the attribute `{word}` is bad")
            }
            Self::Duplicate { line, name } => {
                write!(f, "tier0.h line {line}: the name `{name}` comes twice")
            }
        }
    }
}

/// Splits a Tier-0 line into the C text and the attribute comment.
fn split_line(text: &str, line: u32) -> Result<(&str, &str), Tier0Error> {
    let bad = |word: &str| Tier0Error::Attr {
        line,
        word: word.to_string(),
    };
    let Some((c, comment)) = text.split_once("//") else {
        return Err(bad("the line has no attribute comment"));
    };
    let c = c.trim();
    if !c.ends_with(';') {
        return Err(bad(c));
    }
    Ok((c, comment.trim()))
}

impl std::error::Error for Tier0Error {}

/// The Tier-0 prototype database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier0 {
    store: TypeStore,
    protos: Vec<Proto>,
    index: BTreeMap<String, usize>,
}

impl Tier0 {
    /// Parses a file in the format of `data/tier0.h`.
    ///
    /// # Errors
    ///
    /// Returns [`Tier0Error`] for the first bad line.
    pub fn parse(text: &str) -> Result<Self, Tier0Error> {
        let mut store =
            TypeStore::with_prelude().map_err(|e| Tier0Error::Prelude(e.to_string()))?;
        let mut protos: Vec<Proto> = Vec::new();
        let mut index = BTreeMap::new();
        let mut in_block = false;
        for (raw, line) in text.lines().zip(1u32..) {
            let t = raw.trim();
            if in_block {
                in_block = !t.contains("*/");
                continue;
            }
            if t.starts_with("/*") {
                in_block = !t.contains("*/");
                continue;
            }
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            let (c, comment) = split_line(t, line)?;
            let parsed =
                parse_sig(&mut store, c).map_err(|error| Tier0Error::Parse { line, error })?;
            let found = attrs::parse(comment, &parsed.sig, &store, line)?;
            let names = std::iter::once(&parsed.name).chain(&found.aliases);
            for name in names.clone() {
                if index.contains_key(name) {
                    return Err(Tier0Error::Duplicate {
                        line,
                        name: name.clone(),
                    });
                }
            }
            let slot = protos.len();
            for name in names {
                index.insert(name.clone(), slot);
            }
            protos.push(Proto {
                name: parsed.name,
                text: c.to_string(),
                ty: parsed.ty,
                sig: parsed.sig,
                category: found.category,
                attrs: found.attrs,
                aliases: found.aliases,
            });
        }
        Ok(Self {
            store,
            protos,
            index,
        })
    }

    /// Gives the prototype of the linked name `name`. A symbol version drops out first.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Proto> {
        let bare = name.split_once('@').map_or(name, |(head, _)| head);
        self.index.get(bare).and_then(|i| self.protos.get(*i))
    }

    /// Gives the prototypes in file order.
    #[must_use]
    pub fn protos(&self) -> &[Proto] {
        &self.protos
    }

    /// Gives the linked names of the index in byte order.
    pub fn names(&self) -> impl Iterator<Item = &str> + '_ {
        self.index.keys().map(String::as_str)
    }

    /// Gives the store of the prototype types.
    #[must_use]
    pub const fn store(&self) -> &TypeStore {
        &self.store
    }

    /// Gives the number of prototypes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.protos.len()
    }

    /// Tells if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.protos.is_empty()
    }
}

/// Gives the database of the embedded `data/tier0.h`.
///
/// # Errors
///
/// Returns the [`Tier0Error`] of the embedded file.
pub fn builtin() -> Result<&'static Tier0, &'static Tier0Error> {
    static DB: OnceLock<Result<Tier0, Tier0Error>> = OnceLock::new();
    DB.get_or_init(|| Tier0::parse(TIER0_H)).as_ref()
}
