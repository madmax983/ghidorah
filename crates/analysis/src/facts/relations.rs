//! The relation catalog and the typed claim atoms (design Section 11.8, ADR-0023).
//!
//! A claim is one relation atom with ID arguments. [`CATALOG`] holds one [`RelSpec`] per
//! relation: the name, the columns with their argument kinds, the index that the check reads
//! and a doc line. [`Atom`] is a claim with resolved arguments. The `outcome` module holds
//! its verdict with the evidence and the gaps.
//!
//! | Kind | Text | Example |
//! |---|---|---|
//! | [`ColKind::Func`] | an address, a name or a `fn:` ID of a function | `fn:0x1149`, `main` |
//! | [`ColKind::Import`] | an `imp:` ID | `imp:puts` |
//! | [`ColKind::Syscall`] | a `sys:` ID, a syscall name or a number | `sys:write`, `1` |
//! | [`ColKind::Addr`] | an address expression | `0x2004`, `str:0x2004` |
//! | [`ColKind::Int`] | a decimal integer | `2` |
//! | [`ColKind::Glob`] | a glob pattern | `*password*` |
//! | [`ColKind::RefKind`] | a reference class or a reference type name | `call`, `read` |
//! | [`ColKind::Value`] | an integer, `0x` hex or an address expression | `0`, `0x10` |

use std::fmt;

use ghidorah_base::{Address, FuncId, Glob, ImportId};
use ghidorah_db::RefType;

/// The largest depth of `reaches`.
pub const MAX_DEPTH: u8 = 5;

/// The largest argument index of `const_arg`. Six registers hold the integer arguments.
pub const MAX_INDEX: u8 = 5;

/// A relation of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// `calls(f, g)`.
    Calls,
    /// `reaches(f, g, d)`.
    Reaches,
    /// `uses_import(f, i)`.
    UsesImport,
    /// `refs_string(f, glob)`.
    RefsString,
    /// `refs_addr(f, a)`.
    RefsAddr,
    /// `xref(from, to, kind)`.
    Xref,
    /// `const_arg(callee, index, value)`.
    ConstArg,
    /// `has_syscall(f, name)`.
    HasSyscall,
    /// `noreturn(f)`.
    Noreturn,
    /// `in_func(a, f)`.
    InFunc,
}

/// The names of the relations in catalog order.
pub const NAMES: [&str; 10] = [
    "calls",
    "reaches",
    "uses_import",
    "refs_string",
    "refs_addr",
    "xref",
    "const_arg",
    "has_syscall",
    "noreturn",
    "in_func",
];

impl Relation {
    /// All relations in catalog order.
    pub const ALL: [Self; 10] = [
        Self::Calls,
        Self::Reaches,
        Self::UsesImport,
        Self::RefsString,
        Self::RefsAddr,
        Self::Xref,
        Self::ConstArg,
        Self::HasSyscall,
        Self::Noreturn,
        Self::InFunc,
    ];

    /// Gives the catalog row of the relation.
    #[must_use]
    pub const fn spec(self) -> &'static RelSpec {
        &CATALOG[self as usize]
    }

    /// Gives the name, for example `uses_import`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.spec().name
    }

    /// Gives the relation of a name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The kind of one argument of a relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColKind {
    /// A function.
    Func,
    /// An import.
    Import,
    /// A syscall.
    Syscall,
    /// An address.
    Addr,
    /// A small integer.
    Int,
    /// A glob pattern.
    Glob,
    /// A reference class or type.
    RefKind,
    /// A constant value.
    Value,
}

impl ColKind {
    /// Gives the short name of the kind, for example `fn`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Func => "fn",
            Self::Import => "imp",
            Self::Syscall => "sys",
            Self::Addr => "addr",
            Self::Int => "int",
            Self::Glob => "glob",
            Self::RefKind => "kind",
            Self::Value => "value",
        }
    }
}

/// One column of a relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// The column name, for example `callee`.
    pub name: &'static str,
    /// The argument kinds that the column takes.
    pub kinds: &'static [ColKind],
    /// The claim can leave out the column. Only the last columns are optional.
    pub optional: bool,
}

impl Column {
    /// Makes a required column.
    const fn req(name: &'static str, kinds: &'static [ColKind]) -> Self {
        Self {
            name,
            kinds,
            optional: false,
        }
    }

    /// Makes an optional column.
    const fn opt(name: &'static str, kinds: &'static [ColKind]) -> Self {
        Self {
            name,
            kinds,
            optional: true,
        }
    }
}

/// One row of the relation catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelSpec {
    /// The relation.
    pub relation: Relation,
    /// The name.
    pub name: &'static str,
    /// The columns in argument order.
    pub columns: &'static [Column],
    /// The facts that the check reads.
    pub index: &'static str,
    /// One line that tells when the claim is true.
    pub doc: &'static str,
}

impl RelSpec {
    /// Gives the number of required columns.
    #[must_use]
    pub fn required(&self) -> usize {
        self.columns.iter().filter(|c| !c.optional).count()
    }
}

const FUNC: &[ColKind] = &[ColKind::Func];
const CALLEE: &[ColKind] = &[ColKind::Func, ColKind::Import, ColKind::Syscall];
const TARGET: &[ColKind] = &[ColKind::Func, ColKind::Import];

/// The relation catalog in catalog order.
pub const CATALOG: [RelSpec; 10] = [
    RelSpec {
        relation: Relation::Calls,
        name: NAMES[0],
        columns: &[Column::req("f", FUNC), Column::req("g", CALLEE)],
        index: "call references, tail-call jumps and indirect target overrides of f",
        doc: "The function f calls g directly, through a tail call or through an indirect target override.",
    },
    RelSpec {
        relation: Relation::Reaches,
        name: NAMES[1],
        columns: &[
            Column::req("f", FUNC),
            Column::req("g", TARGET),
            Column::opt("d", &[ColKind::Int]),
        ],
        index: "the call edges of the functions that f reaches",
        doc: "A path of at most d call edges goes from f to g. The default d is 5.",
    },
    RelSpec {
        relation: Relation::UsesImport,
        name: NAMES[2],
        columns: &[Column::req("f", FUNC), Column::req("i", &[ColKind::Import])],
        index: "the references and call edges of f",
        doc: "The function f calls the import i or refers to its stub, slot or EXTERNAL address.",
    },
    RelSpec {
        relation: Relation::RefsString,
        name: NAMES[3],
        columns: &[
            Column::req("f", FUNC),
            Column::req("glob", &[ColKind::Glob]),
        ],
        index: "the references of f and the string table",
        doc: "The function f refers to a string whose text matches the glob.",
    },
    RelSpec {
        relation: Relation::RefsAddr,
        name: NAMES[4],
        columns: &[Column::req("f", FUNC), Column::req("a", &[ColKind::Addr])],
        index: "the references of f",
        doc: "An instruction of f refers to the address a.",
    },
    RelSpec {
        relation: Relation::Xref,
        name: NAMES[5],
        columns: &[
            Column::req("from", &[ColKind::Addr]),
            Column::req("to", &[ColKind::Addr]),
            Column::opt("kind", &[ColKind::RefKind]),
        ],
        index: "the from-index of the references",
        doc: "A reference of the kind goes from the address from to the address to.",
    },
    RelSpec {
        relation: Relation::ConstArg,
        name: NAMES[6],
        columns: &[
            Column::req("callee", CALLEE),
            Column::req("index", &[ColKind::Int]),
            Column::req("value", &[ColKind::Value]),
        ],
        index: "the call sites of the callee and block-local evaluation",
        doc: "A call site of the callee passes the value in the argument with the index. Index 0 is the first argument.",
    },
    RelSpec {
        relation: Relation::HasSyscall,
        name: NAMES[7],
        columns: &[
            Column::req("f", FUNC),
            Column::req("name", &[ColKind::Syscall]),
        ],
        index: "the syscall notes of the syscall sites of f",
        doc: "The function f has a syscall site with the syscall number.",
    },
    RelSpec {
        relation: Relation::Noreturn,
        name: NAMES[8],
        columns: &[Column::req("f", FUNC)],
        index: "the noreturn flag and the return instructions of f",
        doc: "The function f has the noreturn flag.",
    },
    RelSpec {
        relation: Relation::InFunc,
        name: NAMES[9],
        columns: &[Column::req("a", &[ColKind::Addr]), Column::req("f", FUNC)],
        index: "the function bodies and the ownership map",
        doc: "The body of the function f holds the address a.",
    },
];

/// A function, an import or a syscall: the callee of a claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    /// A function.
    Func(FuncId),
    /// An import.
    Import(ImportId),
    /// A syscall number.
    Syscall(u16),
}

/// The reference kinds of an `xref` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefClass {
    /// `call`: the call types.
    Call,
    /// `jump`: the jump types.
    Jump,
    /// `read`: `read` and `read_write`.
    Read,
    /// `write`: `write` and `read_write`.
    Write,
    /// One reference type, for example `data`.
    Type(RefType),
}

impl RefClass {
    /// The class names that are not type names, in schema order.
    pub const CLASSES: [&'static str; 4] = ["call", "jump", "read", "write"];

    /// Gives the class of a name: a class name, else a reference type name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "call" => Some(Self::Call),
            "jump" => Some(Self::Jump),
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => RefType::parse(name).map(Self::Type),
        }
    }

    /// Tells if a reference of the type `kind` is in the class.
    #[must_use]
    pub const fn matches(self, kind: RefType) -> bool {
        match self {
            Self::Call => kind.is_call(),
            Self::Jump => matches!(
                kind,
                RefType::UnconditionalJump | RefType::ConditionalJump | RefType::ComputedJump
            ),
            Self::Read => matches!(kind, RefType::Read | RefType::ReadWrite),
            Self::Write => matches!(kind, RefType::Write | RefType::ReadWrite),
            Self::Type(t) => t.code() == kind.code(),
        }
    }
}

/// A claim with resolved arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Atom {
    /// `calls(f, g)`.
    Calls {
        /// The caller.
        f: FuncId,
        /// The callee.
        g: Endpoint,
    },
    /// `reaches(f, g, d)`.
    Reaches {
        /// The start function.
        f: FuncId,
        /// The goal: a function or an import.
        g: Endpoint,
        /// The largest path length, 1 to [`MAX_DEPTH`].
        depth: u8,
    },
    /// `uses_import(f, i)`.
    UsesImport {
        /// The function.
        f: FuncId,
        /// The import.
        import: ImportId,
    },
    /// `refs_string(f, glob)`.
    RefsString {
        /// The function.
        f: FuncId,
        /// The pattern of the string text.
        glob: Glob,
    },
    /// `refs_addr(f, a)`.
    RefsAddr {
        /// The function.
        f: FuncId,
        /// The address.
        addr: Address,
    },
    /// `xref(from, to, kind)`.
    Xref {
        /// The source of the reference.
        from: Address,
        /// The target of the reference.
        to: Address,
        /// The kinds, or `None` for every kind.
        kind: Option<RefClass>,
    },
    /// `const_arg(callee, index, value)`.
    ConstArg {
        /// The callee.
        callee: Endpoint,
        /// The argument index, 0 to [`MAX_INDEX`].
        index: u8,
        /// The value: an integer or an address offset.
        value: u64,
    },
    /// `has_syscall(f, name)`.
    HasSyscall {
        /// The function.
        f: FuncId,
        /// The syscall number.
        number: u16,
    },
    /// `noreturn(f)`.
    Noreturn {
        /// The function.
        f: FuncId,
    },
    /// `in_func(a, f)`.
    InFunc {
        /// The address.
        addr: Address,
        /// The function.
        f: FuncId,
    },
}

impl Atom {
    /// Gives the relation of the atom.
    #[must_use]
    pub const fn relation(&self) -> Relation {
        match self {
            Self::Calls { .. } => Relation::Calls,
            Self::Reaches { .. } => Relation::Reaches,
            Self::UsesImport { .. } => Relation::UsesImport,
            Self::RefsString { .. } => Relation::RefsString,
            Self::RefsAddr { .. } => Relation::RefsAddr,
            Self::Xref { .. } => Relation::Xref,
            Self::ConstArg { .. } => Relation::ConstArg,
            Self::HasSyscall { .. } => Relation::HasSyscall,
            Self::Noreturn { .. } => Relation::Noreturn,
            Self::InFunc { .. } => Relation::InFunc,
        }
    }
}
