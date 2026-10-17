//! The program database of ghidorah (design Section 3).
//!
//! A [`Program`] is plain owned data: the binary, its memory map and the managers. Each
//! manager keeps `BTreeMap` tables. Manager mutators are `pub(crate)`. The Tx guard of the
//! `tx` module is the only public write path.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`program`] | [`Program`], [`Program::from_binary`], the two layers and the merged reads | Sections 3.4, 3.9 |
//! | [`source`] | [`Source`] ranks and the write rule | Section 3.6 |
//! | [`fact`] | [`Fact`], [`Origin`], [`SessionLabel`] and the write errors | Section 3.6 |
//! | [`listing`] | Code units and data definitions | Section 3.4 |
//! | [`symbols`] | Symbols, primary flags and the name index | Section 3.4 |
//! | [`refs`] | References with a from-index and a to-index | Sections 3.4, 7.5 |
//! | [`funcs`] | Functions and the ownership map | Sections 3.2, 3.4 |
//! | [`comments`] | Comments | Section 3.4 |
//! | [`notes`] | Notes and named sets | Section 10.7 |
//! | [`vars`] | Variable facts | Section 3.4 |
//! | [`jumptables`] | Jump tables | Section 7.8 |
//! | [`strings`] | Strings | Section 7.6 |
//! | [`why`] | Why-records | ADR-0023 |
//! | [`progress`] | Progress rows and last-brief marks | Section 3.4 |
//! | [`overrides`] | Flow overrides | Section 7.5 |
//! | [`typesglue`] | The type store and the data model of a program | Section 9 |
//!
//! The crate reads no file. The persistence modules get file access through the `Fs` seam.

// The Tx guard, the analysis engine and the tools call the manager mutators. Until they
// exist, the mutators have callers only in the unit tests.
#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the Tx guard of WP-11b calls the manager mutators"
    )
)]

pub mod comments;
pub mod fact;
pub mod funcs;
pub mod jumptables;
pub mod listing;
pub mod notes;
pub mod overrides;
pub mod program;
pub mod progress;
pub mod refs;
pub mod source;
pub mod strings;
pub mod symbols;
pub mod typesglue;
pub mod vars;
pub mod why;

pub use comments::{CommentKind, Comments};
pub use fact::{Blocked, Fact, Invalid, Origin, SessionLabel, WriteError, higher};
pub use funcs::{Caveat, FuncFlags, Funcs, Function, Part, PartKind, StartReason};
pub use jumptables::{JtMethod, JumpTable, JumpTables};
pub use listing::{CodeUnit, DataDef, FlowKind, Listing};
pub use notes::{Claim, Note, NoteKind, NoteSet, NoteStatus, Notes, SetMembers, SetOp};
pub use overrides::{FlowOverride, FlowOverrides};
pub use program::{
    AnalysisSet, BinaryMeta, ExportRow, FuncView, ImportRow, Name, Program, ProgramError, Tables,
    VarView,
};
pub use progress::{FuncProgress, Mark, Progress, ProgressCounts};
pub use refs::{Ref, RefKey, RefType, Refs};
pub use source::{Source, Verdict, write_rule};
pub use strings::{Encoding, StrInfo, Strings};
pub use symbols::{SymKey, SymKind, Symbol, Symbols};
pub use typesglue::Types;
pub use vars::{VarFact, Vars};
pub use why::{FactKey, RuleCode, Why, WhyStore};
