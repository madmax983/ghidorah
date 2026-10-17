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
//! | [`edit`] | The closed [`Edit`] enum, its exact inverses and [`EditError`] | Section 3.7 |
//! | [`tx`] | [`Program::begin`], the [`Tx`] guard, nested scopes and [`Commit`] | Section 3.7 |
//! | [`events`] | The bounded [`Events`] ring | Section 3.8 |
//! | [`epochs`] | Table epochs and [`Program::func_epoch`] | Section 3.8 |
//! | [`invariants`] | [`Program::check_invariants`] and [`Violation`] | Section 3.11 |
//! | [`hash`] | [`Program::state_hash`] and [`StateHash`] | Section 3.12 |
//! | [`codec`] | The JSON codec of every table and edit | Sections 3.7, 3.10 |
//!
//! The crate reads no file. The persistence modules get file access through the `Fs` seam.

// The Tx guard calls most manager mutators. The analysis engine (WP-15) and the journal
// replay and undo (WP-20) call the others and `Tx::restore`. Until they exist, these
// functions have callers only in the unit tests.
#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the analysis engine and the journal replay call the other mutators"
    )
)]

pub mod codec;
pub mod comments;
pub mod edit;
pub mod epochs;
pub mod events;
pub mod fact;
pub mod funcs;
pub mod hash;
pub mod invariants;
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
pub mod tx;
pub mod typesglue;
pub mod vars;
pub mod why;

#[cfg(test)]
mod tests;

pub use codec::{CodecError, Reason};
pub use comments::{CommentKind, Comments};
pub use edit::{BlockedEdit, Edit, EditError, EditKind, FuncRecord, Layer, Slot, VarField};
pub use epochs::{Epochs, Table};
pub use events::{EVENT_RING, Event, Events};
pub use fact::{Blocked, Fact, Invalid, Origin, SessionLabel, WriteError, higher};
pub use funcs::{Caveat, FuncFlags, Funcs, Function, Part, PartKind, StartReason};
pub use hash::StateHash;
pub use invariants::Violation;
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
pub use tx::{Applied, Commit, Nested, Tx, TxError, TxLabel};
pub use typesglue::Types;
pub use vars::{VarFact, Vars};
pub use why::{FactKey, RuleCode, Why, WhyStore};
