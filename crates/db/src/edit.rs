//! The closed [`Edit`] enum: each change of a program is one edit (design Section 3.7).
//!
//! An edit names one fact slot and its new state. A slot holds a [`Fact`] with its value and
//! its origin, or nothing. The apply step gives the exact inverse: the same kind of edit with
//! the old state. The inverse also holds the implicit side effects of an edit. For example,
//! the inverse of a cascading [`Edit::DeleteFunction`] holds the body, the parts, the
//! signature, the variable facts and the plate comment of the function.
//!
//! An edit changes one layer: the layer of the source of its transaction ([`Layer::of`]).
//! Two modes apply an edit:
//!
//! | Mode | Use | Checks |
//! |---|---|---|
//! | forward | [`Tx::apply`](crate::Tx::apply) | each fact has the origin of the Tx, the write rule, the input rules |
//! | exact | rollback, undo and replay in the crate | the layer only. The edit puts its exact state. |
//!
//! A forward edit with the same value and source as the current fact is a no-op.
//!
//! | Edit | Inverse | Start band |
//! |---|---|---|
//! | `SetName` | `SetName` with the old symbol | - |
//! | `SetComment` | `SetComment` with the old text | - |
//! | `SetVarFact` | `SetVarFact` with the old field | - |
//! | `AddRef` | `AddRef` with the old reference, or `RemoveRef` | 100 |
//! | `RemoveRef` | `AddRef` with the old reference | 100 |
//! | `CreateFunction` | `DeleteFunction` | 100 |
//! | `DeleteFunction` | `CreateFunction` with the old record | 100 |
//! | `SetSignature` | `SetSignature`, or `DeleteFunction` of a new holder record | 800 |
//! | `SetNoreturn` | `SetNoreturn`, or `DeleteFunction` of a new holder record | 100 |
//! | `SetJumpTable` | `SetJumpTable` with the old table | 100 |
//! | `SetFlowOverride` | `SetFlowOverride` with the old override | 100 |
//! | `SetDataDef` | `SetDataDef` with the old definition | 100 |
//! | `WriteNote` | `WriteNote` with the old note, or `DeleteNote` | - |
//! | `DeleteNote` | `WriteNote` with the old note | - |
//! | `ReplaceAnalysis` | `ReplaceAnalysis` with the old analysis set | - |

mod apply;
mod funcs;
mod rules;

#[cfg(test)]
mod tests;

use std::fmt;
use std::sync::Arc;

use ghidorah_base::{Address, ErrorCode, FuncId, JumpTableId, NoteId, VarId};
use ghidorah_json::Value;
use ghidorah_types::TypeId;

pub(crate) use apply::{Ctx, Mode, apply};
pub(crate) use rules::{is_id, normalize, starts_unit};

use crate::comments::CommentKind;
use crate::fact::{Fact, Invalid, Origin};
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::DataDef;
use crate::notes::Note;
use crate::overrides::FlowOverride;
use crate::program::AnalysisSet;
use crate::refs::{Ref, RefKey};
use crate::source::{Source, write_rule};
use crate::symbols::{SymKey, SymKind};
use crate::vars::VarFact;
use crate::why::FactKey;

/// The state of one fact slot: a fact, or nothing.
pub type Slot<T> = Option<Fact<T>>;

/// The largest number of evidence entries of one `SetName` edit.
pub const MAX_EVIDENCE: usize = 16;

/// The longest evidence entry in characters.
pub const MAX_EVIDENCE_LEN: usize = 200;

/// A fact layer of a program (design Section 3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// The `Imported`, `Agent` and `User` facts.
    Base,
    /// The `Analysis` facts.
    Analysis,
}

impl Layer {
    /// Gives the layer of the facts of `source`. `Default` has no layer.
    #[must_use]
    pub const fn of(source: Source) -> Option<Self> {
        match source {
            Source::Default => None,
            Source::Analysis => Some(Self::Analysis),
            Source::Agent | Source::Imported | Source::User => Some(Self::Base),
        }
    }

    /// Gives the output name: `base` or `analysis`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Analysis => "analysis",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One field of a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarField {
    /// The name fact.
    Name(Slot<String>),
    /// The type fact.
    Type(Slot<TypeId>),
}

/// A function record with the facts that a cascading delete removes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncRecord {
    /// The function: entry, body, parts, signature, flags and the other fields.
    pub func: Function,
    /// The variable facts of the function, in ID order.
    pub vars: Vec<(VarId, VarFact)>,
    /// The plate comment at the entry: the function comment.
    pub plate: Slot<String>,
}

/// One change of a program. The list of variants is closed (design Section 3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Sets, adds or removes one symbol name at an address.
    SetName {
        /// The address.
        addr: Address,
        /// The symbol key, or `None` for the primary symbol.
        key: Option<SymKey>,
        /// The kind of a new symbol. A rename keeps the kind.
        kind: SymKind,
        /// A new symbol takes the primary flag. A rename keeps the flag.
        primary: bool,
        /// The name fact, or `None` to remove the symbol.
        name: Slot<String>,
        /// The evidence of the rename: IDs or feature texts. The journal keeps them.
        evidence: Vec<String>,
    },
    /// Sets or removes a comment. An empty text removes it.
    SetComment {
        /// The address.
        addr: Address,
        /// The kind.
        kind: CommentKind,
        /// The text fact.
        text: Slot<String>,
    },
    /// Sets or removes one fact of a variable.
    SetVarFact {
        /// The variable.
        var: VarId,
        /// The field and its new state.
        field: VarField,
    },
    /// Adds a reference, or changes the reference with the same key.
    AddRef {
        /// The reference fact.
        fact: Fact<Ref>,
    },
    /// Removes a reference.
    RemoveRef {
        /// The key.
        key: RefKey,
    },
    /// Adds a function with its variable facts and its plate comment.
    CreateFunction(Box<FuncRecord>),
    /// Removes a function.
    DeleteFunction {
        /// The function.
        id: FuncId,
        /// The delete also removes the variable facts and the plate comment of the function.
        cascade: bool,
    },
    /// Sets or removes the signature of a function.
    SetSignature {
        /// The function.
        id: FuncId,
        /// The signature: the ID of a function type.
        sig: Slot<TypeId>,
    },
    /// Sets or removes the noreturn flag of a function.
    SetNoreturn {
        /// The function.
        id: FuncId,
        /// The flag.
        noreturn: Slot<bool>,
    },
    /// Sets or removes the jump table of an indirect jump.
    SetJumpTable {
        /// The indirect jump.
        id: JumpTableId,
        /// The table.
        table: Slot<JumpTable>,
    },
    /// Sets or removes the flow override of an instruction.
    SetFlowOverride {
        /// The instruction.
        at: Address,
        /// The override.
        flow: Slot<FlowOverride>,
    },
    /// Sets or removes a data definition.
    SetDataDef {
        /// The RAM address.
        at: Address,
        /// The definition.
        def: Slot<DataDef>,
    },
    /// Writes a new note or changes the note with its ID.
    WriteNote(Box<Note>),
    /// Removes a note.
    DeleteNote {
        /// The note.
        id: NoteId,
    },
    /// Puts a new analysis set in place of the analysis layer.
    ReplaceAnalysis(Arc<AnalysisSet>),
}

/// The kind of an [`Edit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EditKind {
    /// [`Edit::SetName`].
    SetName,
    /// [`Edit::SetComment`].
    SetComment,
    /// [`Edit::SetVarFact`].
    SetVarFact,
    /// [`Edit::AddRef`].
    AddRef,
    /// [`Edit::RemoveRef`].
    RemoveRef,
    /// [`Edit::CreateFunction`].
    CreateFunction,
    /// [`Edit::DeleteFunction`].
    DeleteFunction,
    /// [`Edit::SetSignature`].
    SetSignature,
    /// [`Edit::SetNoreturn`].
    SetNoreturn,
    /// [`Edit::SetJumpTable`].
    SetJumpTable,
    /// [`Edit::SetFlowOverride`].
    SetFlowOverride,
    /// [`Edit::SetDataDef`].
    SetDataDef,
    /// [`Edit::WriteNote`].
    WriteNote,
    /// [`Edit::DeleteNote`].
    DeleteNote,
    /// [`Edit::ReplaceAnalysis`].
    ReplaceAnalysis,
}

impl EditKind {
    /// All kinds in the order of design Section 3.7.
    pub const ALL: [Self; 15] = [
        Self::SetName,
        Self::SetComment,
        Self::SetVarFact,
        Self::AddRef,
        Self::RemoveRef,
        Self::CreateFunction,
        Self::DeleteFunction,
        Self::SetSignature,
        Self::SetNoreturn,
        Self::SetJumpTable,
        Self::SetFlowOverride,
        Self::SetDataDef,
        Self::WriteNote,
        Self::DeleteNote,
        Self::ReplaceAnalysis,
    ];

    /// Gives the name, for example `SetName`. The journal writes it as `op`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SetName => "SetName",
            Self::SetComment => "SetComment",
            Self::SetVarFact => "SetVarFact",
            Self::AddRef => "AddRef",
            Self::RemoveRef => "RemoveRef",
            Self::CreateFunction => "CreateFunction",
            Self::DeleteFunction => "DeleteFunction",
            Self::SetSignature => "SetSignature",
            Self::SetNoreturn => "SetNoreturn",
            Self::SetJumpTable => "SetJumpTable",
            Self::SetFlowOverride => "SetFlowOverride",
            Self::SetDataDef => "SetDataDef",
            Self::WriteNote => "WriteNote",
            Self::DeleteNote => "DeleteNote",
            Self::ReplaceAnalysis => "ReplaceAnalysis",
        }
    }

    /// Gives the kind of a name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Gives the start band of the re-analysis after the edit (design Section 3.9).
    ///
    /// `None` marks an edit that does not affect analysis.
    #[must_use]
    pub const fn band(self) -> Option<u16> {
        match self {
            Self::CreateFunction
            | Self::DeleteFunction
            | Self::SetNoreturn
            | Self::SetJumpTable
            | Self::SetFlowOverride
            | Self::AddRef
            | Self::RemoveRef
            | Self::SetDataDef => Some(100),
            Self::SetSignature => Some(800),
            Self::SetName
            | Self::SetComment
            | Self::SetVarFact
            | Self::WriteNote
            | Self::DeleteNote
            | Self::ReplaceAnalysis => None,
        }
    }
}

impl fmt::Display for EditKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Edit {
    /// Gives the kind.
    #[must_use]
    pub const fn kind(&self) -> EditKind {
        match self {
            Self::SetName { .. } => EditKind::SetName,
            Self::SetComment { .. } => EditKind::SetComment,
            Self::SetVarFact { .. } => EditKind::SetVarFact,
            Self::AddRef { .. } => EditKind::AddRef,
            Self::RemoveRef { .. } => EditKind::RemoveRef,
            Self::CreateFunction(_) => EditKind::CreateFunction,
            Self::DeleteFunction { .. } => EditKind::DeleteFunction,
            Self::SetSignature { .. } => EditKind::SetSignature,
            Self::SetNoreturn { .. } => EditKind::SetNoreturn,
            Self::SetJumpTable { .. } => EditKind::SetJumpTable,
            Self::SetFlowOverride { .. } => EditKind::SetFlowOverride,
            Self::SetDataDef { .. } => EditKind::SetDataDef,
            Self::WriteNote(_) => EditKind::WriteNote,
            Self::DeleteNote { .. } => EditKind::DeleteNote,
            Self::ReplaceAnalysis(_) => EditKind::ReplaceAnalysis,
        }
    }

    /// Gives the keys of the facts that the edit names, in key order.
    ///
    /// A `SetName` edit without a key names no symbol key. Its inverse names the key.
    /// `ReplaceAnalysis` names no key. A selective undo compares these keys (ADR-0017).
    #[must_use]
    pub fn keys(&self) -> Vec<FactKey> {
        rules::keys(self)
    }
}

/// A write that the write rule refuses: `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEdit {
    /// The key of the current fact.
    pub key: FactKey,
    /// The current value in its JSON form. Error details show it.
    pub value: Value,
    /// The origin of the current fact.
    pub current: Origin,
    /// The source of the refused write.
    pub attempted: Source,
    /// The refused write used `force: true`.
    pub force: bool,
}

impl BlockedEdit {
    /// Tells if the same write with `force: true` succeeds. Then `next[0]` repeats it so.
    #[must_use]
    pub fn force_applies(&self) -> bool {
        write_rule(self.current.source, self.attempted, true).is_allowed()
    }
}

/// The error of an edit. The program does not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// A fact of a higher rank blocks the write.
    Blocked(Box<BlockedEdit>),
    /// The edit breaks a rule of its table.
    Invalid(Invalid),
    /// A fact of a forward edit does not have the origin of its transaction.
    Origin(FactKey),
    /// A fact of the edit has a source outside the layer of the transaction.
    WrongLayer(Source),
    /// A reference starts at an address that is not the start of a code unit or data.
    NotCode(Address),
    /// A jump-table target or an indirect target is not in an executable region and not
    /// an import, or it is inside an instruction.
    BadTarget(Address),
    /// The type store has no type with this ID.
    UnknownType(TypeId),
    /// The type is not a function type.
    NotFuncType(TypeId),
    /// A slot that a new function record fills already holds a fact.
    Occupied(FactKey),
    /// A nested abort poisoned the transaction.
    Poisoned,
}

impl EditError {
    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Blocked(_) => ErrorCode::BlockedByHigherPrioritySource,
            Self::Invalid(i) => i.code(),
            Self::UnknownType(_) => ErrorCode::NotFound,
            Self::Occupied(_) | Self::Poisoned => ErrorCode::Conflict,
            Self::Origin(_)
            | Self::WrongLayer(_)
            | Self::NotCode(_)
            | Self::BadTarget(_)
            | Self::NotFuncType(_) => ErrorCode::InvalidArgument,
        }
    }
}

impl From<Invalid> for EditError {
    fn from(value: Invalid) -> Self {
        Self::Invalid(value)
    }
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(b) => write!(
                f,
                "A fact with the source {} (rank {}) blocks the write with the source {} (rank {}).",
                b.current.source,
                b.current.source.rank(),
                b.attempted,
                b.attempted.rank()
            ),
            Self::Invalid(i) => i.fmt(f),
            Self::Origin(key) => write!(
                f,
                "The fact {key:?} does not have the origin of the transaction."
            ),
            Self::WrongLayer(s) => write!(
                f,
                "A fact with the source {s} is outside the layer of the transaction."
            ),
            Self::NotCode(a) => write!(f, "No code unit and no data starts at {a}."),
            Self::BadTarget(a) => write!(
                f,
                "The target {a} is not an instruction start in code and not an import."
            ),
            Self::UnknownType(t) => write!(f, "The type store has no type {}.", t.index()),
            Self::NotFuncType(t) => write!(f, "The type {} is not a function type.", t.index()),
            Self::Occupied(key) => write!(f, "The slot {key:?} already holds a fact."),
            Self::Poisoned => f.write_str("A nested abort poisoned the transaction."),
        }
    }
}

impl std::error::Error for EditError {}
