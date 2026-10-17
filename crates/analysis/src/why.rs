//! The rule catalog and the analysis why-record (ADR-0023).
//!
//! Every analysis fact has a [`Why`]: a rule of the closed catalog [`Rule`] and the keys of
//! its premises. A premise is a fact or an input of the binary: an entry point, a relocation,
//! an FDE, an import or a symbol. The publish step gives each record its creation order, so
//! each premise is older than its fact.
//!
//! | Rule | Fact | Premises |
//! |---|---|---|
//! | `R_ENTRY` | a function at an entry point | the entry point |
//! | `R_SYMBOL_FUNC` | a function at an `STT_FUNC` symbol with a size | the symbol |
//! | `R_PLT_RELOC_SLOT` | a function at a PLT stub | the import and the slot relocation |
//! | `R_FDE_START` | a function at an FDE PC begin | the FDE |
//! | `R_CALL_TARGET` | a function at a direct call target | the call reference |
//! | `R_ENDBR_HEAD` | a function at an `endbr64` head | none: the bytes |
//! | `R_DISASM_FLOW` | a code unit | the function whose flow reaches it |
//! | `R_FLOW_REF` | a call or jump reference | the code unit of the instruction |
//! | `R_NORETURN_KNOWN` | the noreturn flag of a PLT stub | the stub and its import |
//! | `R_NORETURN_BODY` | the noreturn flag of a function with no return path | the function and the noreturn callees |
//! | `R_NORETURN_FALLTHROUGH` | the noreturn flag of a callee with 3 unsafe call sites | the function and the call sites |

use std::fmt;

use ghidorah_db::{FactKey, RuleCode, why::MAX_PREMISES};

use crate::AnalysisError;

/// A rule of the closed catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `R_ENTRY`.
    Entry,
    /// `R_SYMBOL_FUNC`.
    SymbolFunc,
    /// `R_PLT_RELOC_SLOT`.
    PltRelocSlot,
    /// `R_FDE_START`.
    FdeStart,
    /// `R_CALL_TARGET`.
    CallTarget,
    /// `R_ENDBR_HEAD`.
    EndbrHead,
    /// `R_DISASM_FLOW`.
    DisasmFlow,
    /// `R_FLOW_REF`.
    FlowRef,
    /// `R_NORETURN_KNOWN`.
    NoreturnKnown,
    /// `R_NORETURN_BODY`.
    NoreturnBody,
    /// `R_NORETURN_FALLTHROUGH`.
    NoreturnFallthrough,
}

impl Rule {
    /// All rules in catalog order.
    pub const ALL: [Self; 11] = [
        Self::Entry,
        Self::SymbolFunc,
        Self::PltRelocSlot,
        Self::FdeStart,
        Self::CallTarget,
        Self::EndbrHead,
        Self::DisasmFlow,
        Self::FlowRef,
        Self::NoreturnKnown,
        Self::NoreturnBody,
        Self::NoreturnFallthrough,
    ];

    /// Gives the rule code, for example `R_FDE_START`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Entry => "R_ENTRY",
            Self::SymbolFunc => "R_SYMBOL_FUNC",
            Self::PltRelocSlot => "R_PLT_RELOC_SLOT",
            Self::FdeStart => "R_FDE_START",
            Self::CallTarget => "R_CALL_TARGET",
            Self::EndbrHead => "R_ENDBR_HEAD",
            Self::DisasmFlow => "R_DISASM_FLOW",
            Self::FlowRef => "R_FLOW_REF",
            Self::NoreturnKnown => "R_NORETURN_KNOWN",
            Self::NoreturnBody => "R_NORETURN_BODY",
            Self::NoreturnFallthrough => "R_NORETURN_FALLTHROUGH",
        }
    }

    /// Gives the doc line of the rule.
    #[must_use]
    pub const fn doc(self) -> &'static str {
        match self {
            Self::Entry => "An entry point of the binary starts a function.",
            Self::SymbolFunc => "A function symbol with a size above 0 starts a function.",
            Self::PltRelocSlot => "A PLT stub that jumps through an import slot is a function.",
            Self::FdeStart => "The PC begin of an FDE starts a function.",
            Self::CallTarget => "The target of a direct call starts a function.",
            Self::EndbrHead => "An endbr64 head that no function holds starts a function.",
            Self::DisasmFlow => "The flow from the entry of the function reaches the instruction.",
            Self::FlowRef => "The instruction calls or jumps to the target.",
            Self::NoreturnKnown => "The import of the stub is on the noreturn list.",
            Self::NoreturnBody => "No path of the function returns.",
            Self::NoreturnFallthrough => {
                "Three or more call sites fall through into bad code or into a function."
            }
        }
    }

    /// Gives the rule of a code. An unknown code gives `None`.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }

    /// Gives the rule code of the program database.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::Invalid`] when the code breaks the grammar of [`RuleCode`].
    pub fn rule_code(self) -> Result<RuleCode, AnalysisError> {
        Ok(RuleCode::new(self.code())?)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The reason of an analysis fact: a rule and the keys of its premises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Why {
    /// The rule.
    pub rule: Rule,
    /// The premises in key order, at most [`MAX_PREMISES`], with no key twice.
    pub premises: Vec<FactKey>,
}

impl Why {
    /// Makes a record. The premises go in key order. A second copy of a key goes, and the
    /// list stops at [`MAX_PREMISES`] keys.
    #[must_use]
    pub fn new(rule: Rule, mut premises: Vec<FactKey>) -> Self {
        premises.sort();
        premises.dedup();
        premises.truncate(MAX_PREMISES);
        Self { rule, premises }
    }

    /// Makes a record with no premise.
    #[must_use]
    pub const fn bare(rule: Rule) -> Self {
        Self {
            rule,
            premises: Vec::new(),
        }
    }
}
