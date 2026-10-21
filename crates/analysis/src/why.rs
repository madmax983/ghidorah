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
//! | `R_OPERAND_REF` | a data reference of an instruction operand | the code unit of the instruction |
//! | `R_RELOC_PTR` | a pointer slot and its reference | the relocation, and the slot for the reference |
//! | `R_ADDR_TABLE` | a pointer slot of an array or an address table, and its reference | none for the slot, the slot for the reference |
//! | `R_STRING_REF` | a string at the target of a reference | the references to the string |
//! | `R_STRING_SCAN` | a string in read-only data | none: the bytes |
//! | `R_AGENT_FUNCTION` | a function at an agent function | the agent function |
//! | `R_AGENT_CALL_TARGET` | a function at a target of an agent indirect call override | the override |
//! | `R_AGENT_REF` | a function at the target of an agent call reference | the reference |
//! | `R_JUMPTABLE_SLICE` | a jump table of method A | the code unit of the jump and the function |
//! | `R_TAILCALL` | a function at a tail-call target | the code unit of the jump and the function |
//! | `R_MAIN_FROM_LIBC_START` | `main` and its name from the first argument of `__libc_start_main` | the call site and the entry function |
//! | `R_SYSCALL_NUMBER` | the syscall note of a `syscall` site | the code unit of the site |
//! | `R_DATA_CODE_PTR` | a function at a code pointer in data | the relocation, or the data slot of a pointer run |
//! | `R_ADDR_TAKEN` | a function at address-taken code | the code unit of the `lea` or the `mov` |
//! | `R_GAP_COMPONENT` | a function at the entry of a code component in a gap | none: the bytes |
//! | `R_PDATA_START` | a function at a `.pdata` `BeginAddress` that is not a fragment | none: the `.pdata` entry |
//! | `R_IAT_THUNK` | the thunk flag and the import name of a `jmp [rip+IAT]` function | the function and the import |

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
    /// `R_OPERAND_REF`.
    OperandRef,
    /// `R_RELOC_PTR`.
    RelocPtr,
    /// `R_ADDR_TABLE`.
    AddrTable,
    /// `R_STRING_REF`.
    StringRef,
    /// `R_STRING_SCAN`.
    StringScan,
    /// `R_AGENT_FUNCTION`.
    AgentFunction,
    /// `R_AGENT_CALL_TARGET`.
    AgentCallTarget,
    /// `R_AGENT_REF`.
    AgentRef,
    /// `R_JUMPTABLE_SLICE`.
    JumptableSlice,
    /// `R_TAILCALL`.
    Tailcall,
    /// `R_MAIN_FROM_LIBC_START`.
    MainFromLibcStart,
    /// `R_SYSCALL_NUMBER`.
    SyscallNumber,
    /// `R_DATA_CODE_PTR`.
    DataCodePtr,
    /// `R_ADDR_TAKEN`.
    AddrTaken,
    /// `R_GAP_COMPONENT`.
    GapComponent,
    /// `R_PDATA_START`.
    PdataStart,
    /// `R_IAT_THUNK`.
    IatThunk,
}

impl Rule {
    /// All rules in catalog order.
    pub const ALL: [Self; 28] = [
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
        Self::OperandRef,
        Self::RelocPtr,
        Self::AddrTable,
        Self::StringRef,
        Self::StringScan,
        Self::AgentFunction,
        Self::AgentCallTarget,
        Self::AgentRef,
        Self::JumptableSlice,
        Self::Tailcall,
        Self::MainFromLibcStart,
        Self::SyscallNumber,
        Self::DataCodePtr,
        Self::AddrTaken,
        Self::GapComponent,
        Self::PdataStart,
        Self::IatThunk,
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
            Self::OperandRef => "R_OPERAND_REF",
            Self::RelocPtr => "R_RELOC_PTR",
            Self::AddrTable => "R_ADDR_TABLE",
            Self::StringRef => "R_STRING_REF",
            Self::StringScan => "R_STRING_SCAN",
            Self::AgentFunction => "R_AGENT_FUNCTION",
            Self::AgentCallTarget => "R_AGENT_CALL_TARGET",
            Self::AgentRef => "R_AGENT_REF",
            Self::JumptableSlice => "R_JUMPTABLE_SLICE",
            Self::Tailcall => "R_TAILCALL",
            Self::MainFromLibcStart => "R_MAIN_FROM_LIBC_START",
            Self::SyscallNumber => "R_SYSCALL_NUMBER",
            Self::DataCodePtr => "R_DATA_CODE_PTR",
            Self::AddrTaken => "R_ADDR_TAKEN",
            Self::GapComponent => "R_GAP_COMPONENT",
            Self::PdataStart => "R_PDATA_START",
            Self::IatThunk => "R_IAT_THUNK",
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
            Self::OperandRef => "An operand of the instruction points to the target.",
            Self::RelocPtr => "A relocation puts a pointer to the target in the slot.",
            Self::AddrTable => {
                "The slot is in a pointer array or in a run of two or more pointers."
            }
            Self::StringRef => "A reference points to text that ends with a terminator.",
            Self::StringScan => "Read-only data holds text that ends with a terminator.",
            Self::AgentFunction => "An agent function starts a function.",
            Self::AgentCallTarget => {
                "A target of an agent indirect call override starts a function."
            }
            Self::AgentRef => "The target of an agent call reference starts a function.",
            Self::JumptableSlice => "The slice of method A gives the targets of the jump table.",
            Self::Tailcall => {
                "A jump with a stack height of 0 leaves the function for a function start."
            }
            Self::MainFromLibcStart => {
                "The first argument of the call to __libc_start_main is main."
            }
            Self::SyscallNumber => "The value of rax at the syscall site gives the syscall.",
            Self::DataCodePtr => {
                "An aligned pointer in data points to code that no function holds."
            }
            Self::AddrTaken => "An instruction takes the address of code that no function holds.",
            Self::GapComponent => {
                "A connected code component in a gap ends each path and has no other entry."
            }
            Self::PdataStart => {
                "The BeginAddress of a .pdata entry that is not a fragment starts a function."
            }
            Self::IatThunk => {
                "The first instruction of the function jumps through the IAT slot of an import."
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
