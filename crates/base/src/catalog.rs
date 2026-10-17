//! The frozen code catalogs (design Section 10.8, ADR-0002).
//!
//! Three catalogs exist, each `#[repr(u16)]`:
//!
//! - [`ErrorCode`]: the code of a tool error.
//! - [`WarningCode`]: the code of a result warning.
//! - [`DiagCode`]: the code of a loader or C parser diagnostic.
//!
//! Code numbers never change. A reserved number stays out of use. Each code has a
//! [`CodeInfo`] with a message template, a hint, a retry flag and a repair class.
//! A template can hold placeholders such as `{field}`. [`render`] fills them.
//! [`errors_markdown`] gives the text of `docs/errors.md`.

use std::fmt;

/// The path of the generated catalog document, relative to the workspace root.
pub const ERRORS_DOC_PATH: &str = "docs/errors.md";

/// The version of the generator of `docs/errors.md`. The golden header names it.
pub const ERRORS_DOC_VERSION: &str = "1";

/// The repair class of a code (design Section 10.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepairClass {
    /// R: `next[0]` is the complete corrected call.
    Repair,
    /// R*: R only when the fix is mechanical. Else the code gives no repair call.
    RepairWhen,
    /// C: the candidates hold the choices. No client picks one by rule.
    Choice,
    /// H: `next[0]` is a helper call, for example `tool_search`.
    Helper,
    /// N: no mechanical repair.
    None,
}

impl RepairClass {
    /// All classes.
    pub const ALL: [Self; 5] = [
        Self::Repair,
        Self::RepairWhen,
        Self::Choice,
        Self::Helper,
        Self::None,
    ];

    /// Gives the short text of the class: `R`, `R*`, `C`, `H` or `N`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        let _ = self;
        ""
    }
}

impl fmt::Display for RepairClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The catalog data of one code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeInfo {
    /// The frozen number.
    pub num: u16,
    /// The `UPPER_SNAKE` name, for example `ADDRESS_INVALID`.
    pub name: &'static str,
    /// The repair class. Diagnostic codes use [`RepairClass::None`].
    pub class: RepairClass,
    /// `true` when the same call can succeed later without a change.
    pub retry: bool,
    /// The message template in the form "What failed. Why. Action.".
    pub message: &'static str,
    /// The hint: one short instruction or fact for the repair.
    pub hint: &'static str,
}

/// A reserved number of a catalog. No code uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reserved {
    /// The reserved number.
    pub num: u16,
    /// The name of the planned code.
    pub name: &'static str,
    /// The stretch item that plans the code.
    pub stretch: &'static str,
}

/// The code of a tool error. The numbers are frozen.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// `INVALID_ARGUMENT`: a value has the wrong type or range.
    InvalidArgument = 1,
    /// `UNKNOWN_ARGUMENT`: a key is not in the schema.
    UnknownArgument = 2,
    /// `MISSING_ARGUMENT`: a required key is absent.
    MissingArgument = 3,
    /// `UNKNOWN_TOOL`: the tool name is unknown.
    UnknownTool = 4,
    /// `TOOL_NOT_IN_PROFILE`: the tool is outside the profile, or a batch step is destructive.
    ToolNotInProfile = 5,
    /// `ADDRESS_INVALID`: the address text does not parse, or an integer is 2^53 or more.
    AddressInvalid = 6,
    /// `ADDRESS_UNMAPPED`: the address is not in a mapped region.
    AddressUnmapped = 7,
    /// `ADDRESS_BASE_AMBIGUOUS`: the address text has digits only.
    AddressBaseAmbiguous = 8,
    /// `AMBIGUOUS_NAME`: a name matches more than one entity.
    AmbiguousName = 9,
    /// `NOT_FOUND`: an ID, name, type, note or set does not exist.
    NotFound = 10,
    /// `UNKNOWN_BINARY`: the `binary_id` is not open.
    UnknownBinary = 11,
    /// `BINARY_REQUIRED`: more than one binary is open and the call names none.
    BinaryRequired = 12,
    /// `PATH_OUTSIDE_ROOT`: the path is outside the configured roots.
    PathOutsideRoot = 13,
    /// `FILE_UNREADABLE`: the file does not exist, or the process cannot read it.
    FileUnreadable = 14,
    /// `UNSUPPORTED_FORMAT`: the probe finds a format outside the MVP.
    UnsupportedFormat = 15,
    /// `UNSUPPORTED_ARCH`: a code feature on a binary that is not x86-64.
    UnsupportedArch = 16,
    /// `FORMAT_MALFORMED`: bad magic or a truncated main header.
    FormatMalformed = 17,
    /// `CURSOR_INVALID`: the cursor does not decode, fails its check or belongs to another query.
    CursorInvalid = 18,
    /// `CURSOR_STALE`: the sort key of the boundary item changed.
    CursorStale = 19,
    /// `CONFLICT`: `expected_rev` differs, or a selective undo overlaps a later transaction.
    Conflict = 20,
    /// `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`: the write rank is lower than the current fact.
    BlockedByHigherPrioritySource = 21,
    /// `BODY_OVERLAP`: a new function body overlaps another function.
    BodyOverlap = 22,
    /// `NOT_IN_FUNCTION`: the address is not inside a function.
    NotInFunction = 23,
    /// `C_PARSE_ERROR`: the C text does not parse.
    CParseError = 26,
    /// `NOTHING_TO_UNDO`: the scope has no applied entry.
    NothingToUndo = 27,
    /// `LIMIT_EXCEEDED`: a list input or a value is above its cap.
    LimitExceeded = 28,
    /// `BAD_REFERENCE`: a batch reference does not resolve.
    BadReference = 29,
    /// `SKIPPED_DEPENDENCY`: a batch step refers to a failed step.
    SkippedDependency = 30,
    /// `EXPECT_FAILED`: a batch guard failed.
    ExpectFailed = 31,
    /// `PLUCK_TOO_LONG`: a `*` reference gives more values than the target list cap.
    PluckTooLong = 32,
    /// `BUDGET_EXCEEDED`: the fuel ran out in a call that cannot return partial data.
    BudgetExceeded = 33,
    /// `PROJECT_LOCKED`: another writer holds the project lock.
    ProjectLocked = 34,
    /// `JOURNAL_CORRUPT`: a journal line in the middle fails its checksum.
    JournalCorrupt = 35,
    /// `READ_ONLY_PROJECT`: the project is open read-only.
    ReadOnlyProject = 36,
    /// `OUTPUT_BUDGET_EXCEEDED`: an internal guard. A test makes sure that it never fires.
    OutputBudgetExceeded = 37,
    /// `INTERNAL_ERROR`: a handler panicked.
    InternalError = 38,
    /// `NO_BINARY_OPEN`: no binary is open and the call needs one.
    NoBinaryOpen = 40,
    /// `NOTHING_TO_REDO`: no undone entry is in reach.
    NothingToRedo = 41,
}

/// The code of a result warning. The numbers are frozen.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WarningCode {
    /// `W_COERCED`: the server changed an argument.
    Coerced = 1,
    /// `W_ARCH_UNSUPPORTED`: the ELF machine is not x86-64.
    ArchUnsupported = 2,
    /// `W_NOT_DEMANGLED`: a result holds a mangled name.
    NotDemangled = 3,
    /// `W_JOURNAL_TAIL_DISCARDED`: the open step dropped a torn last journal line.
    JournalTailDiscarded = 4,
    /// `W_AGENT_OVERRIDE_CONFLICT`: analysis disagrees with an agent override.
    AgentOverrideConflict = 5,
    /// `W_FACT_ORPHANED`: an agent fact lost its function.
    FactOrphaned = 6,
    /// `W_STALE_OP_ID`: an op ID has another lifter version.
    StaleOpId = 7,
    /// `W_UNGROUNDED_FINDING`: a finding has no evidence and no claim.
    UngroundedFinding = 8,
    /// `W_NORETURN_SUSPECT`: a call has an unsafe fall-through.
    NoreturnSuspect = 9,
    /// `W_NORETURN_ASSUMED`: only the known list marks the callee noreturn.
    NoreturnAssumed = 10,
    /// `W_JUMPTABLE_UNRESOLVED`: method A failed.
    JumptableUnresolved = 11,
    /// `W_INDIRECT_CALL_UNRESOLVED`: an indirect call or jump has no targets.
    IndirectCallUnresolved = 13,
    /// `W_LIFT_UNSUPPORTED`: an instruction lifts to `Intrinsic` in a view.
    LiftUnsupported = 14,
    /// `W_SP_MISMATCH`: the tracked stack pointer differs from the CFA.
    SpMismatch = 15,
    /// `W_BUDGET_FLAT`: the decompiler fell back to FLAT on budget.
    BudgetFlat = 17,
    /// `W_STRUCTURE_SELFCHECK`: the decompiler self-check failed.
    StructureSelfcheck = 18,
    /// `W_ANALYSIS_STALE`: a read used the committed set while a shadow runs.
    AnalysisStale = 19,
    /// `W_TIME_STOP`: a `max_ms` guard stopped the work.
    TimeStop = 20,
}

/// The code of a loader or C parser diagnostic. The numbers are frozen.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagCode {
    /// `E_OOB`: a read goes past the end of its buffer or table.
    Oob = 1,
    /// `E_OVERFLOW`: an address or size computation overflows.
    Overflow = 2,
    /// `E_BAD_MAGIC`: a magic value is wrong.
    BadMagic = 3,
    /// `E_LIMIT`: a count is above its limit.
    Limit = 4,
    /// `E_LOOP`: a walk does not advance or comes back to a visited item.
    Loop = 5,
    /// `E_BAD_ALIGN`: a value does not have its alignment.
    BadAlign = 6,
    /// `E_BAD_ENTSIZE`: a table entry size does not match its type.
    BadEntsize = 7,
    /// `E_UNSUPPORTED_RELOC`: a relocation type outside the MVP set.
    UnsupportedReloc = 8,
    /// `E_CFA_OPCODE`: a CFA instruction has an unknown opcode.
    CfaOpcode = 9,
    /// `E_OVERLAP`: two PE sections overlap.
    Overlap = 10,
    /// `E_SYNTAX`: the C text has a syntax error.
    Syntax = 11,
    /// `E_UNKNOWN_TYPE`: the C text names an unknown type.
    UnknownType = 12,
    /// `E_INCOMPLETE_BY_VALUE`: a record holds an incomplete type by value.
    IncompleteByValue = 13,
    /// `E_CONST_EXPR`: a constant expression does not evaluate.
    ConstExpr = 14,
    /// `E_UNSUPPORTED`: the C text uses a feature outside the MVP.
    Unsupported = 15,
}

/// The empty catalog data that the bodies give before the tables exist.
const EMPTY: CodeInfo = CodeInfo {
    num: 0,
    name: "",
    class: RepairClass::None,
    retry: false,
    message: "",
    hint: "",
};

impl ErrorCode {
    /// All codes in number order.
    pub const ALL: [Self; 38] = [
        Self::InvalidArgument,
        Self::UnknownArgument,
        Self::MissingArgument,
        Self::UnknownTool,
        Self::ToolNotInProfile,
        Self::AddressInvalid,
        Self::AddressUnmapped,
        Self::AddressBaseAmbiguous,
        Self::AmbiguousName,
        Self::NotFound,
        Self::UnknownBinary,
        Self::BinaryRequired,
        Self::PathOutsideRoot,
        Self::FileUnreadable,
        Self::UnsupportedFormat,
        Self::UnsupportedArch,
        Self::FormatMalformed,
        Self::CursorInvalid,
        Self::CursorStale,
        Self::Conflict,
        Self::BlockedByHigherPrioritySource,
        Self::BodyOverlap,
        Self::NotInFunction,
        Self::CParseError,
        Self::NothingToUndo,
        Self::LimitExceeded,
        Self::BadReference,
        Self::SkippedDependency,
        Self::ExpectFailed,
        Self::PluckTooLong,
        Self::BudgetExceeded,
        Self::ProjectLocked,
        Self::JournalCorrupt,
        Self::ReadOnlyProject,
        Self::OutputBudgetExceeded,
        Self::InternalError,
        Self::NoBinaryOpen,
        Self::NothingToRedo,
    ];

    /// The reserved numbers of the catalog.
    pub const RESERVED: [Reserved; 3] = [
        Reserved {
            num: 24,
            name: "NO_FILE_BYTES",
            stretch: "S26",
        },
        Reserved {
            num: 25,
            name: "PATCH_INVALID",
            stretch: "S26",
        },
        Reserved {
            num: 39,
            name: "IDEMPOTENCY_MISMATCH",
            stretch: "S19",
        },
    ];

    /// Gives the frozen number of the code.
    #[must_use]
    pub const fn num(self) -> u16 {
        let _ = self;
        0
    }

    /// Gives the catalog data of the code.
    #[must_use]
    pub const fn info(self) -> CodeInfo {
        let _ = self;
        EMPTY
    }

    /// Gives the `UPPER_SNAKE` name of the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.info().name
    }

    /// Gives the code of a frozen number. A reserved or unknown number gives `None`.
    #[must_use]
    pub fn from_num(num: u16) -> Option<Self> {
        let _ = num;
        None
    }

    /// Gives the code of an `UPPER_SNAKE` name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let _ = name;
        None
    }
}

impl WarningCode {
    /// All codes in number order.
    pub const ALL: [Self; 18] = [
        Self::Coerced,
        Self::ArchUnsupported,
        Self::NotDemangled,
        Self::JournalTailDiscarded,
        Self::AgentOverrideConflict,
        Self::FactOrphaned,
        Self::StaleOpId,
        Self::UngroundedFinding,
        Self::NoreturnSuspect,
        Self::NoreturnAssumed,
        Self::JumptableUnresolved,
        Self::IndirectCallUnresolved,
        Self::LiftUnsupported,
        Self::SpMismatch,
        Self::BudgetFlat,
        Self::StructureSelfcheck,
        Self::AnalysisStale,
        Self::TimeStop,
    ];

    /// The reserved numbers of the catalog.
    pub const RESERVED: [Reserved; 2] = [
        Reserved {
            num: 12,
            name: "W_JUMPTABLE_DISAGREE",
            stretch: "S9",
        },
        Reserved {
            num: 16,
            name: "W_CC_CONFLICT",
            stretch: "S16",
        },
    ];

    /// Gives the frozen number of the code.
    #[must_use]
    pub const fn num(self) -> u16 {
        let _ = self;
        0
    }

    /// Gives the catalog data of the code.
    #[must_use]
    pub const fn info(self) -> CodeInfo {
        let _ = self;
        EMPTY
    }

    /// Gives the `UPPER_SNAKE` name of the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.info().name
    }

    /// Gives the code of a frozen number. A reserved or unknown number gives `None`.
    #[must_use]
    pub fn from_num(num: u16) -> Option<Self> {
        let _ = num;
        None
    }

    /// Gives the code of an `UPPER_SNAKE` name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let _ = name;
        None
    }
}

impl DiagCode {
    /// All codes in number order.
    pub const ALL: [Self; 15] = [
        Self::Oob,
        Self::Overflow,
        Self::BadMagic,
        Self::Limit,
        Self::Loop,
        Self::BadAlign,
        Self::BadEntsize,
        Self::UnsupportedReloc,
        Self::CfaOpcode,
        Self::Overlap,
        Self::Syntax,
        Self::UnknownType,
        Self::IncompleteByValue,
        Self::ConstExpr,
        Self::Unsupported,
    ];

    /// Gives the frozen number of the code.
    #[must_use]
    pub const fn num(self) -> u16 {
        let _ = self;
        0
    }

    /// Gives the catalog data of the code.
    #[must_use]
    pub const fn info(self) -> CodeInfo {
        let _ = self;
        EMPTY
    }

    /// Gives the `UPPER_SNAKE` name of the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.info().name
    }

    /// Gives the code of a frozen number. An unknown number gives `None`.
    #[must_use]
    pub fn from_num(num: u16) -> Option<Self> {
        let _ = num;
        None
    }

    /// Gives the code of an `UPPER_SNAKE` name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let _ = name;
        None
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for DiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Gives the placeholder names of a template in text order, for example `["field"]`.
///
/// A placeholder is `{` and a name of `a-z` and `_`, then `}`.
#[must_use]
pub fn placeholders(template: &str) -> Vec<&str> {
    let _ = template;
    Vec::new()
}

/// Fills the placeholders of a template.
///
/// Each `{key}` with a pair in `args` changes to its value. Other text stays the same.
/// Values must hold no binary text (ADR-0022).
#[must_use]
pub fn render(template: &str, args: &[(&str, &str)]) -> String {
    let _ = (template, args);
    String::new()
}

/// Gives the body of `docs/errors.md`: the three catalogs as Markdown tables.
///
/// The golden header line comes before this body.
#[must_use]
pub fn errors_markdown() -> String {
    String::new()
}
