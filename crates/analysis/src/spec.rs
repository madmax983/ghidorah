//! The analyzer contract (design Section 7.2, ADR-0024).
//!
//! Each analyzer file exports `pub const SPEC: AnalyzerSpec` and a `run` function. The spec
//! gives the name, the priority band, the triggers, the version, the grain and the default
//! options. A lower band runs first. Ties break on the name, then on the address.
//!
//! | Trigger | Event |
//! |---|---|
//! | `Bytes` | The input bytes are new. A fresh run gives each listener every address. |
//! | `Instructions` | Code units or flow references change in a range. |
//! | `Functions` | A function starts, ends or gets a new start reason. |
//! | `FunctionModifiers` | A noreturn flag changes. The range holds the call sites. |
//! | `Signatures` | A signature changes. Only bands 800 and above listen. |
//! | `Data` | A data definition changes. |

use crate::registry::AnalyzerId;

/// The start band of a full re-analysis (design Section 3.9).
pub const BAND_FULL: u16 = 100;

/// The start band of a re-analysis after a signature edit.
pub const BAND_SIGNATURES: u16 = 800;

/// The last band of a triage run.
pub const BAND_TRIAGE: u16 = 700;

/// The kind of a change that queues work for the analyzers that listen to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trigger {
    /// The input bytes.
    Bytes,
    /// Code units and flow references.
    Instructions,
    /// Function starts.
    Functions,
    /// Noreturn flags.
    FunctionModifiers,
    /// Signatures.
    Signatures,
    /// Data definitions.
    Data,
}

impl Trigger {
    /// All triggers in the order of design Section 7.2.
    pub const ALL: [Self; 6] = [
        Self::Bytes,
        Self::Instructions,
        Self::Functions,
        Self::FunctionModifiers,
        Self::Signatures,
        Self::Data,
    ];

    /// Gives the name, for example `function_modifiers`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Instructions => "instructions",
            Self::Functions => "functions",
            Self::FunctionModifiers => "function_modifiers",
            Self::Signatures => "signatures",
            Self::Data => "data",
        }
    }
}

/// How much of its pending set an analyzer takes in one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grain {
    /// The whole pending set.
    Whole,
    /// The first range of the pending set.
    Range,
}

/// One default option of an analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opt {
    /// The name.
    pub name: &'static str,
    /// The default value.
    pub value: u64,
    /// One sentence about the option.
    pub doc: &'static str,
}

/// The spec of one analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalyzerSpec {
    /// The ID.
    pub id: AnalyzerId,
    /// The name of design Section 7.1, for example `Disasm`.
    pub name: &'static str,
    /// The priority band. A lower band runs first.
    pub priority: u16,
    /// The triggers that queue work for the analyzer.
    pub triggers: &'static [Trigger],
    /// The version. A new version changes `analysis_inputs_hash`.
    pub version: u32,
    /// The part of the pending set that one step takes.
    pub grain: Grain,
    /// The default options.
    pub options: &'static [Opt],
    /// One sentence about the analyzer.
    pub doc: &'static str,
}

impl AnalyzerSpec {
    /// Tells if the analyzer listens to `trigger`.
    #[must_use]
    pub fn listens(&self, trigger: Trigger) -> bool {
        self.triggers.contains(&trigger)
    }

    /// Gives the default value of the option `name`.
    #[must_use]
    pub fn option(&self, name: &str) -> Option<u64> {
        self.options
            .iter()
            .find(|o| o.name == name)
            .map(|o| o.value)
    }
}

/// The result of one analyzer step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Step {
    /// The work units of the step. The scheduler takes them from the fuel.
    pub work: u64,
}
