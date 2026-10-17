//! Source ranks and the provenance write rule (design Section 3.6, ADR-0013).
//!
//! | Rank | Source | Who writes it |
//! |---|---|---|
//! | 1 | [`Source::Default`] | computed defaults. The DB never stores them. |
//! | 2 | [`Source::Analysis`] | analyzers |
//! | 3 | [`Source::Agent`] | MCP and CLI calls |
//! | 4 | [`Source::Imported`] | symbol tables, relocation names and PLT names |
//! | 5 | [`Source::User`] | `ghidorah call --source user` |
//!
//! A write succeeds when its rank is at least the rank of the current fact.
//! An `Agent` write over an `Imported` fact succeeds only with `force`.
//! Kernel K7 ([`ghidorah_kernel::may_overwrite`]) proves this rule.
//! The journal and the snapshots keep the rank numbers, so the numbers never change.

use std::fmt;

use ghidorah_kernel::source as k7;

/// The source of a fact. The discriminant is the persisted rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Source {
    /// A computed default. The DB never stores a fact with this source.
    Default = k7::DEFAULT,
    /// An analyzer.
    Analysis = k7::ANALYSIS,
    /// An MCP or CLI call. Every tool call writes with this source by default.
    Agent = k7::AGENT,
    /// The binary: symbol tables, dynamic symbols, relocation names and PLT names.
    Imported = k7::IMPORTED,
    /// A human at the terminal.
    User = k7::USER,
}

impl Source {
    /// All sources in rank order.
    pub const ALL: [Self; 5] = [
        Self::Default,
        Self::Analysis,
        Self::Agent,
        Self::Imported,
        Self::User,
    ];

    /// Gives the persisted rank, 1 to 5.
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Gives the source of a rank. A rank outside 1 to 5 gives `None`.
    #[must_use]
    pub const fn from_rank(rank: u8) -> Option<Self> {
        match rank {
            k7::DEFAULT => Some(Self::Default),
            k7::ANALYSIS => Some(Self::Analysis),
            k7::AGENT => Some(Self::Agent),
            k7::IMPORTED => Some(Self::Imported),
            k7::USER => Some(Self::User),
            _ => None,
        }
    }

    /// Gives the output name, for example `agent`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Analysis => "analysis",
            Self::Agent => "agent",
            Self::Imported => "imported",
            Self::User => "user",
        }
    }

    /// Gives the source of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The result of the write rule for one write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// The new rank is at least the old rank.
    Allowed,
    /// An `Agent` write replaces an `Imported` fact with `force`. The journal records the flag.
    Forced,
    /// The write fails with `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`.
    Blocked {
        /// The same write with `force: true` succeeds.
        force_applies: bool,
    },
}

impl Verdict {
    /// Tells if the write succeeds.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        !matches!(self, Self::Blocked { .. })
    }
}

/// Gives the verdict of a write with the source `new` over a fact with the source `old`.
#[must_use]
pub fn write_rule(old: Source, new: Source, force: bool) -> Verdict {
    let agent_over_imported = old == Source::Imported && new == Source::Agent;
    if !ghidorah_kernel::may_overwrite(old.rank(), new.rank(), force) {
        Verdict::Blocked {
            force_applies: agent_over_imported,
        }
    } else if new.rank() >= old.rank() {
        Verdict::Allowed
    } else {
        Verdict::Forced
    }
}
