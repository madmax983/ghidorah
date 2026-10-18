//! The verdict of a claim with its evidence and its absence basis (design Section 11.8).
//!
//! An [`Outcome`] holds the [`Verdict`], the [`Evidence`] items and the [`Gap`] items. A gap
//! blocks a sound negative verdict. The texts of evidence and gaps are IDs or addresses.

use std::fmt;

use ghidorah_base::{Address, ExportId, FuncId};
use ghidorah_db::RefKey;

/// The verdict of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// The facts hold the claim.
    Supported,
    /// The facts are complete, and they hold the negation of the claim.
    Refuted,
    /// The facts do not decide the claim.
    Unknown,
}

impl Verdict {
    /// Gives the name: `supported`, `refuted` or `unknown`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Refuted => "refuted",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One item of evidence of a verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    /// A reference: its `ref:` ID.
    Ref(RefKey),
    /// The indirect target override at a site: the site address.
    Override(Address),
    /// A call site, a syscall site or a return: its address.
    Site(Address),
    /// A function: its `fn:` ID.
    Func(FuncId),
}

impl Evidence {
    /// Gives the ID text, for example `ref:0x1136>0x2010:read` or `0x1014`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Ref(k) => ref_text(k),
            Self::Override(a) | Self::Site(a) => a.to_string(),
            Self::Func(f) => f.to_string(),
        }
    }
}

/// One item that blocks a sound negative verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Gap {
    /// A site with no known target or value: an indirect call or jump, a syscall site with no
    /// number, or a call site with an unknown argument value.
    Site(Address),
    /// A reference that takes an address: the code can get to the target another way.
    Ref(RefKey),
    /// An export: code outside the binary can call it.
    Export(ExportId),
    /// A function with no fact that decides the claim.
    Func(FuncId),
}

impl Gap {
    /// Gives the ID text, for example `0x1014` or `exp:main`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Site(a) => a.to_string(),
            Self::Ref(k) => ref_text(k),
            Self::Export(e) => e.to_string(),
            Self::Func(f) => f.to_string(),
        }
    }
}

/// Gives the `ref:` ID text of a reference, or its source address when the kind has no ID.
fn ref_text(key: &RefKey) -> String {
    key.id()
        .map_or_else(|_| key.from.to_string(), |id| id.to_string())
}

/// The verdict of one claim with its evidence and its gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The verdict.
    pub verdict: Verdict,
    /// The evidence in sorted order with no duplicate.
    pub evidence: Vec<Evidence>,
    /// The gaps in sorted order with no duplicate.
    pub gaps: Vec<Gap>,
    /// The check ran out of fuel.
    pub stopped: bool,
}

impl Outcome {
    /// Makes an outcome. The evidence and the gaps go in sorted order with no duplicate.
    #[must_use]
    pub fn new(verdict: Verdict, mut evidence: Vec<Evidence>, mut gaps: Vec<Gap>) -> Self {
        evidence.sort();
        evidence.dedup();
        gaps.sort();
        gaps.dedup();
        Self {
            verdict,
            evidence,
            gaps,
            stopped: false,
        }
    }

    /// Makes the outcome of a check that ran out of fuel: `unknown` with no evidence.
    #[must_use]
    pub const fn out_of_fuel() -> Self {
        Self {
            verdict: Verdict::Unknown,
            evidence: Vec::new(),
            gaps: Vec::new(),
            stopped: true,
        }
    }

    /// Tells if the facts of the check are complete: no gap, and the fuel did not run out.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.gaps.is_empty() && !self.stopped
    }

    /// Changes a `refuted` verdict to `unknown`. A read of a partial analysis uses it, because
    /// a negative verdict is not sound then.
    pub fn weaken(&mut self) {
        if self.verdict == Verdict::Refuted {
            self.verdict = Verdict::Unknown;
        }
    }
}
