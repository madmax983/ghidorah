//! The function manager and the ownership map (design Sections 3.2 and 3.4).
//!
//! Each function of a layer has a body: a [`RangeSet`] of RAM offsets that holds its entry.
//! The ownership map is an [`IntervalMap`] from each body range to its [`FuncId`]. So the
//! bodies of one layer are disjoint by construction (Section 3.11, invariant 3).
//! A body can end at `u64::MAX`. The range math uses the inclusive ranges of kernel K2.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, FuncId, IntervalError, IntervalMap, Range, WarningCode};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use crate::fact::{Fact, Invalid, Origin, WriteError, put_slot};
use crate::source::Source;

/// The kind of a function part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartKind {
    /// The main part with the entry.
    Main,
    /// A `.cold` part. It is a range of its parent, not a separate function.
    Cold,
    /// A thunk part.
    Thunk,
}

/// One part of a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Part {
    /// The addresses of the part.
    pub range: Range,
    /// The kind.
    pub kind: PartKind,
}

/// Why a function exists (design Section 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StartReason {
    /// An entry point of the binary.
    Entry,
    /// An `STT_FUNC` symbol with a size above 0.
    Symbol,
    /// A PLT stub named through relocations.
    PltStub,
    /// `main` from the first argument of `__libc_start_main`.
    Main,
    /// A PE `.pdata` entry.
    Pdata,
    /// An FDE PC begin.
    Fde,
    /// A direct call target.
    Call,
    /// A tail-call target.
    TailCall,
    /// An `endbr64` head.
    Endbr,
    /// An agent `func_edit create`.
    Agent,
}

impl StartReason {
    /// All reasons in the order of Section 7.3.
    pub const ALL: [Self; 10] = [
        Self::Entry,
        Self::Symbol,
        Self::PltStub,
        Self::Main,
        Self::Pdata,
        Self::Fde,
        Self::Call,
        Self::TailCall,
        Self::Endbr,
        Self::Agent,
    ];

    /// Gives the output name, for example `plt_stub`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Symbol => "symbol",
            Self::PltStub => "plt_stub",
            Self::Main => "main",
            Self::Pdata => "pdata",
            Self::Fde => "fde",
            Self::Call => "call",
            Self::TailCall => "tail_call",
            Self::Endbr => "endbr",
            Self::Agent => "agent",
        }
    }

    /// Gives the reason of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

impl fmt::Display for StartReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A caveat of a function: a warning code, a place and a remedy call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Caveat {
    /// The warning code.
    pub code: WarningCode,
    /// The address that the caveat names.
    pub at: Option<Address>,
    /// The remedy, for example `func_edit { action: "set_noreturn" }`.
    pub remedy: Option<String>,
}

/// The flags of a function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FuncFlags {
    /// The noreturn fact.
    pub noreturn: Option<Fact<bool>>,
    /// The function is a thunk.
    pub thunk: bool,
    /// The function takes a variable argument list.
    pub varargs: bool,
}

/// One function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// The entry. Its name is the `FUNCTION` symbol at the entry.
    pub entry: Address,
    /// The body. It holds the entry.
    pub body: RangeSet,
    /// The parts in address order.
    pub parts: Vec<Part>,
    /// The signature: the [`TypeId`] of a function type.
    pub sig: Option<Fact<TypeId>>,
    /// The flags.
    pub flags: FuncFlags,
    /// Why the function exists.
    pub start_reason: StartReason,
    /// The confidence, 0 to 100 (Section 7.3).
    pub confidence: u8,
    /// The caveats.
    pub caveats: Vec<Caveat>,
    /// `Analysis` for a discovered function, `Agent` or `User` for `func_edit create`.
    pub source: Source,
}

impl Function {
    /// Makes a function whose body is the one byte at `entry`.
    #[must_use]
    pub fn new(entry: Address, start_reason: StartReason, confidence: u8, source: Source) -> Self {
        let mut body = RangeSet::new();
        body.insert(Range::single(entry.off));
        Self {
            entry,
            body,
            parts: Vec::new(),
            sig: None,
            flags: FuncFlags::default(),
            start_reason,
            confidence: confidence.min(100),
            caveats: Vec::new(),
            source,
        }
    }

    /// Gives the ID.
    #[must_use]
    pub const fn id(&self) -> FuncId {
        FuncId(self.entry)
    }

    /// Gives the number of bytes of the body. A full body holds 2^64 bytes, so the type is `u128`.
    #[must_use]
    pub fn size(&self) -> u128 {
        self.body.ranges().iter().map(Range::len).sum()
    }
}

/// The functions of one layer and their ownership map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Funcs {
    by_entry: BTreeMap<Address, Function>,
    owner: IntervalMap<FuncId>,
}

impl Funcs {
    /// Gives the number of functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_entry.len()
    }

    /// Tells if the layer has no function.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_entry.is_empty()
    }

    /// Gives the function with this ID.
    #[must_use]
    pub fn get(&self, id: FuncId) -> Option<&Function> {
        self.by_entry.get(&id.0)
    }

    /// Gives all functions in entry order.
    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.by_entry.values()
    }

    /// Gives the function that owns the RAM offset `off`.
    #[must_use]
    pub fn owner_of(&self, off: u64) -> Option<FuncId> {
        self.owner.get(off).copied()
    }

    /// Gives the body range that holds `off` and its owner.
    #[must_use]
    pub fn owner_range(&self, off: u64) -> Option<(Range, FuncId)> {
        self.owner.find(off).map(|(r, id)| (r, *id))
    }

    /// Gives the ownership map: each body range with its owner, in address order.
    #[must_use]
    pub fn ownership(&self) -> &[(Range, FuncId)] {
        self.owner.as_slice()
    }

    /// Gives the owners of the ranges that overlap `range`, in entry order. A function with
    /// two such ranges comes once.
    #[must_use]
    pub fn owners_in(&self, range: Range) -> Vec<FuncId> {
        let owners: BTreeSet<FuncId> = self
            .owner
            .overlapping(range)
            .iter()
            .map(|(_, id)| *id)
            .collect();
        owners.into_iter().collect()
    }

    /// Checks a body for the function `id` at `entry`. Ranges of `id` itself do not count.
    fn check_body(&self, id: FuncId, body: &RangeSet) -> Result<(), Invalid> {
        if !body.contains(id.0.off) {
            return Err(Invalid::EntryOutsideBody(id.0));
        }
        for new in body.ranges() {
            if let Some((existing, _)) = self.owner.overlapping(*new).iter().find(|(_, o)| *o != id)
            {
                return Err(Invalid::Overlap {
                    new: *new,
                    existing: *existing,
                });
            }
        }
        Ok(())
    }

    /// Adds the ranges of `body` to the ownership map. The caller checks them first.
    fn own(&mut self, id: FuncId, body: &RangeSet) -> Result<(), Invalid> {
        let items = body.ranges().iter().map(|r| (*r, id)).collect();
        self.owner.extend_sorted(items).map_err(|e| match e {
            IntervalError::Overlap { new, existing } => Invalid::Overlap { new, existing },
            IntervalError::InvalidRange(r) => Invalid::BadLength(r.first),
        })
    }

    /// Removes the ranges of `body` from the ownership map.
    fn disown(&mut self, body: &RangeSet) {
        for r in body.ranges() {
            self.owner.clear_range(*r);
        }
    }

    /// Adds a function and its body ranges to the ownership map.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::NotRam`], [`Invalid::FuncExists`], [`Invalid::EntryOutsideBody`] or
    /// [`Invalid::Overlap`] with the first range of another body that the body overlaps.
    /// Then the layer does not change.
    pub(crate) fn insert(&mut self, func: Function) -> Result<(), Invalid> {
        let id = func.id();
        if !id.0.is_ram() {
            return Err(Invalid::NotRam(id.0));
        }
        if self.by_entry.contains_key(&id.0) {
            return Err(Invalid::FuncExists(id));
        }
        self.check_body(id, &func.body)?;
        self.own(id, &func.body)?;
        self.by_entry.insert(id.0, func);
        Ok(())
    }

    /// Removes a function and its ownership ranges. Gives the function.
    pub(crate) fn remove(&mut self, id: FuncId) -> Option<Function> {
        let func = self.by_entry.remove(&id.0)?;
        self.disown(&func.body);
        Some(func)
    }

    /// Sets the body of a function. Gives the old body.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::NoFunc`], [`Invalid::EntryOutsideBody`] or [`Invalid::Overlap`].
    /// Then the layer does not change.
    pub(crate) fn set_body(&mut self, id: FuncId, body: RangeSet) -> Result<RangeSet, Invalid> {
        let old = self.get(id).ok_or(Invalid::NoFunc(id))?.body.clone();
        self.check_body(id, &body)?;
        self.disown(&old);
        self.own(id, &body)?;
        if let Some(func) = self.by_entry.get_mut(&id.0) {
            func.body = body;
        }
        Ok(old)
    }

    /// Sets the signature fact by the write rule. `None` removes it. Gives the old fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::NoFunc`] or [`WriteError::Blocked`] with the current signature.
    pub(crate) fn set_sig(
        &mut self,
        id: FuncId,
        sig: Option<TypeId>,
        origin: &Origin,
    ) -> Result<Option<Fact<TypeId>>, WriteError<TypeId>> {
        let func = self.by_entry.get_mut(&id.0).ok_or(Invalid::NoFunc(id))?;
        put_slot(&mut func.sig, sig, origin)
    }

    /// Sets the noreturn fact by the write rule. `None` removes it. Gives the old fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::NoFunc`] or [`WriteError::Blocked`] with the current flag.
    pub(crate) fn set_noreturn(
        &mut self,
        id: FuncId,
        noreturn: Option<bool>,
        origin: &Origin,
    ) -> Result<Option<Fact<bool>>, WriteError<bool>> {
        let func = self.by_entry.get_mut(&id.0).ok_or(Invalid::NoFunc(id))?;
        put_slot(&mut func.flags.noreturn, noreturn, origin)
    }
}
