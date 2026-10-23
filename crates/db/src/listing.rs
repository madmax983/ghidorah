//! The listing: code units and data definitions (design Section 3.4).
//!
//! A code unit is an instruction start with an 8-byte payload: length, flow kind and flags.
//! The decoder reads the operands again on demand. A data definition gives a type and a
//! length to an address. Two code units of one layer never overlap, and two data definitions
//! of one layer never overlap (Section 3.11, invariant 5).

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Range;
use ghidorah_types::TypeId;

use crate::fact::{Fact, Invalid, Origin, WriteError, put};

/// The control flow kind of an instruction. The names follow `ghidorah-x86`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowKind {
    /// Execution continues at the next instruction.
    Seq,
    /// A direct jump.
    Jmp,
    /// A conditional branch.
    Jcc,
    /// A direct call.
    Call,
    /// An indirect call.
    ICall,
    /// An indirect jump.
    IJmp,
    /// A return.
    Ret,
    /// An instruction that does not continue.
    Trap,
}

impl FlowKind {
    /// Gives the output name, for example `icall`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Seq => "seq",
            Self::Jmp => "jmp",
            Self::Jcc => "jcc",
            Self::Call => "call",
            Self::ICall => "icall",
            Self::IJmp => "ijmp",
            Self::Ret => "ret",
            Self::Trap => "trap",
        }
    }
}

impl fmt::Display for FlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A code unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeUnit {
    /// An instruction.
    Insn {
        /// The length in bytes, 1 to 15 for x86-64.
        len: u8,
        /// The flow kind.
        flow: FlowKind,
        /// Analyzer flags, for example the `noreturn_call` site flag.
        flags: u8,
    },
}

impl CodeUnit {
    /// Gives the length in bytes.
    #[must_use]
    pub const fn len(&self) -> u8 {
        match self {
            Self::Insn { len, .. } => *len,
        }
    }

    /// Tells if the unit has no bytes. A stored unit always has bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gives the addresses of the unit at `at`, or `None` when the end passes `u64::MAX`.
    #[must_use]
    pub fn range(&self, at: u64) -> Option<Range> {
        Range::with_len(at, u64::from(self.len()))
    }
}

/// A data definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataDef {
    /// The type.
    pub ty: TypeId,
    /// The length in bytes.
    pub len: u32,
}

impl DataDef {
    /// Gives the addresses of the definition at `at`, or `None` for a bad length.
    #[must_use]
    pub fn range(&self, at: u64) -> Option<Range> {
        Range::with_len(at, u64::from(self.len))
    }
}

/// The code units and data definitions of one layer. The keys are RAM offsets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    units: BTreeMap<u64, CodeUnit>,
    data: BTreeMap<u64, Fact<DataDef>>,
}

/// Gives the entry of `map` whose range holds `off`. `range` gives the range of an entry.
fn containing<V>(
    map: &BTreeMap<u64, V>,
    off: u64,
    range: impl Fn(u64, &V) -> Option<Range>,
) -> Option<(u64, &V)> {
    let (start, value) = map.range(..=off).next_back()?;
    range(*start, value)?
        .contains(off)
        .then_some((*start, value))
}

/// Gives the range of an entry of `map` that overlaps `new`. The entry at `skip` does not count.
fn overlap<V>(
    map: &BTreeMap<u64, V>,
    new: Range,
    skip: Option<u64>,
    range: impl Fn(u64, &V) -> Option<Range>,
) -> Option<Range> {
    let before = containing(map, new.first, &range).filter(|(at, _)| Some(*at) != skip);
    let inside = || starts_in(map, new).find(|(at, _)| Some(*at) != skip);
    let (at, value) = before.or_else(inside)?;
    range(at, value)
}

/// Gives the entries of `map` that start in `range`, in key order.
///
/// A range with `first > last` is empty.
pub(crate) fn starts_in<V>(
    map: &BTreeMap<u64, V>,
    range: Range,
) -> impl Iterator<Item = (u64, &V)> {
    map.range(range.first..=range.last.max(range.first))
        .filter(move |(at, _)| **at <= range.last)
        .map(|(at, v)| (*at, v))
}

impl Listing {
    /// Gives the number of code units.
    #[must_use]
    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    /// Gives the code unit that starts at `off`.
    #[must_use]
    pub fn unit(&self, off: u64) -> Option<&CodeUnit> {
        self.units.get(&off)
    }

    /// Gives the code unit whose bytes hold `off`, with its start.
    #[must_use]
    pub fn unit_containing(&self, off: u64) -> Option<(u64, &CodeUnit)> {
        containing(&self.units, off, |at, u| u.range(at))
    }

    /// Gives the code units that start in `range`, in address order.
    pub fn units_in(&self, range: Range) -> impl Iterator<Item = (u64, &CodeUnit)> {
        starts_in(&self.units, range)
    }

    /// Gives the number of data definitions.
    #[must_use]
    pub fn data_count(&self) -> usize {
        self.data.len()
    }

    /// Gives the data definition that starts at `off`.
    #[must_use]
    pub fn data(&self, off: u64) -> Option<&Fact<DataDef>> {
        self.data.get(&off)
    }

    /// Gives the data definition whose bytes hold `off`, with its start.
    #[must_use]
    pub fn data_containing(&self, off: u64) -> Option<(u64, &Fact<DataDef>)> {
        containing(&self.data, off, |at, d| d.value.range(at))
    }

    /// Gives all data definitions in address order.
    pub fn data_defs(&self) -> impl Iterator<Item = (u64, &Fact<DataDef>)> {
        self.data.iter().map(|(k, v)| (*k, v))
    }

    /// Adds an instruction at `off`.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::BadLength`] for a length of 0 or an end past `u64::MAX`, and
    /// [`Invalid::Overlap`] when the bytes overlap another code unit.
    pub(crate) fn insert_unit(&mut self, off: u64, unit: CodeUnit) -> Result<(), Invalid> {
        let new = unit
            .range(off)
            .ok_or_else(|| Invalid::BadLength(u64::from(unit.len())))?;
        if let Some(existing) = overlap(&self.units, new, None, |at, u| u.range(at)) {
            return Err(Invalid::Overlap { new, existing });
        }
        self.units.insert(off, unit);
        Ok(())
    }

    /// Adds the code units of `units`, as [`Self::insert_unit`] does one at a time.
    ///
    /// An empty listing takes units in strict address order in one bulk build, so the map has
    /// full nodes. Then a unit can only overlap the unit before it.
    ///
    /// # Errors
    ///
    /// Returns the position and the error of the first unit that [`Self::insert_unit`]
    /// refuses.
    pub(crate) fn extend_units(
        &mut self,
        units: Vec<(u64, CodeUnit)>,
    ) -> Result<(), (usize, Invalid)> {
        let sorted = units.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0));
        if !self.units.is_empty() || !sorted {
            for (i, (off, unit)) in units.into_iter().enumerate() {
                self.insert_unit(off, unit).map_err(|e| (i, e))?;
            }
            return Ok(());
        }
        let mut before: Option<Range> = None;
        for (i, (off, unit)) in units.iter().enumerate() {
            let new = unit
                .range(*off)
                .ok_or_else(|| (i, Invalid::BadLength(u64::from(unit.len()))))?;
            if let Some(existing) = before.filter(|b| b.last >= new.first) {
                return Err((i, Invalid::Overlap { new, existing }));
            }
            before = Some(new);
        }
        self.units = units.into_iter().collect();
        Ok(())
    }

    /// Removes the code unit that starts at `off` and gives it.
    pub(crate) fn remove_unit(&mut self, off: u64) -> Option<CodeUnit> {
        self.units.remove(&off)
    }

    /// Sets the data definition at `off` by the write rule. `None` removes it. Gives the old
    /// fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::BadLength`], [`Invalid::Overlap`] with another definition, or
    /// [`WriteError::Blocked`] with the current definition.
    pub(crate) fn set_data(
        &mut self,
        off: u64,
        def: Option<DataDef>,
        origin: &Origin,
    ) -> Result<Option<Fact<DataDef>>, WriteError<DataDef>> {
        if let Some(d) = def {
            let new = d
                .range(off)
                .ok_or_else(|| Invalid::BadLength(u64::from(d.len)))?;
            if let Some(existing) = overlap(&self.data, new, Some(off), |at, f| f.value.range(at)) {
                return Err(Invalid::Overlap { new, existing }.into());
            }
        }
        put(&mut self.data, off, def, origin)
    }
}
