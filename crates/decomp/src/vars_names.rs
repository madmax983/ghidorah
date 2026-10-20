//! The storage-based identity of each variable (design Sections 3.5 and 8.3).
//!
//! | Members | Storage |
//! |---|---|
//! | the entry value of argument register `n` | `param:<n>` |
//! | the entry value of floating register `n` of a positional convention, when the body reads no entry value of integer register `n` | `param:<n>` |
//! | the entry value of a stack parameter slot | `param:<n>`, after the register parameters |
//! | a value of the stack slot `k` | `stack:<k>` |
//! | other values | `reg:<name>@<first def address>` |
//!
//! A parameter number must be below the parameter count of the view. The count is the count of
//! the facts ([`crate::Env::param_count`]), or the count of the slots that the L1 body reads
//! when that is more. A call use is a read. An entry value of a later slot is a register value.
//!
//! Two variables never share an identity. A taken identity gets a register storage, and a
//! taken register name gets a number suffix.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::cc::loc_of;
use ghidorah_base::{Storage, VarId};
use ghidorah_ir::{Loc, Val};
use ghidorah_types::CallConv;

use crate::expr::VarIdx;
use crate::vars::{Ctx, kind_of, reg_storage, var_id};
use crate::view::Var;
use crate::view::facts::{Facts, Kind};

/// Gives the parameter slot of an entry location in the convention `conv`. The slot is the
/// position of an integer argument register, or the number of a stack parameter after them.
fn slot_of(conv: &CallConv, loc: Loc) -> Option<u16> {
    if let Some(n) = conv.int_args.iter().position(|r| loc_of(r) == Some(loc)) {
        return u16::try_from(n).ok();
    }
    let Loc::Stack(k) = loc else {
        return None;
    };
    let off = i64::from(conv.stack_arg_offset);
    let k = i64::from(k);
    if k < off || (k - off) % 8 != 0 {
        return None;
    }
    let n = i64::try_from(conv.int_args.len()).ok()? + (k - off) / 8;
    u16::try_from(n).ok()
}

/// Gives the locations whose entry values have a use in the L1 body. A call use counts.
fn inputs_read(f: &Facts<'_>) -> BTreeSet<Loc> {
    f.start
        .iter()
        .filter_map(|&i| f.op(i).and_then(|o| o.out))
        .filter(|v| f.use_count(*v) > 0)
        .filter_map(|v| match f.kind_of(v) {
            Kind::Input(loc) => Some(loc),
            _ => None,
        })
        .collect()
}

/// Gives the count of the parameter slots that the L1 body reads: one more than the highest
/// slot of an entry value with a use.
pub(crate) fn read_slots(f: &Facts<'_>, conv: Option<&CallConv>) -> u16 {
    let Some(conv) = conv else {
        return 0;
    };
    inputs_read(f)
        .into_iter()
        .filter_map(|loc| slot_of(conv, loc))
        .map(|n| n.saturating_add(1))
        .max()
        .unwrap_or(0)
}

/// The namer of the variables of one view.
pub(crate) struct Namer<'a> {
    cx: &'a Ctx<'a>,
    home: &'a BTreeMap<Val, Loc>,
    vars: Vec<Var>,
    taken: BTreeSet<VarId>,
    /// The locations whose entry values the L1 body reads.
    read: BTreeSet<Loc>,
}

/// Gives the register name of a location: its lower-case letters and digits.
fn loc_name(loc: Loc) -> String {
    if matches!(loc, Loc::Stack(_)) {
        return "stack".to_owned();
    }
    let name: String = loc
        .to_string()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    if name.starts_with(|c: char| c.is_ascii_lowercase()) {
        name
    } else {
        "v".to_owned()
    }
}

impl<'a> Namer<'a> {
    /// Makes a namer.
    pub(crate) fn new(cx: &'a Ctx<'a>, home: &'a BTreeMap<Val, Loc>) -> Self {
        Self {
            cx,
            home,
            vars: Vec::new(),
            taken: BTreeSet::new(),
            read: inputs_read(cx.f),
        }
    }

    /// Gives the parameter number of an entry location. A number at or above the parameter
    /// count of the view gives `None`, so an entry value of such a register is a register
    /// value.
    fn param(&self, loc: Loc) -> Option<u16> {
        let n = self.slot(loc)?;
        let count = self.cx.params.unwrap_or(u16::MAX);
        (n < count).then_some(n)
    }

    /// Gives the parameter slot of an entry location in the calling convention. In a
    /// positional convention, floating register n has slot n when the body reads no entry
    /// value of integer register n.
    fn slot(&self, loc: Loc) -> Option<u16> {
        let conv = self.cx.conv?;
        if let Some(n) = slot_of(conv, loc) {
            return Some(n);
        }
        let k = conv
            .float_args
            .iter()
            .position(|r| loc_of(r) == Some(loc))
            .filter(|_| conv.positional)?;
        let int = conv.int_args.get(k).and_then(|r| loc_of(r))?;
        (!self.read.contains(&int)).then(|| u16::try_from(k).ok())?
    }

    /// Gives a free register storage with the base name `name`.
    fn free_reg(&self, name: &str, def: u64) -> Option<Storage> {
        let entry = self.cx.entry;
        for k in 0..=self.vars.len() {
            let candidate = if k == 0 {
                name.to_owned()
            } else {
                format!("{name}{k}")
            };
            let s = reg_storage(&candidate, def)?;
            if !self.taken.contains(&var_id(entry, s.clone())) {
                return Some(s);
            }
        }
        None
    }

    /// Adds a variable with the first free storage of `wanted`, then of a register storage.
    fn push(
        &mut self,
        wanted: Option<Storage>,
        name: &str,
        def: u64,
        w: u8,
        home: Option<Loc>,
        input: Option<Loc>,
    ) -> VarIdx {
        let entry = self.cx.entry;
        let storage = wanted
            .filter(|s| !self.taken.contains(&var_id(entry, s.clone())))
            .or_else(|| self.free_reg(name, def))
            .unwrap_or(Storage::Ret);
        let id = var_id(entry, storage.clone());
        self.taken.insert(id.clone());
        let idx = VarIdx(u32::try_from(self.vars.len()).unwrap_or(u32::MAX));
        self.vars.push(Var {
            id,
            w,
            kind: kind_of(&storage),
            home,
            input,
        });
        idx
    }

    /// Adds the variable of a class of values.
    pub(crate) fn class(&mut self, members: &[Val]) -> VarIdx {
        let f = self.cx.f;
        let w = members
            .iter()
            .filter_map(|v| f.ssa.value_width(*v))
            .max()
            .unwrap_or(64);
        let input = members.iter().find_map(|v| match f.kind_of(*v) {
            Kind::Input(loc) => Some(loc),
            _ => None,
        });
        let home = input.or_else(|| members.iter().find_map(|v| self.home.get(v).copied()));
        let def = if input.is_some() {
            self.cx.entry
        } else {
            members
                .iter()
                .filter_map(|v| f.def.get(v).and_then(|&i| f.op(i)).map(|o| o.id.addr))
                .min()
                .unwrap_or(self.cx.entry)
        };
        let wanted = match (input, home) {
            (Some(loc), _) => self.param(loc).map(Storage::Param),
            (None, Some(Loc::Stack(k))) => Some(Storage::Stack(i64::from(k))),
            _ => None,
        };
        let name = home.map_or_else(|| "tmp".to_owned(), loc_name);
        self.push(wanted, &name, def, w, home, input)
    }

    /// Adds a temporary variable for a cycle of copies.
    pub(crate) fn temp(&mut self, w: u8, addr: u64) -> VarIdx {
        self.push(None, "tmp", addr, w, None, None)
    }

    /// Gives the width of a variable.
    pub(crate) fn width(&self, v: VarIdx) -> u8 {
        self.vars.get(v.index()).map_or(64, |x| x.w)
    }

    /// Gives the variables.
    pub(crate) fn into_vars(self) -> Vec<Var> {
        self.vars
    }
}
