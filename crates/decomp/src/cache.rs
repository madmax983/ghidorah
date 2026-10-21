//! The decompile cache (design Section 8.5, AC-104b).
//!
//! The key is `(FuncId, func_epoch, options hash)`. A rename, a retype, a comment or a
//! signature change of the function or of a callee changes `func_epoch` (design Section 3.8),
//! so the next lookup misses. The target of a tail jump is a callee too. The cache holds at most its capacity of outputs. A full cache
//! drops the entry with the oldest use. The use counter is a plain counter, so the order is
//! deterministic.
//!
//! One render also has a memo of the parameter facts of each function (`RenderEnv`). The L1
//! build, the view, the head and the printer share it.

use std::cell::{RefCell, RefMut};
use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_analysis::cc::conv_of;
use ghidorah_analysis::fir::callsite::{self, Memo, ParamFacts};
use ghidorah_analysis::fir::ret::{RetValue, ret_value_in};
use ghidorah_base::{Address, Fnv1a64, Fuel, FuncId, Rev, VarId};
use ghidorah_db::{CommentKind, Program};
use ghidorah_ir::{IntrinsicNames, Loc};
use ghidorah_types::{CallConv, DataModel, TypeId, TypeStore};

use crate::{DecompError, Env, Opts, Output, ParamInfo, PrintEnv, ProgramEnv, Signature};

/// The default capacity of a cache: 512 outputs (design Section 3.9).
pub const DEFAULT_CAPACITY: usize = 512;

/// The key of a cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// The function.
    pub func: FuncId,
    /// The epoch of the function.
    pub epoch: Rev,
    /// The hash of the decompile options.
    pub opts: u64,
}

/// Gives the FNV-1a 64 hash of the options.
#[must_use]
pub fn opts_hash(opts: &Opts) -> u64 {
    let mut h = Fnv1a64::new();
    h.write(
        &u64::try_from(opts.max_nodes)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    let p = opts.passes;
    for flag in [p.fold, p.sailr, p.canary, p.tailcall] {
        h.write_u8(u8::from(flag));
    }
    h.finish()
}

/// Gives the key of a decompile of `func` in `program` with `opts`.
#[must_use]
pub fn key(program: &Program, func: FuncId, opts: &Opts) -> Key {
    Key {
        func,
        epoch: program.func_epoch(func),
        opts: opts_hash(opts),
    }
}

/// The counts of the lookups of a cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Stats {
    /// The lookups that found an entry.
    pub hits: u64,
    /// The lookups that found no entry.
    pub misses: u64,
}

/// A cache of decompile outputs.
#[derive(Debug, Clone, Default)]
pub struct Cache {
    capacity: usize,
    tick: u64,
    entries: BTreeMap<Key, (u64, Arc<Output>)>,
    stats: Stats,
}

impl Cache {
    /// Makes an empty cache with room for `capacity` outputs. A capacity of 0 counts as 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            entries: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    /// Gives the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the cache has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gives the lookup counts.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Gives the next use count.
    const fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.saturating_add(1);
        self.tick
    }

    /// Gives the output of `key` and counts a hit, or counts a miss.
    pub fn get(&mut self, key: &Key) -> Option<Arc<Output>> {
        let tick = self.next_tick();
        if let Some((used, out)) = self.entries.get_mut(key) {
            *used = tick;
            self.stats.hits = self.stats.hits.saturating_add(1);
            return Some(Arc::clone(out));
        }
        self.stats.misses = self.stats.misses.saturating_add(1);
        None
    }

    /// Puts the output of `key`. A full cache drops the entry with the oldest use first.
    pub fn put(&mut self, key: Key, output: Output) -> Arc<Output> {
        let tick = self.next_tick();
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(k, (used, _))| (*used, **k))
                    .map(|(k, _)| *k);
                match oldest {
                    Some(k) => {
                        let _ = self.entries.remove(&k);
                    }
                    None => break,
                }
            }
        }
        let out = Arc::new(output);
        self.entries.insert(key, (tick, Arc::clone(&out)));
        out
    }

    /// Gives the output of `func` from the cache, or renders and puts it. The flag tells if
    /// the lookup found the entry.
    ///
    /// # Errors
    ///
    /// Returns the [`DecompError`] of the render.
    pub fn render(
        &mut self,
        program: &Program,
        func: FuncId,
        opts: &Opts,
        names: &dyn IntrinsicNames,
        fuel: &mut Fuel,
    ) -> Result<(Arc<Output>, bool), DecompError> {
        let key = key(program, func, opts);
        if let Some(out) = self.get(&key) {
            return Ok((out, true));
        }
        let out = crate::render(program, func, opts, names, fuel)?;
        Ok((self.put(key, out), false))
    }
}

/// The largest fuel of the parameter queries of one render.
const PARAM_FUEL: u64 = 1_000_000;

/// Gives the count of the integer and stack parameter slots of `facts` (see
/// [`Env::param_count`]). A function with no count gives `None`: it passes its registers on to
/// an import with no Tier-0 prototype in a tail jump, as a thunk does.
pub(crate) fn slot_count(program: &Program, facts: &ParamFacts) -> Option<u8> {
    let p = facts.params;
    let conv = conv_of(program);
    if facts.open {
        return None;
    }
    if p.stack > 0 {
        let regs = u8::try_from(conv.int_args.len()).unwrap_or(u8::MAX);
        return Some(regs.saturating_add(p.stack));
    }
    // A positional slot is its position, so the count holds the floating slots too.
    Some(if conv.positional {
        p.int.saturating_add(p.float)
    } else {
        p.int
    })
}

/// Gives the slot of each parameter of the function at `addr` with the facts `facts`, in
/// slot order (see [`Env::param_slots`]). A function with no count gives `None`.
///
/// - A positional convention gives the register of each register slot that the recovery
///   chose ([`callsite::arg_regs`]). A signature or a prototype gives `None`.
/// - Another convention (`SysV`) gives the integer registers, then the floating registers,
///   then the stack slots of the recovery. A signature or a prototype gives the slots of its
///   parameter classes ([`callsite::fixed_slots`]).
pub(crate) fn param_slots(program: &Program, addr: u64, facts: &ParamFacts) -> Option<Vec<Loc>> {
    if facts.open {
        return None;
    }
    let conv = conv_of(program);
    let Some(live) = facts.live.as_ref() else {
        return (!conv.positional)
            .then(|| callsite::fixed_slots(program, FuncId(Address::ram(addr))))
            .flatten();
    };
    let mut out = callsite::arg_regs(conv, &facts.params, Some(live));
    if !conv.positional {
        let first = i64::from(conv.stack_arg_offset);
        out.extend((0..i64::from(facts.params.stack)).filter_map(|j| {
            let k = first.checked_add(j.checked_mul(8)?)?;
            i32::try_from(k).ok().map(Loc::Stack)
        }));
    }
    Some(out)
}

/// Gives the parameter count of `facts` with its source and its varargs flag.
pub(crate) fn param_info(program: &Program, facts: &ParamFacts) -> Option<ParamInfo> {
    Some(ParamInfo {
        count: slot_count(program, facts)?,
        source: facts.source,
        varargs: facts.params.varargs,
    })
}

/// Gives the parameter facts of the function at `addr` with the solve memo `memo`.
pub(crate) fn param_facts(
    program: &Program,
    addr: u64,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Option<ParamFacts> {
    callsite::param_facts(program, FuncId(Address::ram(addr)), memo, fuel).ok()
}

/// The facts of a program for one render (r3-engine-07).
///
/// One memo holds the parameter facts of each function. So the L1 build, the view, the head
/// and the printer share one solve of each function. The parameter queries take their fuel
/// from one tank of at most [`PARAM_FUEL`] units. [`RenderEnv::charge`] takes those units from
/// the fuel of the render.
pub(crate) struct RenderEnv<'a> {
    /// The facts of the program.
    env: ProgramEnv<'a>,
    /// The solve memo of the render.
    memo: RefCell<Memo>,
    /// The parameter facts of each function so far.
    facts: RefCell<BTreeMap<u64, Option<ParamFacts>>>,
    /// The return value of each callee so far.
    rets: RefCell<BTreeMap<u64, Option<RetValue>>>,
    /// The fuel of the parameter queries.
    fuel: RefCell<Fuel>,
}

impl<'a> RenderEnv<'a> {
    /// Makes the environment of one render of `program`. `fuel` is the fuel of the render.
    pub(crate) fn new(program: &'a Program, fuel: &Fuel) -> Self {
        Self {
            env: ProgramEnv(program),
            memo: RefCell::new(Memo::default()),
            facts: RefCell::new(BTreeMap::new()),
            rets: RefCell::new(BTreeMap::new()),
            fuel: RefCell::new(Fuel::new(fuel.remaining().min(PARAM_FUEL))),
        }
    }

    /// Gives the solve memo of the render.
    pub(crate) fn memo(&self) -> RefMut<'_, Memo> {
        self.memo.borrow_mut()
    }

    /// Gives the parameter facts of the function at `addr`, from the memo when it has them.
    pub(crate) fn facts(&self, addr: u64) -> Option<ParamFacts> {
        if let Some(found) = self.facts.borrow().get(&addr) {
            return found.clone();
        }
        let found = param_facts(
            self.env.0,
            addr,
            &mut self.memo.borrow_mut(),
            &mut self.fuel.borrow_mut(),
        );
        self.facts.borrow_mut().insert(addr, found.clone());
        found
    }

    /// Takes the units of the parameter queries from `fuel`. A short tank becomes empty.
    pub(crate) fn charge(&self, fuel: &mut Fuel) {
        let used = self.fuel.borrow().used();
        // A failed take empties the tank, so the next step of the caller stops.
        let _ = fuel.take(used);
    }
}

impl Env for RenderEnv<'_> {
    fn callee_name(&self, addr: u64) -> Option<String> {
        self.env.callee_name(addr)
    }

    fn is_noreturn(&self, addr: u64) -> bool {
        self.env.is_noreturn(addr)
    }

    fn is_string(&self, addr: u64) -> bool {
        self.env.is_string(addr)
    }

    fn is_thunk(&self, entry: u64) -> bool {
        self.env.is_thunk(entry)
    }

    fn import_at_slot(&self, slot: u64) -> Option<u64> {
        self.env.import_at_slot(slot)
    }

    fn param_count(&self, addr: u64) -> Option<u8> {
        self.facts(addr).and_then(|f| slot_count(self.env.0, &f))
    }

    fn param_info(&self, addr: u64) -> Option<ParamInfo> {
        self.facts(addr).and_then(|f| param_info(self.env.0, &f))
    }

    fn param_slots(&self, addr: u64) -> Option<Vec<Loc>> {
        self.facts(addr)
            .and_then(|f| param_slots(self.env.0, addr, &f))
    }

    fn jumptable_unresolved(&self, site: u64) -> bool {
        self.env.jumptable_unresolved(site)
    }
}

impl PrintEnv for RenderEnv<'_> {
    fn var_name(&self, id: &VarId) -> Option<(String, &'static str)> {
        self.env.var_name(id)
    }

    fn var_type(&self, id: &VarId) -> Option<TypeId> {
        self.env.var_type(id)
    }

    fn comments(&self, entry: u64) -> Vec<(u64, CommentKind, String)> {
        self.env.comments(entry)
    }

    fn signature(&self, addr: u64) -> Option<Signature> {
        self.env.signature(addr)
    }

    fn string_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        self.env.string_bytes(addr)
    }

    fn types(&self) -> Option<(&TypeStore, &DataModel)> {
        self.env.types()
    }

    fn call_targets(&self, site: u64) -> Vec<u64> {
        self.env.call_targets(site)
    }

    fn syscall_name(&self, nr: u64) -> Option<&'static str> {
        self.env.syscall_name(nr)
    }

    fn conv(&self) -> &'static CallConv {
        self.env.conv()
    }

    fn ret_value(&self, addr: u64) -> Option<RetValue> {
        if let Some(found) = self.rets.borrow().get(&addr) {
            return *found;
        }
        let found = ret_value_in(
            self.env.0,
            addr,
            &mut self.memo.borrow_mut(),
            &mut self.fuel.borrow_mut(),
        );
        self.rets.borrow_mut().insert(addr, found);
        found
    }
}
