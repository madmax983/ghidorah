//! `Disasm` (band 300): recursive descent from each function entry (design Sections 7.3, 7.7).
//!
//! The descent follows fall-through, branch and call edges. It stops at these addresses:
//!
//! | Address | Result |
//! |---|---|
//! | the entry of another function | an exit: a tail call or a fall into that function |
//! | an address in the declared extent of another function | an exit |
//! | code of a function with a lower entry | an exit: the lower entry keeps shared code |
//! | an address outside executable memory, bad bytes, a jump into an instruction | `unknown` |
//! | the address after a call to a noreturn function | no edge: the site gets [`UNIT_NORETURN_CALL`] |
//! | an indirect jump or call to the constant 0 | the site gets [`UNIT_NULL_TARGET`] |
//!
//! Each instruction becomes a code unit with `R_DISASM_FLOW`. Each direct call and jump gives
//! a flow reference with `R_FLOW_REF`. A call or a jump through an import slot gives a
//! reference to the EXTERNAL address of the import. The slot is the memory operand, or the
//! slot in a register that `JumpTables` finds ([`crate::slotsite`]).

use std::collections::BTreeSet;

use ghidorah_base::{Address, FuncId, Range};
use ghidorah_db::{FactKey, RefKey, RefType};
use ghidorah_kernel::RangeSet;
use ghidorah_x86::{Flow, Insn};

use crate::code::{decode_at, flow_kind, is_exec, is_mapped, slot_of};
use crate::ctx::{
    AnalysisCtx, Body, UNIT_NORETURN_ASSUMED, UNIT_NORETURN_CALL, UNIT_NULL_TARGET, UnitRec,
};
use crate::overrides::SiteFlow;
use crate::registry::AnalyzerId;
use crate::slotsite::SiteTarget;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};

/// The largest number of instructions in one function body.
pub const MAX_INSNS: u64 = 100_000;

/// The largest number of code units of the program. A walk stops at the cap, so the memory
/// of the analysis stays bounded for a large or hostile binary.
pub const MAX_UNITS: u64 = 8_388_608;

/// The largest number of body changes of one function. Then its body stays.
pub const MAX_CHANGES: u64 = 64;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Disasm,
    name: "Disasm",
    priority: 300,
    triggers: &[Trigger::Functions, Trigger::FunctionModifiers],
    version: 1,
    grain: Grain::Range,
    options: &[
        Opt {
            name: "max_insns",
            value: MAX_INSNS,
            doc: "The largest number of instructions in one function body.",
        },
        Opt {
            name: "max_units",
            value: MAX_UNITS,
            doc: "The largest number of code units of the program.",
        },
        Opt {
            name: "max_changes",
            value: MAX_CHANGES,
            doc: "The largest number of body changes of one function.",
        },
    ],
    doc: "Decodes the body of each function by recursive descent.",
};

/// Runs one step over `ranges`: each function that the ranges touch gets a new body.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    if !ctx.program().meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        if ctx.changes(entry) >= MAX_CHANGES {
            continue;
        }
        let walk = Walk::new(ctx, entry).run();
        let (insns, body, capped) = (walk.insns, walk.body, walk.capped);
        work = work.saturating_add(insns);
        if capped {
            ctx.work.capped = true;
        }
        let _ = ctx.set_body(entry, body);
    }
    Step { work }
}

/// The recursive descent of one function.
struct Walk<'c, 'a> {
    ctx: &'c AnalysisCtx<'a>,
    entry: u64,
    body: Body,
    todo: BTreeSet<u64>,
    insns: u64,
    /// The code units that the walk can add: the cap less the units of other functions.
    budget: u64,
    /// `true` when the walk stopped at `budget`.
    capped: bool,
}

impl<'c, 'a> Walk<'c, 'a> {
    fn new(ctx: &'c AnalysisCtx<'a>, entry: u64) -> Self {
        let work = &ctx.work;
        let own = work.funcs.get(&entry).map_or(0, |f| f.units.len());
        let others = work.units.len().saturating_sub(own);
        let cap = work.unit_cap.unwrap_or(MAX_UNITS);
        Self {
            ctx,
            entry,
            body: Body::default(),
            todo: BTreeSet::from([entry]),
            insns: 0,
            budget: cap.saturating_sub(u64::try_from(others).unwrap_or(u64::MAX)),
            capped: false,
        }
    }

    /// Tells if `owner` is another function with a lower entry.
    const fn lower(&self, owner: u64) -> bool {
        owner < self.entry
    }

    /// Tells if `at` is in a decoded instruction of the walk after its first byte.
    fn inside(&self, at: u64) -> bool {
        self.body
            .units
            .range(..at)
            .next_back()
            .is_some_and(|(start, u)| {
                Range::with_len(*start, u64::from(u.len)).is_some_and(|r| r.contains(at))
            })
    }

    /// Tells if the instruction at `range` clashes. It clashes when it covers a decoded start
    /// or the entry of another function. It also clashes with code of a lower entry.
    fn clashes(&self, range: Range) -> bool {
        let later = range.first.checked_add(1).filter(|n| *n <= range.last);
        let covers = later.is_some_and(|n| {
            self.body.units.range(n..=range.last).next().is_some()
                || self.ctx.work.funcs.range(n..=range.last).next().is_some()
        });
        covers
            || self
                .ctx
                .work
                .overlapping(range)
                .iter()
                .any(|(_, o)| self.lower(*o))
    }

    /// Follows the flow to `to`.
    fn follow(&mut self, to: u64) {
        let ctx = self.ctx;
        let other_extent = ctx.foreign_extent(self.entry, to).is_some();
        if to == self.entry {
            self.todo.insert(to);
        } else if ctx.is_entry(to) || other_extent || ctx.owner(to).is_some_and(|o| self.lower(o)) {
            self.body.summary.exits.insert(to);
        } else if is_exec(ctx.program(), to) {
            self.todo.insert(to);
        } else {
            self.body.summary.unknown = true;
        }
    }

    /// Adds a flow reference from `at` to `to` with `kind`. A RAM target needs a mapped region.
    fn reference(&mut self, at: u64, to: Address, kind: RefType) {
        if to.is_ram() && !is_mapped(self.ctx.program(), to.off) {
            return;
        }
        let key = RefKey {
            from: Address::ram(at),
            op_index: 0,
            to,
            kind,
        };
        let why = Why::new(Rule::FlowRef, vec![FactKey::CodeUnit(at)]);
        self.body.refs.insert(key, why);
    }

    /// Gives the import slot of the indirect site `insn` at `at` and the EXTERNAL address of
    /// its import. The slot is the memory operand, else the slot site of `JumpTables` for a
    /// register that holds the slot ([`crate::slotsite`]).
    fn slot(&self, at: u64, insn: &Insn) -> Option<(u64, Address)> {
        let site = || match self.ctx.ir().slot_sites.get(&at)?.target {
            SiteTarget::Slot(s) => Some(s),
            SiteTarget::Null => None,
        };
        let slot = slot_of(insn).or_else(site)?;
        self.ctx.slot_target(slot).map(|(_, ext)| (slot, ext))
    }

    /// Tells if the indirect site at `at` is a null site of `JumpTables`.
    fn null_site(&self, at: u64) -> bool {
        self.ctx
            .ir()
            .slot_sites
            .get(&at)
            .is_some_and(|s| s.target == SiteTarget::Null)
    }

    /// Handles a direct call at `at`. Gives the site flags.
    fn call(&mut self, at: u64, next: u64, target: Option<u64>) -> u8 {
        let Some(t) = target else {
            self.follow(next);
            return 0;
        };
        self.body.summary.calls.insert(at, t);
        self.reference(at, Address::ram(t), RefType::UnconditionalCall);
        if !self.ctx.noreturn(t) {
            self.follow(next);
            return 0;
        }
        if self.ctx.noreturn_known(t) {
            UNIT_NORETURN_CALL | UNIT_NORETURN_ASSUMED
        } else {
            UNIT_NORETURN_CALL
        }
    }

    /// Handles the flow of the decoded instruction `insn` at `at` with the flow that a fact
    /// sets for the site (design Section 7.8). Gives the site flags.
    fn flow(&mut self, at: u64, next: u64, insn: &Insn) -> u8 {
        match crate::overrides::site_flow(self.ctx, at, insn.flow()) {
            Some(SiteFlow::Fallthrough(t)) => self.plain(at, t, insn),
            Some(SiteFlow::Cases(targets)) => {
                for t in targets {
                    self.reference(at, Address::ram(t), RefType::ComputedJump);
                    self.follow(t);
                }
                0
            }
            Some(SiteFlow::Calls(targets)) => {
                for t in targets {
                    self.reference(at, Address::ram(t), RefType::ComputedCall);
                }
                self.follow(next);
                0
            }
            Some(SiteFlow::CallAsJump) => {
                match insn.target() {
                    Some(t) => {
                        self.reference(at, Address::ram(t), RefType::UnconditionalJump);
                        self.follow(t);
                    }
                    None => self.body.summary.unknown = true,
                }
                0
            }
            Some(SiteFlow::JumpAsCall) => self.call(at, next, insn.target()),
            None => self.plain(at, next, insn),
        }
    }

    /// Handles the decoder flow of the instruction `insn` at `at`. Gives the site flags.
    fn plain(&mut self, at: u64, next: u64, insn: &Insn) -> u8 {
        match insn.flow() {
            Flow::Seq => self.follow(next),
            Flow::Jmp | Flow::Jcc => {
                let kind = if insn.flow() == Flow::Jmp {
                    RefType::UnconditionalJump
                } else {
                    self.follow(next);
                    RefType::ConditionalJump
                };
                if let Some(t) = insn.target() {
                    self.reference(at, Address::ram(t), kind);
                    self.follow(t);
                } else {
                    self.body.summary.unknown = true;
                }
            }
            Flow::Call => return self.call(at, next, insn.target()),
            Flow::ICall => match self.slot(at, insn) {
                Some((slot, ext)) => {
                    self.body.summary.slot_calls.insert(at, slot);
                    self.reference(at, ext, RefType::UnconditionalCall);
                    if self.ctx.noreturn_slot(slot) {
                        return UNIT_NORETURN_CALL | UNIT_NORETURN_ASSUMED;
                    }
                    self.follow(next);
                }
                None if self.null_site(at) => {
                    self.follow(next);
                    return UNIT_NULL_TARGET;
                }
                None => self.follow(next),
            },
            Flow::IJmp => match self.slot(at, insn) {
                Some((slot, ext)) => {
                    self.body.summary.slot_exits.insert(slot);
                    self.reference(at, ext, RefType::UnconditionalJump);
                }
                None if self.null_site(at) => return UNIT_NULL_TARGET,
                None => self.body.summary.unknown = true,
            },
            Flow::Ret => self.body.summary.ret = true,
            Flow::Trap => {}
            Flow::Invalid => self.body.summary.unknown = true,
        }
        0
    }

    /// Runs the descent from the entry.
    fn run(mut self) -> Self {
        let ctx = self.ctx;
        let id = FactKey::Func(FuncId(Address::ram(self.entry)));
        if ctx.owner(self.entry).is_some_and(|o| self.lower(o)) {
            // The exit at the entry runs the walk again when the lower function lets go.
            self.body.summary.exits.insert(self.entry);
            self.body.summary.unknown = true;
            return self;
        }
        while let Some(at) = self.todo.pop_first() {
            if self.body.units.contains_key(&at) {
                continue;
            }
            if self.insns >= MAX_INSNS {
                self.body.summary.unknown = true;
                break;
            }
            if self.insns >= self.budget {
                self.body.summary.unknown = true;
                self.capped = true;
                break;
            }
            let decoded = decode_at(ctx.program(), at).and_then(|insn| {
                let range = Range::with_len(at, u64::from(insn.len()))?;
                let flow = flow_kind(insn.flow())?;
                Some((insn, range, flow))
            });
            let Some((insn, range, flow)) = decoded else {
                self.body.summary.unknown = true;
                continue;
            };
            if self.inside(at) || self.clashes(range) {
                self.body.summary.unknown = true;
                continue;
            }
            let Some(next) = range.last.checked_add(1) else {
                self.body.summary.unknown = true;
                continue;
            };
            self.insns = self.insns.saturating_add(1);
            let flags = self.flow(at, next, &insn);
            let why = Why::new(Rule::DisasmFlow, vec![id.clone()]);
            self.body.units.insert(
                at,
                UnitRec {
                    len: insn.len(),
                    flow,
                    flags,
                    why,
                },
            );
        }
        self
    }
}
