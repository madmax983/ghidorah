//! Random forward edits for the model tests. Some edits break a rule on purpose, so the
//! tests also see refused edits.

use ghidorah_base::{Address, FuncId, JumpTableId, NoteId, Range, SetName, Storage, VarId};
use ghidorah_kernel::RangeSet;
use ghidorah_testkit::pbt::Gen;
use ghidorah_types::{Prim, TypeId};

use super::{CODE_END, CODE_FIRST, FUNCS, ram, units};
use crate::comments::CommentKind;
use crate::edit::{Edit, FuncRecord, VarField};
use crate::funcs::{Function, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::DataDef;
use crate::notes::{Claim, Note, NoteKind, NoteSet, NoteStatus, SetMembers};
use crate::overrides::FlowOverride;
use crate::program::{AnalysisSet, Program};
use crate::refs::{Ref, RefKey, RefType};
use crate::symbols::SymKind;
use crate::tx::Tx;

/// The values that the random edits use.
#[derive(Debug, Clone)]
pub(crate) struct Pools {
    /// Addresses for names and comments.
    pub addrs: Vec<Address>,
    /// The function type `int (void)`.
    pub fn_type: TypeId,
    /// The type `long`.
    pub long: TypeId,
}

impl Pools {
    /// Gives the pools of a seeded program.
    pub(crate) fn of(p: &Program, fn_type: TypeId) -> Self {
        let mut addrs: Vec<Address> = p.base().symbols().iter().map(|s| s.addr).take(4).collect();
        addrs.extend([ram(0x1080), ram(0x1084), ram(0x10c0), ram(0x4000)]);
        Self {
            addrs,
            fn_type,
            long: p.types().store().prim(Prim::Long),
        }
    }
}

fn pick<T: Copy>(g: &mut Gen, items: &[T]) -> T {
    *g.pick(items).unwrap()
}

fn unit(g: &mut Gen) -> u64 {
    pick(g, &units())
}

fn target(g: &mut Gen) -> Address {
    match g.draw(8) {
        0 => ram(0x2000),
        1 => ram(CODE_FIRST + 1),
        2 => Address::external(1),
        _ => ram(unit(g)),
    }
}

fn names(g: &mut Gen) -> String {
    pick(g, &["alpha", "beta", "gamma", "main"]).to_string()
}

fn func_id(g: &mut Gen) -> FuncId {
    let entries = [FUNCS[0], FUNCS[1], FUNCS[2], 0x1140, 0x1144, 0x1170];
    FuncId(ram(pick(g, &entries)))
}

fn flow(g: &mut Gen) -> FlowOverride {
    match g.draw(4) {
        0 => FlowOverride::Fallthrough(ram(unit(g))),
        1 => FlowOverride::CallAsJump,
        2 => FlowOverride::JumpAsCall,
        _ => FlowOverride::IndirectTargets(vec![target(g), target(g)]),
    }
}

fn note(g: &mut Gen, tx: &Tx<'_>) -> Note {
    let next = tx.program().notes().next_id();
    let id = if g.bool() {
        next
    } else {
        NoteId(g.range(1, 3))
    };
    let kind = pick(g, &NoteKind::ALL);
    let set = (kind == NoteKind::Set).then(|| {
        let members = if g.bool() {
            let mut r = RangeSet::new();
            r.insert(Range {
                first: CODE_FIRST,
                last: CODE_END - 1,
            });
            SetMembers::Addrs(r)
        } else {
            SetMembers::ids(vec!["fn:0x1080".to_string(), "str:0x2004".to_string()])
        };
        NoteSet {
            name: SetName::new(pick(g, &["parsers", "crypto"])).unwrap(),
            members,
        }
    });
    let evidence = match g.draw(4) {
        0 => vec!["not an id".to_string()],
        1 => Vec::new(),
        _ => vec!["fn:0x10c0".to_string()],
    };
    Note {
        id,
        kind,
        text: names(g),
        at: g.bool().then(|| ram(unit(g))),
        func: g.bool().then(|| FuncId(ram(FUNCS[0]))),
        status: pick(g, &NoteStatus::ALL),
        tags: vec!["t".to_string()],
        evidence,
        claims: vec![Claim {
            rel: "calls".to_string(),
            args: vec!["fn:0x1080".to_string(), "fn:0x10c0".to_string()],
        }],
        set,
        src: tx.origin().source,
        session: tx.origin().session.clone(),
        rev: tx.pending_rev(),
    }
}

/// Draws one forward edit of a base-layer Tx. `kind` picks the variant, 0 to 13.
pub(crate) fn base_edit(g: &mut Gen, tx: &Tx<'_>, pools: &Pools, kind: u64) -> Edit {
    let gone = g.draw(5) == 0;
    match kind {
        0 => Edit::SetName {
            addr: pick(g, &pools.addrs),
            key: None,
            kind: SymKind::Function,
            primary: true,
            name: (!gone).then(|| tx.fact(names(g))),
            evidence: vec!["fn:0x1080".to_string()],
        },
        1 => Edit::SetComment {
            addr: pick(g, &pools.addrs),
            kind: pick(g, &CommentKind::ALL),
            text: (!gone).then(|| tx.fact(names(g))),
        },
        2 => Edit::SetVarFact {
            var: VarId {
                func: func_id(g),
                storage: g
                    .pick(&[Storage::Param(0), Storage::Stack(-8), Storage::Ret])
                    .cloned()
                    .unwrap(),
            },
            field: if g.bool() {
                VarField::Name((!gone).then(|| tx.fact(names(g))))
            } else {
                VarField::Type((!gone).then(|| tx.fact(pools.long)))
            },
        },
        3 => Edit::AddRef {
            fact: tx.fact(Ref {
                key: ref_key(g),
                primary: g.bool(),
            }),
        },
        4 => Edit::RemoveRef { key: ref_key(g) },
        5 => {
            let entry = pick(g, &[0x1140, 0x1144, 0x1170, 0x1080]);
            let mut func = Function::new(ram(entry), StartReason::Agent, 100, tx.origin().source);
            let mut body = RangeSet::new();
            body.insert(Range {
                first: entry,
                last: entry + 3,
            });
            func.body = body;
            if g.bool() {
                func.sig = Some(tx.fact(pools.fn_type));
            }
            Edit::CreateFunction(Box::new(FuncRecord {
                func,
                vars: Vec::new(),
                plate: None,
            }))
        }
        6 => Edit::DeleteFunction {
            id: func_id(g),
            cascade: g.bool(),
        },
        7 => Edit::SetSignature {
            id: func_id(g),
            sig: (!gone).then(|| {
                tx.fact(if g.draw(4) == 0 {
                    pools.long
                } else {
                    pools.fn_type
                })
            }),
        },
        8 => Edit::SetNoreturn {
            id: func_id(g),
            noreturn: (!gone).then(|| tx.fact(g.bool())),
        },
        9 => Edit::SetJumpTable {
            id: JumpTableId(ram(unit(g))),
            table: (!gone).then(|| {
                tx.fact(JumpTable {
                    base: None,
                    entry_size: 0,
                    count: 2,
                    targets: vec![target(g), target(g)],
                    method: JtMethod::Agent,
                    resolved: true,
                })
            }),
        },
        10 => Edit::SetFlowOverride {
            at: ram(unit(g)),
            flow: (!gone).then(|| tx.fact(flow(g))),
        },
        11 => Edit::SetDataDef {
            at: ram(0x4000 + 8 * g.draw(2)),
            def: (!gone).then(|| {
                tx.fact(DataDef {
                    ty: pools.long,
                    len: pick(g, &[8, 16]),
                })
            }),
        },
        12 => Edit::WriteNote(Box::new(note(g, tx))),
        _ => Edit::DeleteNote {
            id: NoteId(g.range(1, 3)),
        },
    }
}

fn ref_key(g: &mut Gen) -> RefKey {
    let from = if g.draw(6) == 0 {
        CODE_FIRST + 2
    } else {
        unit(g)
    };
    RefKey {
        from: ram(from),
        op_index: pick(g, &[-1, 0]),
        to: target(g),
        kind: pick(
            g,
            &[RefType::Read, RefType::UnconditionalCall, RefType::Data],
        ),
    }
}

/// Draws a `ReplaceAnalysis` edit with one of `sets`.
pub(crate) fn analysis_edit(g: &mut Gen, sets: &[AnalysisSet]) -> Edit {
    let set = g.pick(sets).cloned().unwrap_or_default();
    Edit::ReplaceAnalysis(Box::new(set))
}
