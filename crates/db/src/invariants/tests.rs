mod premises;

use std::cell::RefCell;

use ghidorah_base::{Address, FuncId, JumpTableId, NoteId, Range, Rev, SetName, TxId};
use ghidorah_kernel::RangeSet;
use ghidorah_testkit::pbt::check;

use super::Violation;
use crate::edit::{EditKind, Layer};
use crate::epochs::Table;
use crate::events::Event;
use crate::fact::Origin;
use crate::funcs::{Function, StartReason};
use crate::hash::StateHash;
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::{CodeUnit, FlowKind};
use crate::notes::{Note, NoteKind, NoteSet, NoteStatus, SetMembers};
use crate::overrides::FlowOverride;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind, Symbol};
use crate::tests::ops::{Pools, analysis_edit, base_edit};
use crate::tests::{analysis_set, fixture, func_type, origin, ram, seeded};
use crate::tx::Applied;
use crate::why::{FactKey, RuleCode, Why};

fn hash(p: &crate::Program) -> StateHash {
    p.state_hash().unwrap()
}

/// One undo entry of the model: the state before a commit and the commit.
struct Entry {
    before: StateHash,
    edits: Vec<Applied>,
    source: Source,
    session: &'static str,
}

/// Reverts the commit of `entry` with its exact inverses, as `history_undo` does.
fn undo(p: &mut crate::Program, entry: &Entry) -> Result<(), String> {
    let label = crate::tests::session(entry.session);
    let mut tx = p.begin("history_undo", entry.source, label).unwrap();
    for a in entry.edits.iter().rev() {
        tx.restore(a.inverse.clone()).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    if hash(p) == entry.before {
        Ok(())
    } else {
        Err("undo does not restore the state".to_string())
    }
}

#[test]
fn ac_123_program_invariants() {
    let mut start = seeded();
    let fn_type = func_type(&mut start);
    let pools = Pools::of(&start, fn_type);
    let sets = [analysis_set(&start, 0), analysis_set(&start, 1)];
    let counts = RefCell::new([0usize; 15]);
    check("ac_123_program_invariants", 96, |g| {
        let mut p = start.clone();
        let mut stack: Vec<Entry> = Vec::new();
        let count = 20 + g.draw(40);
        for steps in 1..=count {
            let before = hash(&p);
            let (source, session) = match g.draw(4) {
                0 => (Source::User, "cli"),
                1 => (Source::Analysis, "analysis"),
                _ => (Source::Agent, "mcp-1"),
            };
            let end = g.draw(10);
            if end == 9 {
                let Some(entry) = stack.pop() else { continue };
                undo(&mut p, &entry).map_err(|e| format!("step {steps}: {e}"))?;
            } else {
                let mut tx = p
                    .begin("model", source, crate::tests::session(session))
                    .unwrap();
                for _ in 0..=g.draw(3) {
                    let edit = if source == Source::Analysis {
                        analysis_edit(g, &sets)
                    } else {
                        let kind = g.draw(14);
                        base_edit(g, &tx, &pools, kind)
                    };
                    let _ = tx.apply(edit);
                }
                match end {
                    7 => {
                        drop(tx);
                        if hash(&p) != before {
                            return Err(format!("step {steps}: a drop does not roll back"));
                        }
                    }
                    8 => {
                        {
                            let mut nested = tx.nest();
                            let edit = base_edit(g, nested.tx(), &pools, 0);
                            let _ = nested.apply(edit);
                            nested.abort();
                        }
                        if tx.commit().is_ok() {
                            return Err(format!("step {steps}: a poisoned Tx commits"));
                        }
                        if hash(&p) != before {
                            return Err(format!("step {steps}: a poisoned commit keeps edits"));
                        }
                    }
                    _ => {
                        let commit = tx.commit().map_err(|e| e.to_string())?;
                        if commit.noop {
                            if hash(&p) != before {
                                return Err(format!("step {steps}: a no-op changes the state"));
                            }
                        } else {
                            for a in &commit.edits {
                                let i = EditKind::ALL
                                    .iter()
                                    .position(|k| *k == a.edit.kind())
                                    .unwrap_or(0);
                                counts.borrow_mut()[i] += 1;
                            }
                            stack.push(Entry {
                                before,
                                edits: commit.edits,
                                source,
                                session,
                            });
                        }
                    }
                }
            }
            let found = p.check_invariants();
            if !found.is_empty() {
                return Err(format!("step {steps}: {found:?}"));
            }
        }
        Ok(())
    });
    let counts = counts.into_inner();
    let table: Vec<String> = EditKind::ALL
        .iter()
        .zip(counts)
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect();
    assert!(
        counts.iter().all(|c| *c >= 20),
        "each kind applies 20 times: {table:?}"
    );
}

#[test]
fn fresh_programs_hold_the_invariants() {
    for name in ["hello.gcc-O2", "hello.gcc-O2.stripped", "crackme.clang-O2"] {
        let p = fixture(name);
        assert_eq!(p.check_invariants(), Vec::new(), "{name}");
    }
    assert_eq!(seeded().check_invariants(), Vec::new());
}

fn why(rule: &str, premises: Vec<FactKey>) -> Why {
    Why {
        rule: RuleCode::new(rule).unwrap(),
        premises,
    }
}

/// Gives the seeded program with broken facts for rules 2, 6, 7 and 8.
fn broken() -> crate::Program {
    let mut p = seeded();
    let a = Origin::analysis();
    let agent = origin(Source::Agent, 1, "mcp-1");
    // Rule 2: a base reference from an address without a code unit.
    let bad_ref = RefKey {
        from: ram(0x1082),
        op_index: 0,
        to: ram(0x1080),
        kind: RefType::Read,
    };
    p.layer_mut(Source::Agent)
        .unwrap()
        .refs
        .add(
            Ref {
                key: bad_ref,
                primary: true,
            },
            &agent,
        )
        .unwrap();
    // Rule 6: an analysis code unit without a why-record, and a premise that does not exist.
    let layer = p.layer_mut(Source::Analysis).unwrap();
    layer
        .listing
        .insert_unit(
            0x1180,
            CodeUnit::Insn {
                len: 4,
                flow: FlowKind::Seq,
                flags: 0,
            },
        )
        .unwrap();
    layer
        .why
        .insert(FactKey::Data(0x9999), why("R_TEST_ORPHAN", Vec::new()))
        .unwrap();
    layer
        .why
        .insert(
            FactKey::CodeUnit(0x1084),
            why(
                "R_TEST_LATE",
                vec![FactKey::Fde(0x77), FactKey::CodeUnit(0x1090)],
            ),
        )
        .unwrap();
    // A new record for 0x1090 gives it a higher order than its user at 0x1084.
    layer
        .why
        .insert(FactKey::CodeUnit(0x1090), why("R_TEST_AGAIN", Vec::new()))
        .unwrap();
    // Rule 8: a jump target inside an instruction and an indirect target in data.
    layer
        .jumptables
        .set(
            JumpTableId(ram(0x1150)),
            Some(JumpTable {
                base: None,
                entry_size: 4,
                count: 1,
                targets: vec![ram(0x1081)],
                method: JtMethod::A,
                resolved: true,
            }),
            &a,
        )
        .unwrap();
    layer
        .why
        .insert(
            FactKey::JumpTable(JumpTableId(ram(0x1150))),
            why("R_TEST_JT", Vec::new()),
        )
        .unwrap();
    p.layer_mut(Source::Agent)
        .unwrap()
        .overrides
        .set(
            ram(0x1090),
            Some(FlowOverride::IndirectTargets(vec![ram(0x2000)])),
            &agent,
        )
        .unwrap();
    // Rule 7: an event above the revision.
    p.changes_mut().events.push(vec![Event {
        rev: Rev(5),
        tx: TxId(5),
        kind: Table::Refs,
        ranges: RangeSet::new(),
        ids: Vec::new(),
    }]);
    p
}

#[test]
fn each_rule_finds_its_violation() {
    let found = broken().check_invariants();
    let want = [
        Violation::RefFrom {
            layer: Layer::Base,
            from: ram(0x1082),
        },
        Violation::NoWhy {
            key: FactKey::CodeUnit(0x1180),
        },
        Violation::WhyOrphan {
            key: FactKey::Data(0x9999),
        },
        Violation::Premise {
            key: FactKey::CodeUnit(0x1084),
            premise: FactKey::Fde(0x77),
        },
        Violation::PremiseOrder {
            key: FactKey::CodeUnit(0x1084),
            premise: FactKey::CodeUnit(0x1090),
        },
        Violation::EventRev { rev: Rev(5) },
        Violation::JumpTarget {
            layer: Layer::Analysis,
            table: JumpTableId(ram(0x1150)),
            target: ram(0x1081),
        },
        Violation::CallTarget {
            layer: Layer::Base,
            at: ram(0x1090),
            target: ram(0x2000),
        },
    ];
    for v in &want {
        assert!(found.contains(v), "{v} is missing from {found:?}");
    }
    let rules: Vec<u8> = found.iter().map(Violation::rule).collect();
    let mut sorted = rules.clone();
    sorted.sort_unstable();
    assert_eq!(rules, sorted, "violations come in rule order");
    assert!(want[0].to_string().starts_with("invariant 2:"));
}

fn sym(addr: u64, key: u16, name: &str, primary: bool) -> Symbol {
    Symbol {
        addr: ram(addr),
        key: SymKey(key),
        name: Origin::analysis().fact(name.to_string()),
        kind: SymKind::Label,
        primary,
    }
}

#[test]
fn structural_rules_find_broken_tables() {
    let layer = Layer::Analysis;
    let mut out = Vec::new();
    // Rule 1: the to-index misses a key of the from-index.
    let key = RefKey {
        from: ram(0x10),
        op_index: 0,
        to: ram(0x20),
        kind: RefType::Read,
    };
    super::ref_index(layer, vec![key], Vec::new(), &mut out);
    super::ref_index(layer, vec![key], vec![key], &mut out);
    // Rule 3: a body without its entry, two bodies that overlap and a wrong ownership map.
    let mut low = Function::new(ram(0x100), StartReason::Call, 50, Source::Analysis);
    low.body = RangeSet::from_ranges(&[Range {
        first: 0x101,
        last: 0x10f,
    }]);
    let mut high = Function::new(ram(0x108), StartReason::Call, 50, Source::Analysis);
    high.body = RangeSet::from_ranges(&[Range {
        first: 0x108,
        last: 0x11f,
    }]);
    super::bodies(layer, &[&low, &high], &[], &mut out);
    // Rule 4: two primary symbols at one address, and a name index without a symbol.
    let one = sym(0x200, 0, "one", true);
    let two = sym(0x200, 1, "two", true);
    let three = sym(0x300, 0, "three", false);
    let addrs = [ram(0x200)];
    let names: [(&str, &[Address]); 3] = [("one", &addrs), ("ghost", &addrs), ("two", &addrs)];
    super::symbols(layer, &[&one, &two, &three], &names, &mut out);
    // Rule 5: units and data definitions that overlap.
    super::overlaps(layer, &[(0x10, 4), (0x12, 4), (0x16, 1)], false, &mut out);
    super::overlaps(layer, &[(0x40, 16), (0x48, 8)], true, &mut out);
    // Rule 9: an evidence entry and a set member that do not parse.
    let note = Note {
        id: NoteId(3),
        kind: NoteKind::Set,
        text: String::new(),
        at: None,
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: vec!["fn:0x10".to_string(), "bad evidence".to_string()],
        claims: Vec::new(),
        set: Some(NoteSet {
            name: SetName::new("s").unwrap(),
            members: SetMembers::Ids(vec!["nope".to_string()]),
        }),
        src: Source::Agent,
        session: crate::tests::session("mcp-1"),
        rev: Rev(0),
    };
    super::evidence(&[&note], &mut out);
    let want = vec![
        Violation::RefIndex { layer },
        Violation::FuncEntry {
            layer,
            func: FuncId(ram(0x100)),
        },
        Violation::FuncOverlap {
            layer,
            func: FuncId(ram(0x108)),
        },
        Violation::Ownership { layer },
        Violation::Primary {
            layer,
            addr: ram(0x200),
            count: 2,
        },
        Violation::Primary {
            layer,
            addr: ram(0x300),
            count: 0,
        },
        Violation::NameIndex {
            layer,
            name: "ghost".to_string(),
        },
        Violation::NameIndex {
            layer,
            name: "three".to_string(),
        },
        Violation::UnitOverlap { layer, at: 0x10 },
        Violation::DataOverlap { layer, at: 0x40 },
        Violation::Evidence {
            note: NoteId(3),
            text: "bad evidence".to_string(),
        },
        Violation::Evidence {
            note: NoteId(3),
            text: "nope".to_string(),
        },
    ];
    assert_eq!(out, want);
}
