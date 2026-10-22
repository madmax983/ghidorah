//! Agent references whose source stops being code (design Sections 3.9 and 3.11).
//!
//! A re-analysis can drop the code unit at the source of an agent reference. The reference
//! is an orphan then. It stays in the base layer, and the publish commit keeps the
//! invariants.

use crate::edit::{Edit, Layer};
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::tests::{ram, seeded, session};

use super::super::Violation;

/// The key of the agent reference of the tests: a read from the seeded unit `0x1090`.
fn key() -> RefKey {
    RefKey {
        from: ram(0x1090),
        op_index: 0,
        to: ram(0x2004),
        kind: RefType::Read,
    }
}

#[test]
fn regress_orphan_agent_ref_keeps_invariants() {
    let mut p = seeded();
    let mut tx = p
        .begin("func_edit", Source::Agent, session("mcp-1"))
        .unwrap();
    let fact = tx.fact(Ref {
        key: key(),
        primary: false,
    });
    tx.apply(Edit::AddRef { fact }).unwrap();
    tx.commit().unwrap();
    // A re-analysis publishes a set with no code unit at the source of the reference.
    let label = crate::fact::SessionLabel::new(crate::fact::SessionLabel::ANALYSIS).unwrap();
    let mut tx = p.begin("analysis_run", Source::Analysis, label).unwrap();
    tx.apply(Edit::ReplaceAnalysis(std::sync::Arc::default()))
        .unwrap();
    tx.commit().unwrap();
    assert!(p.code_unit(0x1090).is_none(), "the source is not code");
    assert!(
        p.base().refs().get(&key()).is_some(),
        "the agent reference stays"
    );
    let found = p.check_invariants();
    assert!(
        !found.contains(&Violation::RefFrom {
            layer: Layer::Base,
            from: ram(0x1090),
        }),
        "an orphaned agent reference is not a violation: {found:?}"
    );
}
