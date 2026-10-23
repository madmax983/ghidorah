//! The publish step, the change counts and `analysis_inputs_hash`.

use ghidorah_analysis::{Changed, Scheduler, Until, inputs_hash};
use ghidorah_base::{Address, Fuel, FuncId, TxId};
use ghidorah_db::{AnalysisSet, Edit, SessionLabel, Source};

use crate::support::{analyze, named, program};

#[test]
fn facts_have_one_origin() {
    let mut p = program("fixtures/bin/two_helpers.gcc-O2");
    let (sched, _) = analyze(&mut p);
    let a = p.analysis();
    assert!(a.funcs().next().is_some());
    for f in a.funcs() {
        assert_eq!(f.source, Source::Analysis);
        if let Some(n) = &f.flags.noreturn {
            assert_eq!(n.source, Source::Analysis);
            assert_eq!(n.tx, TxId(0));
            assert_eq!(n.session.as_str(), SessionLabel::ANALYSIS);
        }
    }
    for r in a.refs() {
        assert_eq!((r.source, r.tx), (Source::Analysis, TxId(0)));
        assert_eq!(r.session.as_str(), SessionLabel::ANALYSIS);
    }
    let set = sched.analysis_set(&p).expect("the set");
    assert_eq!(&set, a, "the published set is the set of the work state");
}

#[test]
fn changed_counts_tables() {
    let mut p = program("fixtures/bin/two_helpers.gcc-O2");
    let _ = analyze(&mut p);
    let empty = AnalysisSet::default();
    let all = Changed::between(&empty, p.analysis());
    assert_eq!(
        all.functions,
        u64::try_from(p.analysis().funcs().count()).expect("small")
    );
    assert_eq!(
        all.refs,
        u64::try_from(p.analysis().refs().count()).expect("small")
    );
    assert_eq!(
        all.strings,
        u64::try_from(p.analysis().strings().count()).expect("small")
    );
    assert_eq!(
        all.jumptables,
        u64::try_from(p.analysis().jumptables().count()).expect("small")
    );
    assert_eq!(
        Changed::between(p.analysis(), p.analysis()),
        Changed::default()
    );
    assert_eq!(Changed::between(p.analysis(), &empty), all);

    let mut q = program("fixtures/bin/two_helpers.gcc-O2");
    let mut s = Scheduler::new();
    let _ = s
        .run(&mut q, Until::Full, &mut Fuel::new(3))
        .expect("a slice");
    let part = Changed::between(q.analysis(), p.analysis());
    assert!(part.functions > 0, "a partial set differs");
}

#[test]
fn inputs_hash_tracks_inputs() {
    let mut p = program("fixtures/bin/noreturn_wrappers.gcc-O2");
    let fresh = inputs_hash(&p).expect("a hash");
    assert_ne!(fresh, [0; 32]);
    let _ = analyze(&mut p);
    assert_eq!(
        inputs_hash(&p).expect("a hash"),
        fresh,
        "analysis facts are not inputs"
    );
    let other = program("fixtures/bin/noreturn_wrappers.gcc-O0");
    assert_ne!(inputs_hash(&other).expect("a hash"), fresh);
    let check = named(&p, "check_args");
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("test", Source::Agent, label)
        .expect("a transaction");
    let flag = tx.fact(true);
    tx.apply(Edit::SetNoreturn {
        id: FuncId(Address::ram(check)),
        noreturn: Some(flag),
    })
    .expect("the flag applies");
    tx.commit().expect("a commit");
    assert_ne!(
        inputs_hash(&p).expect("a hash"),
        fresh,
        "an agent flag is an input"
    );
}
