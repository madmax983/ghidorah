use std::sync::Arc;

use ghidorah_base::{Address, FuncId, Range};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use super::{AnalysisSet, SHARD_BITS, ShardId};
use crate::codec::{set_from_json, set_from_tables, set_to_json, tables_to_json};
use crate::edit::Layer;
use crate::fact::Origin;
use crate::funcs::{Function, StartReason};
use crate::invariants::Violation;
use crate::listing::{CodeUnit, DataDef, FlowKind};
use crate::program::Tables;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::SymKind;
use crate::why::{FactKey, RuleCode, Why};

/// The first offset of shard 1.
const EDGE: u64 = 1 << SHARD_BITS;

/// The start of the second body range of the wide function, in shard 2.
const FAR: u64 = 2 << SHARD_BITS;

fn ram(off: u64) -> Address {
    Address::ram(off)
}

fn unit(len: u8) -> CodeUnit {
    CodeUnit::Insn {
        len,
        flow: FlowKind::Seq,
        flags: 0,
    }
}

fn call(from: u64, to: u64) -> RefKey {
    RefKey {
        from: ram(from),
        op_index: -1,
        to: ram(to),
        kind: RefType::UnconditionalCall,
    }
}

/// Gives the facts of one layer across three shards:
///
/// - a unit at the end of shard 0 that reaches into shard 1,
/// - a data definition at the end of shard 0 that reaches into shard 1,
/// - a function in shard 0 with a second body range in shard 2,
/// - two calls to the far range, one from each shard, and a symbol name in two shards,
/// - a why-record in shard 2 with a premise in shard 0.
fn layer() -> Tables {
    let o = Origin::analysis();
    let mut t = Tables::default();
    for (at, len) in [(0x10_0000, 4), (EDGE - 2, 4), (FAR, 4), (FAR + 4, 4)] {
        t.listing.insert_unit(at, unit(len)).unwrap();
    }
    let def = DataDef {
        ty: TypeId::from_index(1),
        len: 0x20,
    };
    t.listing.set_data(EDGE - 0x10, Some(def), &o).unwrap();
    let mut f = Function::new(ram(0x10_0000), StartReason::Call, 90, Source::Analysis);
    let mut body = RangeSet::new();
    body.insert(Range::new(0x10_0000, 0x10_00ff).unwrap());
    body.insert(Range::new(FAR, FAR + 0xff).unwrap());
    f.body = body;
    t.funcs.insert(f).unwrap();
    for from in [0x10_0000, FAR + 4] {
        let key = call(from, FAR);
        t.refs.add(Ref { key, primary: true }, &o).unwrap();
    }
    for at in [FAR, 0x10_0000] {
        t.symbols
            .add(ram(at), "twice".to_owned(), SymKind::Label, &o)
            .unwrap();
    }
    let why = Why {
        rule: RuleCode::new("R_TEST").unwrap(),
        premises: vec![FactKey::Func(FuncId(ram(0x10_0000)))],
    };
    t.why.insert(FactKey::CodeUnit(FAR), why).unwrap();
    t
}

#[test]
fn shard_ids_follow_the_address() {
    assert_eq!(ShardId::of_off(EDGE - 1), ShardId::from_index(0));
    assert_eq!(ShardId::of_off(EDGE), ShardId::from_index(1));
    assert_eq!(ShardId::of(Address::external(3)), ShardId::OUTSIDE);
    assert!(ShardId::from_index(1) < ShardId::OUTSIDE);
    assert_eq!(
        ShardId::from_index(1).range(),
        Range::new(EDGE, 2 * EDGE - 1)
    );
    assert_eq!(ShardId::OUTSIDE.range(), None);
    assert_eq!(ShardId::OUTSIDE.index(), u64::MAX);
    let keys = [
        (FactKey::Ref(call(FAR + 4, 0x10)), 2),
        (FactKey::Func(FuncId(ram(EDGE))), 1),
        (FactKey::Data(EDGE - 1), 0),
    ];
    for (key, index) in keys {
        assert_eq!(ShardId::of_key(&key), ShardId::from_index(index), "{key:?}");
    }
}

#[test]
fn each_fact_goes_in_the_shard_of_its_key() {
    let set = set_from_tables(&layer()).unwrap();
    let ids: Vec<u64> = set.shards().map(|(id, _)| id.index()).collect();
    assert_eq!(
        ids,
        [0, 2],
        "the unit and the data that reach into shard 1 start in 0"
    );
    assert_eq!(set.unit_count(), 4);
    let far = set.shard(ShardId::from_index(2)).unwrap();
    assert!(
        far.funcs().is_empty(),
        "a function goes in the shard of its entry"
    );
    assert_eq!(far.refs().len(), 1);
    assert!(far.why().get(&FactKey::CodeUnit(FAR)).is_some());
    assert!(set.at(ram(FAR)).is_some() && set.at_off(EDGE).is_none());
    assert!(!set.is_empty() && AnalysisSet::new().is_empty());
}

#[test]
fn reads_cross_the_shard_edges() {
    let set = set_from_tables(&layer()).unwrap();
    assert_eq!(set.unit_containing(EDGE).map(|(at, _)| at), Some(EDGE - 2));
    assert_eq!(
        set.data_containing(EDGE + 8).map(|(at, _)| at),
        Some(EDGE - 0x10)
    );
    let entry = FuncId(ram(0x10_0000));
    assert_eq!(
        set.owner_of(FAR + 0x10),
        Some(entry),
        "the body range in shard 2"
    );
    assert_eq!(set.owner_of(0x10_0010), Some(entry));
    assert_eq!(set.owner_of(EDGE), None);
    let units: Vec<u64> = set
        .units_in(Range::new(EDGE - 4, FAR + 4).unwrap())
        .map(|(at, _)| at)
        .collect();
    assert_eq!(units, [EDGE - 2, FAR, FAR + 4]);
    let names = set.names();
    assert_eq!(
        names.get("twice").cloned(),
        Some(vec![ram(0x10_0000), ram(FAR)])
    );

    let mut p = crate::tests::fixture("hello.gcc-O2");
    p.swap_analysis(Arc::new(set));
    let to: Vec<u64> = p
        .refs_to(ram(FAR))
        .iter()
        .map(|r| r.value.key.from.off)
        .collect();
    assert_eq!(
        to,
        [0x10_0000, FAR + 4],
        "the calls of both shards in key order"
    );
    assert_eq!(p.addrs_named("twice"), [ram(0x10_0000), ram(FAR)]);
    assert_eq!(p.owner_of(ram(FAR + 8)), Some(entry));
    assert!(p.why(&FactKey::CodeUnit(FAR)).is_some());
}

#[test]
fn a_set_reads_back_from_its_json_form() {
    let t = layer();
    let set = set_from_tables(&t).unwrap();
    let json = set_to_json(&set);
    assert_eq!(set_from_json(&json).unwrap(), set);
    assert_eq!(
        set_from_json(&tables_to_json(&t)).unwrap(),
        set,
        "the JSON form of one layer gives the same shards"
    );
}

#[test]
fn a_new_set_shares_each_shard_with_no_change() {
    let old = set_from_tables(&layer()).unwrap();
    let mut t = layer();
    t.listing.insert_unit(FAR + 8, unit(4)).unwrap();
    let rows = crate::codec::rows_of_tables(&t).unwrap();
    let new = crate::codec::set_from_rows(rows, &old).unwrap();
    let zero = ShardId::from_index(0);
    assert!(Arc::ptr_eq(
        old.shard_arc(zero).unwrap(),
        new.shard_arc(zero).unwrap()
    ));
    let changed: Vec<u64> = old.changed_shards(&new).map(ShardId::index).collect();
    assert_eq!(changed, [2]);
    assert_eq!(old.changed_shards(&old).count(), 0);
}

#[test]
fn invariants_see_an_overlap_across_a_shard_edge() {
    let mut p = crate::tests::fixture("hello.gcc-O2");
    let mut t = Tables::default();
    t.listing.insert_unit(EDGE - 2, unit(4)).unwrap();
    t.listing.insert_unit(EDGE, unit(2)).unwrap_err();
    // One layer refuses the overlap, so each unit goes into its own shard by hand.
    let mut set = set_from_tables(&t).unwrap();
    set.tables_mut(ShardId::of_off(EDGE))
        .listing
        .insert_unit(EDGE, unit(2))
        .unwrap();
    set.tidy();
    p.swap_analysis(Arc::new(set));
    let found = p.check_invariants();
    assert!(
        found.contains(&Violation::UnitOverlap {
            layer: Layer::Analysis,
            at: EDGE - 2
        }),
        "{found:?}"
    );
}

#[test]
fn an_empty_shard_leaves_the_set() {
    let mut set = set_from_tables(&layer()).unwrap();
    let zero = ShardId::from_index(0);
    set.put(zero, Tables::default());
    assert!(set.shard(zero).is_none());
    assert_eq!(set.owner_of(FAR + 0x10), None, "the wide shard is gone");
    let _ = set.tables_mut(ShardId::from_index(5));
    set.tidy();
    assert!(set.shard(ShardId::from_index(5)).is_none());
}
