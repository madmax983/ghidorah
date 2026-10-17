//! Tests of the property-test module.

use std::cell::Cell;

use ghidorah_testkit::pbt::{self, Config, DEFAULT_SHRINK_BUDGET, Gen};
use ghidorah_testkit::rng::fnv1a64;

fn config(cases: u32, seed: u64) -> Config {
    Config {
        cases,
        seed,
        shrink_budget: DEFAULT_SHRINK_BUDGET,
    }
}

fn sum_property(g: &mut Gen) -> Result<(), String> {
    let v = g.vec(16, |g| g.draw(1000));
    if v.iter().sum::<u64>() >= 500 {
        Err(format!("the sum of {v:?} is at least 500"))
    } else {
        Ok(())
    }
}

#[test]
fn pbt_shrinks_to_minimal() {
    let result = pbt::run("sum_below_500", &config(200, 1), sum_property);
    let Err(failure) = result else {
        panic!("the property must fail");
    };
    let mut g = Gen::replay(failure.choices.clone());
    let v = g.vec(16, |g| g.draw(1000));
    assert_eq!(v, vec![500], "the minimal list has one item with the value 500");
    assert!(failure.message.contains("[500]"), "{}", failure.message);
    let repro = failure.repro();
    assert!(repro.contains("sum_below_500"), "{repro}");
    assert!(repro.contains("PBT_SEED=0x"), "{repro}");
    assert!(!repro.contains('\n'), "the repro is one line: {repro}");
}

#[test]
fn pbt_shrinks_a_single_value() {
    let result = pbt::run("above_1000", &config(500, 2), |g| {
        let x = g.u64();
        if x > 1000 {
            Err(format!("{x} is above 1000"))
        } else {
            Ok(())
        }
    });
    let Err(failure) = result else {
        panic!("the property must fail");
    };
    assert_eq!(failure.choices, vec![1001]);
}

#[test]
fn pbt_passing_property_runs_all_cases() {
    let calls = Cell::new(0u32);
    let result = pbt::run("always_ok", &config(77, 3), |g| {
        calls.set(calls.get() + 1);
        let _ = g.bytes(8);
        Ok(())
    });
    assert_eq!(result, Ok(77));
    assert_eq!(calls.get(), 77);
}

#[test]
fn pbt_panic_is_a_failure() {
    let result = pbt::run("panics_on_seven", &config(500, 4), |g| {
        let v = g.draw(10);
        assert!(v != 7, "seven");
        Ok(())
    });
    let Err(failure) = result else {
        panic!("the property must fail");
    };
    assert_eq!(failure.choices, vec![7]);
    assert!(failure.message.contains("seven"), "{}", failure.message);
}

#[test]
fn pbt_same_seed_same_choices() {
    let mut a = Gen::random(42);
    let mut b = Gen::random(42);
    let va: Vec<u64> = (0..32).map(|_| a.draw(1 << 20)).collect();
    let vb: Vec<u64> = (0..32).map(|_| b.draw(1 << 20)).collect();
    assert_eq!(va, vb);
    assert_eq!(a.choices(), va.as_slice());
    assert!(va.iter().any(|&x| x != va[0]), "the values vary");
}

#[test]
fn pbt_replay_reads_zero_after_end() {
    let mut g = Gen::replay(vec![5, 9]);
    assert_eq!(g.draw(10), 5);
    assert_eq!(g.draw(10), 9);
    assert_eq!(g.draw(10), 0);
    assert_eq!(g.u64(), 0);
    assert!(!g.bool());
}

#[test]
fn pbt_replay_clamps_large_choices() {
    let mut g = Gen::replay(vec![50]);
    assert_eq!(g.draw(10), 9, "a choice above the bound reads as the largest value");
}

#[test]
fn pbt_draw_ranges_hold() {
    let mut g = Gen::random(5);
    for _ in 0..1000 {
        assert!(g.draw(7) < 7);
        let r = g.range(10, 20);
        assert!((10..=20).contains(&r));
        assert!(g.bytes(5).len() <= 5);
        assert!(g.vec(3, Gen::bool).len() <= 3);
    }
    assert_eq!(g.range(9, 3), 9);
    assert_eq!(g.pick::<u8>(&[]), None);
    let items = [1, 2, 3];
    assert!(g.pick(&items).is_some());
}

#[test]
fn pbt_name_seed_is_fnv1a() {
    assert_eq!(pbt::name_seed("abc"), fnv1a64(b"abc"));
    assert_eq!(pbt::name_seed("abc"), 0xe71f_a219_0541_574b);
}

#[test]
fn shrink_deletes_chunks_and_lowers_values() {
    let input: Vec<u64> = (1..=20).collect();
    let fails = |c: &[u64]| c.contains(&7) && c.contains(&13);
    assert_eq!(pbt::shrink(&input, fails), vec![7, 13]);
    let lowered = pbt::shrink(&[900, 3], |c: &[u64]| c.first().is_some_and(|&x| x >= 100));
    assert_eq!(lowered, vec![100]);
}

#[test]
fn shrink_bytes_finds_minimal_input() {
    let input = b"hello, world, this is a long input with an A in it".to_vec();
    let out = pbt::shrink_bytes(&input, |b: &[u8]| b.contains(&b'A'));
    assert_eq!(out, b"A".to_vec());
}

#[test]
fn shrink_respects_budget() {
    let calls = Cell::new(0u32);
    let input: Vec<u64> = (0..200).collect();
    let _ = pbt::shrink_with_budget(&input, 25, |c: &[u64]| {
        calls.set(calls.get() + 1);
        !c.is_empty()
    });
    assert!(calls.get() <= 25, "{} calls", calls.get());
}
