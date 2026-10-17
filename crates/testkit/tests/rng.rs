//! Tests of the PRNG module (AC-044a, AC-044b).

#![allow(clippy::panic, reason = "a test fails through a panic")]

use ghidorah_testkit::rng::{Rng, SplitMix64, Xoshiro256ss, below, fnv1a64};

/// Parses the reference vector file into `(state, outputs)` blocks.
fn parse_vector(text: &str) -> Vec<([u64; 4], Vec<u64>)> {
    let mut blocks: Vec<([u64; 4], Vec<u64>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("state ") {
            let words: Vec<u64> = rest.split_whitespace().map(hex).collect();
            assert_eq!(words.len(), 4, "a state line has four words: {line}");
            blocks.push(([words[0], words[1], words[2], words[3]], Vec::new()));
        } else {
            let block = blocks.last_mut();
            assert!(block.is_some(), "an output line comes after a state line");
            if let Some(block) = block {
                block.1.push(hex(line));
            }
        }
    }
    blocks
}

fn hex(word: &str) -> u64 {
    let digits = word.trim_start_matches("0x");
    u64::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("bad hex word {word}: {e}"))
}

#[test]
fn ac_044a_splitmix_kat() {
    let mut g = SplitMix64::new(0);
    assert_eq!(g.next_u64(), 0xe220_a839_7b1d_cdaf);
    assert_eq!(g.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    assert_eq!(g.next_u64(), 0x06c4_5d18_8009_454f);
}

#[test]
fn ac_044b_xoshiro_kat() {
    let blocks = parse_vector(include_str!("data/xoshiro256ss.txt"));
    assert_eq!(blocks.len(), 2, "the vector file has two blocks");
    for (state, outputs) in &blocks {
        assert_eq!(outputs.len(), 16);
        let mut g = Xoshiro256ss::from_state(*state);
        for (i, want) in outputs.iter().enumerate() {
            assert_eq!(g.next_u64(), *want, "output {i} of state {state:x?}");
        }
    }
    // The second block starts from the SplitMix64 seed expansion of seed 0.
    assert_eq!(Xoshiro256ss::seed_from_u64(0).state(), blocks[1].0);
    let mut g = Xoshiro256ss::seed_from_u64(44);
    for _ in 0..10_000 {
        assert_eq!(below(&mut g, 1), 0);
        assert!(below(&mut g, 2) < 2);
        assert!(below(&mut g, u64::MAX) < u64::MAX);
    }
}

#[test]
fn below_one_is_zero() {
    for seed in 0..64 {
        let mut g = Xoshiro256ss::seed_from_u64(seed);
        for _ in 0..256 {
            assert_eq!(below(&mut g, 1), 0);
        }
    }
    let mut g = Xoshiro256ss::seed_from_u64(1);
    assert_eq!(
        below(&mut g, 0),
        0,
        "no value is below 0, so the result is 0"
    );
}

#[test]
fn below_u64_max_in_range() {
    let mut g = Xoshiro256ss::seed_from_u64(9);
    let mut high = 0u32;
    for _ in 0..10_000 {
        let v = below(&mut g, u64::MAX);
        assert!(v < u64::MAX);
        if v > u64::MAX / 2 {
            high += 1;
        }
    }
    assert!(
        (4_000..6_000).contains(&high),
        "about half of the values are in the upper half: {high}"
    );
}

#[test]
fn below_matches_the_multiply_shift_reference() {
    // Without a rejection, the Lemire result is the high word of `x * n`.
    let mut source = Xoshiro256ss::seed_from_u64(0);
    let mut reference = Xoshiro256ss::seed_from_u64(0);
    let want_values = [0x1u64, 0x7, 0x67, 0x6a_a594_f126];
    for (n, fixed) in [3u64, 10, 1000, 1 << 40].into_iter().zip(want_values) {
        let x = reference.next_u64();
        let m = u128::from(x) * u128::from(n);
        let low = m & u128::from(u64::MAX);
        let threshold = u128::from(n.wrapping_neg() % n);
        assert!(low >= threshold, "this vector has no rejection");
        let want = u64::try_from(m >> 64).unwrap_or(u64::MAX);
        assert_eq!(want, fixed, "the Python reference gives the same value");
        assert_eq!(below(&mut source, n), want);
    }
}

#[test]
fn below_is_near_uniform_for_three() {
    let mut g = Xoshiro256ss::seed_from_u64(3);
    let mut counts = [0u32; 3];
    for _ in 0..30_000 {
        let v = below(&mut g, 3);
        let slot = usize::try_from(v).unwrap_or(usize::MAX);
        assert!(slot < 3);
        counts[slot] += 1;
    }
    for c in counts {
        assert!((9_500..10_500).contains(&c), "count {c} is near 10,000");
    }
}

#[test]
fn fill_bytes_uses_little_endian_outputs() {
    let mut a = Xoshiro256ss::from_state([1, 2, 3, 4]);
    let mut b = Xoshiro256ss::from_state([1, 2, 3, 4]);
    let mut buf = [0u8; 12];
    a.fill_bytes(&mut buf);
    let first = b.next_u64().to_le_bytes();
    let second = b.next_u64().to_le_bytes();
    assert_eq!(&buf[..8], &first);
    assert_eq!(&buf[8..], &second[..4]);
}

#[test]
fn fnv1a64_known_values() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
}
