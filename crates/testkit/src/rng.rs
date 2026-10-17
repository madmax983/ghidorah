//! Deterministic pseudo-random number generators.
//!
//! `SplitMix64` seeds other generators. `Xoshiro256ss` is the main generator.
//! The [`below`] function gives a uniform value in `0..n` with the Lemire method.
//! These generators are for tests only. They are not cryptographic.

/// A source of 64-bit pseudo-random values.
pub trait Rng {
    /// Returns the next 64-bit value.
    fn next_u64(&mut self) -> u64;
}

/// The `SplitMix64` generator of Steele, Lea and Flood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Makes a generator with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next value. This `const` form lets other `const fn` items seed from it.
    #[must_use]
    pub const fn next_const(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Rng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.next_const()
    }
}

/// The xoshiro256** generator of Blackman and Vigna.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xoshiro256ss {
    s: [u64; 4],
}

impl Xoshiro256ss {
    /// Makes a generator from a full state.
    ///
    /// An all-zero state gives only zeros. Use [`Xoshiro256ss::seed_from_u64`] for normal seeds.
    #[must_use]
    pub const fn from_state(s: [u64; 4]) -> Self {
        Self { s }
    }

    /// Makes a generator whose state is the first four `SplitMix64` values of `seed`.
    #[must_use]
    pub const fn seed_from_u64(seed: u64) -> Self {
        let mut sm = SplitMix64::new(seed);
        let a = sm.next_const();
        let b = sm.next_const();
        let c = sm.next_const();
        let d = sm.next_const();
        Self { s: [a, b, c, d] }
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> [u64; 4] {
        self.s
    }

    /// Fills `buf` with pseudo-random bytes.
    ///
    /// Each 8 bytes are one output in little-endian order. A short tail uses the first bytes of one output.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }
}

impl Rng for Xoshiro256ss {
    fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1 << 17;
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        let s2 = s2 ^ t;
        let s3 = s3.rotate_left(45);
        self.s = [s0, s1, s2, s3];
        result
    }
}

/// Returns the 64-bit FNV-1a hash of `bytes`.
///
/// The kit uses it for fixed seeds from names and for golden file checksums.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Returns the high and the low 64 bits of `x * n`.
fn mul_wide(x: u64, n: u64) -> (u64, u64) {
    let m = u128::from(x) * u128::from(n);
    let high = u64::try_from(m >> 64).unwrap_or(u64::MAX);
    let low = u64::try_from(m & u128::from(u64::MAX)).unwrap_or(0);
    (high, low)
}

/// Returns a uniform value in `0..n` with the Lemire multiply-and-reject method.
///
/// For `n == 0` no value is below `n`, so the function returns 0.
/// The rejection loop runs fewer than two times on average.
pub fn below<R: Rng + ?Sized>(rng: &mut R, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let (mut high, mut low) = mul_wide(rng.next_u64(), n);
    if low < n {
        let threshold = n.wrapping_neg() % n;
        while low < threshold {
            (high, low) = mul_wide(rng.next_u64(), n);
        }
    }
    high
}
