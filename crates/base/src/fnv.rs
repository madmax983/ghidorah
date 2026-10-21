//! FNV-1a with 64 bits.
//!
//! Users: similarity feature keys (Section 7.13), cursor checks (Section 10.9) and the
//! hash form of anonymous type IDs. The hash is not for security.

/// The FNV-1a offset basis for 64 bits.
pub const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// The FNV-1a prime for 64 bits.
pub const PRIME: u64 = 0x0000_0100_0000_01b3;

/// A streaming FNV-1a hasher with 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fnv1a64(u64);

impl Default for Fnv1a64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Fnv1a64 {
    /// Makes a hasher in the initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self(OFFSET_BASIS)
    }

    /// Adds `bytes` to the hash.
    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(PRIME);
        }
    }

    /// Adds one byte to the hash.
    pub fn write_u8(&mut self, byte: u8) {
        self.write(&[byte]);
    }

    /// Gives the hash of the bytes so far.
    #[must_use]
    pub const fn finish(&self) -> u64 {
        self.0
    }
}

/// Gives the FNV-1a hash with 64 bits of `bytes`.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hasher = Fnv1a64::new();
    hasher.write(bytes);
    hasher.finish()
}
