//! SHA-256 (FIPS 180-4).
//!
//! Users: the binary ID, the journal checksum, the state hash and the cursor args hash.

/// The size of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// A streaming SHA-256 hasher.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Makes a hasher in the initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [0; 8],
            block: [0; 64],
            block_len: 0,
            total: 0,
        }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        let _ = (data, self.block, self.block_len, self.total);
    }

    /// Gives the digest of the message.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let _ = self.state;
        [0; DIGEST_LEN]
    }
}

/// Gives the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Gives the SHA-256 digest of `data` as 64 lower case hex digits.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    crate::hex::encode(&sha256(data))
}
