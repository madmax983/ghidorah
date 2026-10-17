//! SHA-256 (FIPS 180-4).
//!
//! Users: the binary ID, the journal checksum, the state hash and the cursor args hash.

/// The size of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// The size of one message block in bytes.
const BLOCK_LEN: usize = 64;

/// The initial hash value of FIPS 180-4, Section 5.3.3.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The round constants of FIPS 180-4, Section 4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// A streaming SHA-256 hasher.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_LEN],
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
            state: H0,
            block: [0; BLOCK_LEN],
            block_len: 0,
            total: 0,
        }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.total = self
            .total
            .wrapping_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let mut rest = data;
        while !rest.is_empty() {
            let free = self.block.get_mut(self.block_len..).unwrap_or_default();
            let n = free.len().min(rest.len());
            let (now, later) = rest.split_at(n);
            for (dst, src) in free.iter_mut().zip(now) {
                *dst = *src;
            }
            self.block_len += n;
            rest = later;
            if self.block_len == BLOCK_LEN {
                compress(&mut self.state, &self.block);
                self.block_len = 0;
            }
        }
    }

    /// Gives the digest of the message.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK_LEN + 8];
        pad[0] = 0x80;
        // The padding ends the message at 56 bytes modulo 64, then the length follows.
        let pad_len = if self.block_len < 56 {
            56 - self.block_len
        } else {
            BLOCK_LEN + 56 - self.block_len
        };
        let total = self.total;
        self.update(&pad[..pad_len]);
        self.update(&bits.to_be_bytes());
        self.total = total;
        let mut out = [0u8; DIGEST_LEN];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Runs the compression function of FIPS 180-4, Section 6.2.2, on one block.
#[expect(
    clippy::many_single_char_names,
    reason = "the names a to h and w of FIPS 180-4"
)]
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        let mut b = [0u8; 4];
        b.copy_from_slice(bytes);
        *word = u32::from_be_bytes(b);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wt) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wt);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
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
