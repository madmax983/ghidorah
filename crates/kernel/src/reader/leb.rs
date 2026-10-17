//! The LEB128 reads of K1: unsigned and signed values of at most 64 bits.
//!
//! A value has at most 10 bytes. Verus proves that each read rejects a bad 10th byte.

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

use super::{ReadError, Reader};

#[cfg(verus_only)]
verus! {

/// The bits of the first `n` LEB128 bytes of `s`, without sign extension.
pub open spec fn spec_leb_bits(s: Seq<u8>, n: nat) -> u64
    decreases n,
{
    if n == 0 || n > 10 {
        0
    } else {
        let k = (n - 1) as nat;
        spec_leb_bits(s, k) | (((s[k as int] & 0x7f) as u64) << ((7 * k) as u64))
    }
}

/// The first `n` bytes of `s` have the LEB128 form.
///
/// Each byte before the last has the continuation bit. The last byte does not.
pub open spec fn leb_form(s: Seq<u8>, n: int) -> bool {
    &&& 1 <= n <= 10
    &&& n <= s.len()
    &&& forall|k: int| 0 <= k < n - 1 ==> s[k] >= 0x80
    &&& s[n - 1] < 0x80
}

/// The first `n` bytes of `s` are a valid unsigned LEB128 value of 64 bits.
pub open spec fn uleb_valid(s: Seq<u8>, n: int) -> bool {
    leb_form(s, n) && (n == 10 ==> s[9] <= 1)
}

/// The first `n` bytes of `s` are a valid signed LEB128 value of 64 bits.
pub open spec fn sleb_valid(s: Seq<u8>, n: int) -> bool {
    leb_form(s, n) && (n == 10 ==> (s[9] == 0 || s[9] == 0x7f))
}

/// The signed value of the first `n` LEB128 bytes of `s`.
pub open spec fn spec_sleb(s: Seq<u8>, n: nat) -> i64 {
    let bits = spec_leb_bits(s, n);
    if 1 <= n < 10 && (s[n - 1] & 0x40) != 0 {
        (bits | (0xffff_ffff_ffff_ffffu64 << ((7 * n) as u64))) as i64
    } else {
        bits as i64
    }
}

} // verus!

#[verus_verify]
impl Reader<'_> {
    /// Reads an unsigned LEB128 value of at most 64 bits.
    ///
    /// The value has at most 10 bytes. The 10th byte can only be 0 or 1.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when the data ends in the value.
    /// Gives [`ReadError::BadLeb`] for a bad 10th byte.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => {
                    let n = final(self).at() - old(self).at();
                    &&& uleb_valid(old(self).tail(), n)
                    &&& v == spec_leb_bits(old(self).tail(), n as nat)
                    &&& final(self).moved(old(self), n)
                },
                Err(e) => (e == ReadError::Eof || e == ReadError::BadLeb)
                    && final(self).moved(old(self), 0),
            },
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn uleb128(&mut self) -> Result<u64, ReadError> {
        let start = self.pos;
        let left = self.buf.len() - start;
        let mut value: u64 = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                self.moved(old(self), 0),
                start as int == old(self).at(),
                start as int + left as int == self.data().len(),
                self.data().len() <= usize::MAX,
                i <= 9,
                forall|k: int| 0 <= k < i ==> old(self).tail()[k] >= 0x80,
                value == spec_leb_bits(old(self).tail(), i as nat),
            decreases 10 - i,
        ))]
        loop {
            if i >= left {
                return Err(ReadError::Eof);
            }
            let b = self.buf[start + i];
            proof! {
                assert(b == old(self).tail()[i as int]);
            }
            if i == 9 && b > 1 {
                return Err(ReadError::BadLeb);
            }
            value |= u64::from(b & 0x7f) << (7 * i);
            if b < 0x80 {
                self.pos = start + i + 1;
                return Ok(value);
            }
            i += 1;
        }
    }

    /// Reads a signed LEB128 value of at most 64 bits.
    ///
    /// The value has at most 10 bytes. The 10th byte can only be `0x00` or `0x7f`.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when the data ends in the value.
    /// Gives [`ReadError::BadLeb`] for a bad 10th byte.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => {
                    let n = final(self).at() - old(self).at();
                    &&& sleb_valid(old(self).tail(), n)
                    &&& v == spec_sleb(old(self).tail(), n as nat)
                    &&& final(self).moved(old(self), n)
                },
                Err(e) => (e == ReadError::Eof || e == ReadError::BadLeb)
                    && final(self).moved(old(self), 0),
            },
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    #[expect(
        clippy::cast_possible_wrap,
        reason = "the two's complement view of the 64 bits is the value"
    )]
    pub fn sleb128(&mut self) -> Result<i64, ReadError> {
        let start = self.pos;
        let left = self.buf.len() - start;
        let mut value: u64 = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                self.moved(old(self), 0),
                start as int == old(self).at(),
                start as int + left as int == self.data().len(),
                self.data().len() <= usize::MAX,
                i <= 9,
                forall|k: int| 0 <= k < i ==> old(self).tail()[k] >= 0x80,
                value == spec_leb_bits(old(self).tail(), i as nat),
            decreases 10 - i,
        ))]
        loop {
            if i >= left {
                return Err(ReadError::Eof);
            }
            let b = self.buf[start + i];
            proof! {
                assert(b == old(self).tail()[i as int]);
            }
            if i == 9 && b != 0 && b != 0x7f {
                return Err(ReadError::BadLeb);
            }
            value |= u64::from(b & 0x7f) << (7 * i);
            if b < 0x80 {
                let n = i + 1;
                if n < 10 && (b & 0x40) != 0 {
                    value |= u64::MAX << (7 * n);
                }
                self.pos = start + n;
                return Ok(value as i64);
            }
            i += 1;
        }
    }
}
