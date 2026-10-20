//! The LEB128 reads of K1: unsigned and signed values of at most 64 bits.
//!
//! A value has at most 10 bytes. Verus proves that each read rejects a bad 10th byte.
//! Verus also proves the error rule: each read gives an error only for data without a valid value.
//! The data ends in the value, or the 10th byte is bad.

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

/// The data ends in a LEB128 value: fewer than 10 bytes are left, and each has the continuation bit.
pub open spec fn leb_eof(s: Seq<u8>) -> bool {
    &&& s.len() < 10
    &&& forall|k: int| 0 <= k < s.len() ==> s[k] >= 0x80
}

/// The first 10 bytes of `s` are not a valid unsigned LEB128 value of 64 bits.
///
/// The first 9 bytes have the continuation bit. The 10th byte also has it, or it is more than 1.
pub open spec fn uleb_bad(s: Seq<u8>) -> bool {
    &&& s.len() >= 10
    &&& forall|k: int| 0 <= k < 9 ==> s[k] >= 0x80
    &&& !uleb_valid(s, 10)
}

/// The first 10 bytes of `s` are not a valid signed LEB128 value of 64 bits.
///
/// The first 9 bytes have the continuation bit. The 10th byte is not `0x00` and not `0x7f`.
pub open spec fn sleb_bad(s: Seq<u8>) -> bool {
    &&& s.len() >= 10
    &&& forall|k: int| 0 <= k < 9 ==> s[k] >= 0x80
    &&& !sleb_valid(s, 10)
}

/// `e` is the error of a failed LEB128 read of `s`.
///
/// The error is `Eof` exactly when the data ends in the value.
/// Else it is `BadLeb`, and the first 10 bytes are not a valid value.
pub open spec fn leb_error(s: Seq<u8>, signed: bool, e: ReadError) -> bool {
    if leb_eof(s) {
        e == ReadError::Eof
    } else {
        &&& e == ReadError::BadLeb
        &&& if signed {
            sleb_bad(s)
        } else {
            uleb_bad(s)
        }
    }
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
    /// Gives [`ReadError::Eof`] when the data ends in the value: fewer than 10 bytes are left,
    /// and each has the continuation bit.
    /// Gives [`ReadError::BadLeb`] for a bad 10th byte. Each valid value gives `Ok`.
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
                Err(e) => {
                    &&& leb_error(old(self).tail(), false, e)
                    &&& final(self).moved(old(self), 0)
                },
            },
    )]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn uleb128(&mut self) -> Result<u64, ReadError> {
        let (value, n, _) = self.leb_scan(false)?;
        self.pos += n;
        Ok(value)
    }

    /// Reads a signed LEB128 value of at most 64 bits.
    ///
    /// The value has at most 10 bytes. The 10th byte can only be `0x00` or `0x7f`.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when the data ends in the value: fewer than 10 bytes are left,
    /// and each has the continuation bit.
    /// Gives [`ReadError::BadLeb`] for a bad 10th byte. Each valid value gives `Ok`.
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
                Err(e) => {
                    &&& leb_error(old(self).tail(), true, e)
                    &&& final(self).moved(old(self), 0)
                },
            },
    )]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    #[expect(
        clippy::cast_possible_wrap,
        reason = "the two's complement view of the 64 bits is the value"
    )]
    pub fn sleb128(&mut self) -> Result<i64, ReadError> {
        let (mut value, n, last) = self.leb_scan(true)?;
        // A value of fewer than 10 bytes takes the sign from bit 6 of its last byte.
        if n < 10 && (last & 0x40) != 0 {
            value |= u64::MAX << (7 * n);
        }
        self.pos += n;
        Ok(value as i64)
    }

    /// Reads the bytes of a LEB128 value at the position. The position does not move.
    ///
    /// Gives the bits without sign extension, the byte count and the last byte.
    /// The 10th byte must be 0 or 1. With `signed`, it must be `0x00` or `0x7f`.
    /// The error follows the rule of `leb_error`.
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            self.data().len() <= usize::MAX,
            match r {
                Ok((v, n, last)) => {
                    &&& if signed {
                        sleb_valid(self.tail(), n as int)
                    } else {
                        uleb_valid(self.tail(), n as int)
                    }
                    &&& v == spec_leb_bits(self.tail(), n as nat)
                    &&& last == self.tail()[n - 1]
                },
                Err(e) => leb_error(self.tail(), signed, e),
            },
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    fn leb_scan(&self, signed: bool) -> Result<(u64, usize, u8), ReadError> {
        let start = self.pos;
        let left = self.buf.len() - start;
        let mut value: u64 = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                self.wf(),
                start as int == self.at(),
                start as int + left as int == self.data().len(),
                self.data().len() <= usize::MAX,
                i <= 9,
                forall|k: int| 0 <= k < i ==> self.tail()[k] >= 0x80,
                value == spec_leb_bits(self.tail(), i as nat),
            decreases 10 - i,
        ))]
        loop {
            if i >= left {
                return Err(ReadError::Eof);
            }
            let b = self.buf[start + i];
            proof! {
                assert(b == self.tail()[i as int]);
            }
            let tenth_ok = if signed { b == 0 || b == 0x7f } else { b <= 1 };
            if i == 9 && !tenth_ok {
                return Err(ReadError::BadLeb);
            }
            value |= u64::from(b & 0x7f) << (7 * i);
            if b < 0x80 {
                return Ok((value, i + 1, b));
            }
            i += 1;
        }
    }
}
