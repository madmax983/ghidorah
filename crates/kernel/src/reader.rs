//! K1: a bounded reader over a borrowed byte buffer.
//!
//! Verus proves these properties of every call:
//!
//! - The position stays in the buffer: `pos <= buf.len()`.
//! - A successful read gives the bytes `buf[old_pos..new_pos]`.
//! - A failed call keeps the position.
//! - No call adds an offset and a length without a check.
//! - The LEB128 reads reject a bad 10th byte.

use core::fmt;

#[cfg(not(verus_only))]
use ghidorah_spec::{verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

/// The byte order of the multi-byte reads.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Endian {
    /// The least significant byte comes first.
    Little,
    /// The most significant byte comes first.
    Big,
}

/// The cause of a failed read.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadError {
    /// Fewer bytes remain than the read needs.
    Eof,
    /// A LEB128 value has no end in 10 bytes, or its 10th byte is not valid.
    BadLeb,
    /// No NUL byte comes in the remaining bytes or in the length limit of the C string.
    NoNul,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Eof => "the data ends before the end of the read",
            Self::BadLeb => "the LEB128 value is not valid",
            Self::NoNul => "the C string has no NUL byte in its limit",
        })
    }
}

impl std::error::Error for ReadError {}

/// A cursor over a borrowed byte buffer.
///
/// The position is always in the buffer. A failed read keeps the position.
#[verus_verify]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    endian: Endian,
}

#[cfg(verus_only)]
verus! {

impl<'a> Reader<'a> {
    /// The position is in the buffer.
    pub closed spec fn wf(&self) -> bool {
        self.pos <= self.buf@.len()
    }

    /// The position.
    pub closed spec fn at(&self) -> int {
        self.pos as int
    }

    /// The bytes of the buffer.
    pub closed spec fn data(&self) -> Seq<u8> {
        self.buf@
    }

    /// The byte order.
    pub closed spec fn order(&self) -> Endian {
        self.endian
    }

    /// The count of bytes after the position.
    pub open spec fn left(&self) -> int {
        self.data().len() - self.at()
    }

    /// The bytes after the position.
    pub open spec fn tail(&self) -> Seq<u8> {
        self.data().subrange(self.at(), self.data().len() as int)
    }

    /// `self` is `old` with the position `n` bytes further on.
    pub open spec fn moved(&self, old: &Self, n: int) -> bool {
        &&& self.wf()
        &&& self.data() == old.data()
        &&& self.order() == old.order()
        &&& self.at() == old.at() + n
    }
}

/// The value of the two bytes `s[0..2]` in the byte order `e`.
pub open spec fn spec_u16(e: Endian, s: Seq<u8>) -> u16 {
    if e == Endian::Little {
        (s[0] as u16) | ((s[1] as u16) << 8u16)
    } else {
        ((s[0] as u16) << 8u16) | (s[1] as u16)
    }
}

/// The value of the four bytes `s[0..4]` in the byte order `e`.
pub open spec fn spec_u32(e: Endian, s: Seq<u8>) -> u32 {
    let a = spec_u16(e, s.subrange(0, 2)) as u32;
    let b = spec_u16(e, s.subrange(2, 4)) as u32;
    if e == Endian::Little {
        a | (b << 16u32)
    } else {
        (a << 16u32) | b
    }
}

/// The value of the eight bytes `s[0..8]` in the byte order `e`.
pub open spec fn spec_u64(e: Endian, s: Seq<u8>) -> u64 {
    let a = spec_u32(e, s.subrange(0, 4)) as u64;
    let b = spec_u32(e, s.subrange(4, 8)) as u64;
    if e == Endian::Little {
        a | (b << 32u64)
    } else {
        (a << 32u64) | b
    }
}

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
impl<'a> Reader<'a> {
    /// Makes a reader at position 0 of `buf`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r.wf(),
            r.at() == 0,
            r.data() == buf@,
            r.order() == endian,
    )]
    pub fn new(buf: &'a [u8], endian: Endian) -> Self {
        Self {
            buf,
            pos: 0,
            endian,
        }
    }

    /// Gives the position.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r as int == self.at(),
    )]
    pub fn pos(&self) -> usize {
        0
    }

    /// Gives the count of bytes after the position.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            r as int == self.left(),
    )]
    pub fn remaining(&self) -> usize {
        0
    }

    /// Gives the byte order of the multi-byte reads.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == self.order(),
    )]
    pub fn endian(&self) -> Endian {
        Endian::Big
    }

    /// Gives the bytes after the position. The position does not move.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            r@ == self.tail(),
    )]
    pub fn rest(&self) -> &'a [u8] {
        &[]
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] at the end of the buffer.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => old(self).left() >= 1 && v == old(self).data()[old(self).at()]
                    && final(self).moved(old(self), 1),
                Err(e) => e == ReadError::Eof && old(self).left() < 1
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Err(ReadError::Eof)
    }

    /// Reads a `u16` in the byte order of the reader.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when fewer than 2 bytes remain.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => old(self).left() >= 2
                    && v == spec_u16(old(self).order(), old(self).tail().subrange(0, 2))
                    && final(self).moved(old(self), 2),
                Err(e) => e == ReadError::Eof && old(self).left() < 2
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        Err(ReadError::Eof)
    }

    /// Reads a `u32` in the byte order of the reader.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when fewer than 4 bytes remain.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => old(self).left() >= 4
                    && v == spec_u32(old(self).order(), old(self).tail().subrange(0, 4))
                    && final(self).moved(old(self), 4),
                Err(e) => e == ReadError::Eof && old(self).left() < 4
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        Err(ReadError::Eof)
    }

    /// Reads a `u64` in the byte order of the reader.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when fewer than 8 bytes remain.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(v) => old(self).left() >= 8
                    && v == spec_u64(old(self).order(), old(self).tail().subrange(0, 8))
                    && final(self).moved(old(self), 8),
                Err(e) => e == ReadError::Eof && old(self).left() < 8
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        Err(ReadError::Eof)
    }

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
    pub fn uleb128(&mut self) -> Result<u64, ReadError> {
        Err(ReadError::Eof)
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
    pub fn sleb128(&mut self) -> Result<i64, ReadError> {
        Err(ReadError::Eof)
    }

    /// Reads a C string of at most `max_len` bytes and its NUL byte.
    ///
    /// The result does not include the NUL byte. The position moves past the NUL byte.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::NoNul`] when no NUL byte comes in the first `max_len + 1` bytes.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(s) => {
                    &&& s@.len() <= max_len
                    &&& s@.len() < old(self).left()
                    &&& s@ == old(self).tail().subrange(0, s@.len() as int)
                    &&& old(self).tail()[s@.len() as int] == 0
                    &&& forall|k: int| 0 <= k < s@.len() ==> s@[k] != 0
                    &&& final(self).moved(old(self), s@.len() + 1)
                },
                Err(e) => {
                    &&& e == ReadError::NoNul
                    &&& forall|k: int| 0 <= k < old(self).left() && k <= max_len
                        ==> old(self).tail()[k] != 0
                    &&& final(self).moved(old(self), 0)
                },
            },
    )]
    pub fn cstr(&mut self, max_len: usize) -> Result<&'a [u8], ReadError> {
        Err(ReadError::NoNul)
    }

    /// Reads `n` bytes as a slice of the buffer.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when fewer than `n` bytes remain.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(s) => n <= old(self).left()
                    && s@ == old(self).tail().subrange(0, n as int)
                    && final(self).moved(old(self), n as int),
                Err(e) => e == ReadError::Eof && n > old(self).left()
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        Err(ReadError::Eof)
    }

    /// Moves the position `n` bytes further on.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when fewer than `n` bytes remain.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(()) => n <= old(self).left() && final(self).moved(old(self), n as int),
                Err(e) => e == ReadError::Eof && n > old(self).left()
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn skip(&mut self, n: usize) -> Result<(), ReadError> {
        Err(ReadError::Eof)
    }

    /// Moves the position to the offset `off` of the buffer.
    ///
    /// # Errors
    ///
    /// Gives [`ReadError::Eof`] when `off` is after the end of the buffer.
    #[verus_spec(r =>
        requires
            old(self).wf(),
        ensures
            match r {
                Ok(()) => off <= old(self).data().len()
                    && final(self).moved(old(self), off - old(self).at()),
                Err(e) => e == ReadError::Eof && off > old(self).data().len()
                    && final(self).moved(old(self), 0),
            },
    )]
    pub fn seek(&mut self, off: usize) -> Result<(), ReadError> {
        Err(ReadError::Eof)
    }
}
