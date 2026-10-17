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

mod leb;

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec, verus_verify};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Joins two bytes in the byte order `e`. The byte `x` comes first in memory.
pub open spec fn join16(e: Endian, x: u8, y: u8) -> u16 {
    if e == Endian::Little {
        (x as u16) | ((y as u16) << 8u16)
    } else {
        ((x as u16) << 8u16) | (y as u16)
    }
}

/// Joins two `u16` halves in the byte order `e`. The half `x` comes first in memory.
pub open spec fn join32(e: Endian, x: u16, y: u16) -> u32 {
    if e == Endian::Little {
        (x as u32) | ((y as u32) << 16u32)
    } else {
        ((x as u32) << 16u32) | (y as u32)
    }
}

/// Joins two `u32` halves in the byte order `e`. The half `x` comes first in memory.
pub open spec fn join64(e: Endian, x: u32, y: u32) -> u64 {
    if e == Endian::Little {
        (x as u64) | ((y as u64) << 32u64)
    } else {
        ((x as u64) << 32u64) | (y as u64)
    }
}

/// The value of the two bytes `s[0..2]` in the byte order `e`.
pub open spec fn spec_u16(e: Endian, s: Seq<u8>) -> u16 {
    join16(e, s[0], s[1])
}

/// The value of the four bytes `s[0..4]` in the byte order `e`.
pub open spec fn spec_u32(e: Endian, s: Seq<u8>) -> u32 {
    join32(e, join16(e, s[0], s[1]), join16(e, s[2], s[3]))
}

/// The value of the eight bytes `s[0..8]` in the byte order `e`.
pub open spec fn spec_u64(e: Endian, s: Seq<u8>) -> u64 {
    join64(
        e,
        join32(e, join16(e, s[0], s[1]), join16(e, s[2], s[3])),
        join32(e, join16(e, s[4], s[5]), join16(e, s[6], s[7])),
    )
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
        self.pos
    }

    /// Gives the count of bytes after the position.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            r as int == self.left(),
    )]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Gives the byte order of the multi-byte reads.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == self.order(),
    )]
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Gives the bytes after the position. The position does not move.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            r@ == self.tail(),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        if self.pos >= self.buf.len() {
            return Err(ReadError::Eof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        let s = self.take(2)?;
        Ok(join_u16(self.endian, s[0], s[1]))
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        let s = self.take(4)?;
        let e = self.endian;
        Ok(join_u32(
            e,
            join_u16(e, s[0], s[1]),
            join_u16(e, s[2], s[3]),
        ))
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        let s = self.take(8)?;
        let e = self.endian;
        let low = join_u32(e, join_u16(e, s[0], s[1]), join_u16(e, s[2], s[3]));
        let high = join_u32(e, join_u16(e, s[4], s[5]), join_u16(e, s[6], s[7]));
        Ok(join_u64(e, low, high))
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
                    &&& final(self).moved(old(self), s@.len() as int + 1)
                },
                Err(e) => {
                    &&& e == ReadError::NoNul
                    &&& forall|k: int| 0 <= k < old(self).left() && k <= max_len
                        ==> old(self).tail()[k] != 0
                    &&& final(self).moved(old(self), 0)
                },
            },
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn cstr(&mut self, max_len: usize) -> Result<&'a [u8], ReadError> {
        let start = self.pos;
        let left = self.buf.len() - start;
        let mut i: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                self.moved(old(self), 0),
                start as int == old(self).at(),
                start as int + left as int == self.data().len(),
                self.data().len() <= usize::MAX,
                i <= left,
                i <= max_len + 1,
                forall|k: int| 0 <= k < i ==> old(self).tail()[k] != 0,
            decreases left - i,
        ))]
        while i < left && i <= max_len {
            if self.buf[start + i] == 0 {
                let s = &self.buf[start..start + i];
                self.pos = start + i + 1;
                return Ok(s);
            }
            proof! {
                assert(old(self).tail()[i as int] == self.buf@[start + i]);
            }
            i += 1;
        }
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        if n > self.buf.len() - self.pos {
            return Err(ReadError::Eof);
        }
        let start = self.pos;
        let s = &self.buf[start..start + n];
        self.pos = start + n;
        Ok(s)
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
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn skip(&mut self, n: usize) -> Result<(), ReadError> {
        if n > self.buf.len() - self.pos {
            return Err(ReadError::Eof);
        }
        self.pos += n;
        Ok(())
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
        if off > self.buf.len() {
            return Err(ReadError::Eof);
        }
        self.pos = off;
        Ok(())
    }
}

/// Joins two bytes in the byte order `e`. The byte `x` comes first in memory.
#[verus_spec(r =>
    ensures
        r == join16(e, x, y),
)]
fn join_u16(e: Endian, x: u8, y: u8) -> u16 {
    let (x, y) = (u16::from(x), u16::from(y));
    match e {
        Endian::Little => x | (y << 8),
        Endian::Big => (x << 8) | y,
    }
}

/// Joins two `u16` halves in the byte order `e`. The half `x` comes first in memory.
#[verus_spec(r =>
    ensures
        r == join32(e, x, y),
)]
fn join_u32(e: Endian, x: u16, y: u16) -> u32 {
    let (x, y) = (u32::from(x), u32::from(y));
    match e {
        Endian::Little => x | (y << 16),
        Endian::Big => (x << 16) | y,
    }
}

/// Joins two `u32` halves in the byte order `e`. The half `x` comes first in memory.
#[verus_spec(r =>
    ensures
        r == join64(e, x, y),
)]
fn join_u64(e: Endian, x: u32, y: u32) -> u64 {
    let (x, y) = (u64::from(x), u64::from(y));
    match e {
        Endian::Little => x | (y << 32),
        Endian::Big => (x << 32) | y,
    }
}
