//! IDs that hold one address or one number.

use std::fmt;
use std::str::FromStr;

use super::{IdError, IdKind, from_str_via_id, parse_dec, parse_dec_as};
use crate::address::Address;
use crate::hex;

/// A function, named by its entry address. Text: `fn:0x401130`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuncId(pub Address);

/// A basic block, named by its start address. Text: `bb:0x401145`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub Address);

/// A string, named by its address. Text: `str:0x402010`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StringId(pub Address);

/// A jump table, named by the address of its indirect jump. Text: `jt:0x401200`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JumpTableId(pub Address);

/// An offset in the input file. Text: `file:0x1040`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileOffset(pub u64);

/// A segment, named by its index. Text: `seg:2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId(pub u16);

/// A note. Text: `note:7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteId(pub u64);

/// A committed transaction. Text: `tx:42`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId(pub u64);

/// A revision of a program. Output writes it as the JSON integer field `rev`.
///
/// The text form is the decimal number, for example `57`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rev(pub u64);

/// An IR op: the address of its instruction and a sequence number. Text: `op:0x401a2c:3`.
///
/// The lifter uses `0..=0x7fff`, the passes use `0x8000..` and phis use `0xf000 + k`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId {
    /// The RAM address of the instruction.
    pub addr: u64,
    /// The sequence number of the op.
    pub seq: u16,
}

impl OpId {
    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        let (addr, seq) = body
            .rsplit_once(':')
            .ok_or(IdError::bad(IdKind::Op, "sequence"))?;
        let addr = hex::parse_u64(addr).ok_or(IdError::bad(IdKind::Op, "address"))?;
        let seq = parse_dec_as::<u16>(seq).ok_or(IdError::bad(IdKind::Op, "sequence"))?;
        Ok(Self { addr, seq })
    }
}

/// A binary: the first 8 bytes of the SHA-256 of the file. Text: 16 lower case hex digits.
///
/// Input also accepts all 64 digits of the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinaryId(pub [u8; 8]);

impl BinaryId {
    /// Makes the ID of a file from the SHA-256 of the file.
    #[must_use]
    pub fn from_sha256(hash: &[u8; 32]) -> Self {
        let mut id = [0u8; 8];
        for (dst, src) in id.iter_mut().zip(hash) {
            *dst = *src;
        }
        Self(id)
    }

    /// Parses 16 or 64 hex digits in either letter case.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for any other text.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let bad = IdError::BadPart {
            kind: None,
            part: "binary_id",
        };
        if text.len() != 16 && text.len() != 64 {
            return Err(bad);
        }
        let bytes = hex::decode(text).map_err(|_| bad)?;
        let mut id = [0u8; 8];
        for (dst, src) in id.iter_mut().zip(&bytes) {
            *dst = *src;
        }
        Ok(Self(id))
    }
}

impl fmt::Display for BinaryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl FromStr for BinaryId {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, IdError> {
        Self::parse(text)
    }
}

impl fmt::Display for Rev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Rev {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, IdError> {
        parse_dec(text).map(Self).ok_or(IdError::BadPart {
            kind: None,
            part: "rev",
        })
    }
}

/// Writes `prefix` and the text form of `value`.
fn write_prefixed(
    f: &mut fmt::Formatter<'_>,
    prefix: &str,
    value: &dyn fmt::Display,
) -> fmt::Result {
    write!(f, "{prefix}{value}")
}

impl fmt::Display for FuncId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "fn:", &self.0)
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "bb:", &self.0)
    }
}

impl fmt::Display for StringId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "str:", &self.0)
    }
}

impl fmt::Display for JumpTableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "jt:", &self.0)
    }
}

impl fmt::Display for FileOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file:{:#x}", self.0)
    }
}

impl fmt::Display for SegmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "seg:", &self.0)
    }
}

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "note:", &self.0)
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_prefixed(f, "tx:", &self.0)
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op:{:#x}:{}", self.addr, self.seq)
    }
}

from_str_via_id!(FuncId, Func);
from_str_via_id!(BlockId, Block);
from_str_via_id!(StringId, Str);
from_str_via_id!(JumpTableId, JumpTable);
from_str_via_id!(FileOffset, File);
from_str_via_id!(SegmentId, Segment);
from_str_via_id!(NoteId, Note);
from_str_via_id!(TxId, Tx);
from_str_via_id!(OpId, Op);
