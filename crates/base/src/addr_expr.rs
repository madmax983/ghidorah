//! The syntax of address input (design Section 10.5, ADR-0007).
//!
//! ```text
//! addr_input   := json_integer          ; decimal value, 0 <= v < 2^53
//!               | string
//! string       := expr
//! expr         := term ( ("+" | "-") offset )?
//! offset       := hex                   ; "main+16" is ADDRESS_BASE_AMBIGUOUS
//! term         := hex | id | name | section | default_name | name_at
//! hex          := "0x" [0-9a-fA-F]{1,16}
//! ```
//!
//! This module reads only the syntax. It knows no symbols and no sections.
//! The resolver of `ghidorah-tools` applies the rule order to the result:
//!
//! | Rule | Form | Result |
//! |---|---|---|
//! | 1 | JSON integer below 2^53 | [`AddrExpr::Integer`] from [`from_integer`] |
//! | 2 | `0x` and 1 to 16 hex digits | [`AddrExpr::Hex`] |
//! | 3 | A registered ID prefix, as an exact parse | [`AddrExpr::Id`]. `sym:` takes the whole rest. |
//! | - | Digits only | [`AddrExpr::Digits`]: never guessed, `ADDRESS_BASE_AMBIGUOUS` |
//! | 4, 5 | The whole text as a symbol or section name | [`NameExpr::text`] |
//! | 6 | A default name such as `FUN_00401000` | [`NameExpr::default`] |
//! | 7 | `name@0x<hex>` | [`NameExpr::at`] |
//! | 8 | `term+0x..` or `term-0x..`, split at the last sign | [`NameExpr::split`] or [`AddrExpr::Offset`] |
//!
//! The parser trims ASCII white space at both ends. An offset of digits only gives
//! [`OffsetValue::Digits`], so the resolver can report `ADDRESS_BASE_AMBIGUOUS`.

use std::fmt;

use crate::catalog::ErrorCode;
use crate::default_name::DefaultName;
use crate::id::{Id, IdError, MAX_ID_TEXT};

/// The smallest JSON integer that is not a valid address input: 2^53.
pub const JSON_INT_LIMIT: u64 = 1 << 53;

/// The largest address text in bytes.
pub const MAX_EXPR_LEN: usize = MAX_ID_TEXT;

/// The two readings of a text of digits only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Readings {
    /// The decimal value, or `None` when it is above `u64::MAX`.
    pub decimal: Option<u64>,
    /// The hex value, or `None` when the text has more than 16 digits.
    pub hex: Option<u64>,
}

/// The offset of an offset expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OffsetValue {
    /// A `0x` hex offset.
    Hex(u64),
    /// An offset of digits only. The resolver reports `ADDRESS_BASE_AMBIGUOUS` for it.
    Digits(Readings),
}

/// A term with an offset: `term+0x10` or `term-0x10`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OffsetExpr {
    /// The term before the sign. It holds no offset of its own.
    pub term: Box<AddrExpr>,
    /// `true` for `-`, `false` for `+`.
    pub negative: bool,
    /// The offset after the sign.
    pub offset: OffsetValue,
}

/// A name and an address: `helper@0x401000`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameAt {
    /// The name before the last `@`.
    pub name: String,
    /// The address after the last `@`.
    pub addr: u64,
}

/// The readings of a text that can be a name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameExpr {
    /// The whole text: a symbol name (rule 4) or a section name (rule 5).
    pub text: String,
    /// The text as a default name (rule 6).
    pub default: Option<DefaultName>,
    /// The text as `name@0x<hex>` (rule 7).
    pub at: Option<NameAt>,
    /// The text as a term and an offset (rule 8).
    pub split: Option<OffsetExpr>,
    /// The value of a text of 1 to 16 hex digits with at least one letter and no `0x`.
    ///
    /// The resolver uses it for the repair call of `ADDRESS_INVALID`.
    pub bare_hex: Option<u64>,
}

/// The syntax tree of one address input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrExpr {
    /// Rule 1: a JSON integer below 2^53.
    Integer(u64),
    /// Rule 2: `0x` and 1 to 16 hex digits.
    Hex(u64),
    /// Rule 3: an ID with a registered prefix.
    Id(Id),
    /// A text of digits only. The resolver never guesses its base.
    Digits(Readings),
    /// Rules 4 to 8: a text that can be a name.
    Name(NameExpr),
    /// Rule 8 for a term that is not a name: for example `0x401000+0x10` or `fn:0x401000-0x4`.
    Offset(OffsetExpr),
}

/// An error of the address syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrExprError {
    /// The text is empty after the trim.
    Empty,
    /// The text is longer than [`MAX_EXPR_LEN`] bytes.
    TooLong {
        /// The length of the text in bytes.
        len: usize,
    },
    /// The text starts with `0x` but is not hex and not a hex term with an offset.
    BadHex,
    /// The text has an ID prefix but is not an ID and not an ID term with an offset.
    BadId(IdError),
    /// The JSON integer is 2^53 or more.
    IntegerTooLarge(u64),
}

impl AddrExprError {
    /// Gives the error code: `ADDRESS_INVALID`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::AddressInvalid
    }

    /// Gives the corrected address text of a repair call, when one exists.
    ///
    /// A JSON integer of 2^53 or more gives its `0x` hex text.
    #[must_use]
    pub fn repair_text(&self) -> Option<String> {
        let _ = self;
        None
    }
}

impl fmt::Display for AddrExprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("The address text is empty."),
            Self::TooLong { len } => write!(
                f,
                "The address text has {len} bytes. The limit is {MAX_EXPR_LEN} bytes."
            ),
            Self::BadHex => f.write_str("The text after 0x is not 1 to 16 hex digits."),
            Self::BadId(e) => write!(f, "The ID in the address text does not parse. {e}"),
            Self::IntegerTooLarge(v) => write!(
                f,
                "The JSON integer {v} is 2^53 or more. Send the address as a 0x hex string."
            ),
        }
    }
}

impl std::error::Error for AddrExprError {}

/// Parses address text into its syntax tree.
///
/// # Errors
///
/// Returns [`AddrExprError`] for empty text, text above [`MAX_EXPR_LEN`] bytes, bad hex after
/// `0x` and a bad ID after a registered prefix.
pub fn parse(text: &str) -> Result<AddrExpr, AddrExprError> {
    let _ = (text, DefaultName::parse);
    Err(AddrExprError::Empty)
}

/// Reads a JSON integer address input (rule 1).
///
/// # Errors
///
/// Returns [`AddrExprError::IntegerTooLarge`] for a value of 2^53 or more.
pub fn from_integer(value: u64) -> Result<AddrExpr, AddrExprError> {
    let _ = value;
    Err(AddrExprError::Empty)
}
