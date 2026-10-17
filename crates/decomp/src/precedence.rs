//! C operator precedence with the numbers of Ghidra (design Section 8.3).
//!
//! The printer uses precedence climbing. A higher number binds tighter. A child expression
//! gets parentheses when its number is lower than the number of its parent operator. The right
//! operand of a binary operator also gets parentheses when the numbers are equal. The binary
//! operators of C group from left to right.
//!
//! | Group | Operators | Number |
//! |---|---|---|
//! | atom | names, constants, string literals | 70 |
//! | postfix | call, `->` | 66 |
//! | prefix | `-`, `~`, `!`, `*`, cast | 62 |
//! | multiplicative | `*`, `/`, `%` | 54 |
//! | additive | `+`, `-` | 50 |
//! | shift | `<<`, `>>` | 46 |
//! | relational | `<`, `<=`, `>`, `>=` | 42 |
//! | equality | `==`, `!=` | 38 |
//! | bitwise and | `&` | 34 |
//! | bitwise xor | `^` | 30 |
//! | bitwise or | `\|` | 26 |
//! | logical and | `&&` | 22 |
//! | logical or | `\|\|` | 18 |
//! | conditional | `?:` | 16 |
//! | assignment | `=` | 14 |
//! | comma | `,` | 2 |

use ghidorah_ir::Opc;

/// The number of a name, a constant or a string literal.
pub const ATOM: u8 = 70;
/// The number of a call and of `->`.
pub const POSTFIX: u8 = 66;
/// The number of a prefix operator and of a cast.
pub const UNARY: u8 = 62;
/// The number of `*`, `/` and `%`.
pub const MUL: u8 = 54;
/// The number of `+` and `-`.
pub const ADD: u8 = 50;
/// The number of `<<` and `>>`.
pub const SHIFT: u8 = 46;
/// The number of `<`, `<=`, `>` and `>=`.
pub const REL: u8 = 42;
/// The number of `==` and `!=`.
pub const EQ: u8 = 38;
/// The number of `&`.
pub const BIT_AND: u8 = 34;
/// The number of `^`.
pub const BIT_XOR: u8 = 30;
/// The number of `|`.
pub const BIT_OR: u8 = 26;
/// The number of `&&`.
pub const LOG_AND: u8 = 22;
/// The number of `||`.
pub const LOG_OR: u8 = 18;
/// The number of `?:`.
pub const TERNARY: u8 = 16;
/// The number of `=`.
pub const ASSIGN: u8 = 14;
/// The number of `,`.
pub const COMMA: u8 = 2;

/// A binary C operator of an L1 opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Binary {
    /// The operator text, for example `+`.
    pub text: &'static str,
    /// The precedence number.
    pub prec: u8,
    /// The operands are signed: the printer casts them to a signed type.
    pub signed: bool,
}

/// Gives a binary operator.
const fn op(text: &'static str, prec: u8, signed: bool) -> Option<Binary> {
    Some(Binary { text, prec, signed })
}

/// Gives the C operator of a binary L1 opcode. An opcode that prints as a call, for example
/// `Rol`, gives `None`.
#[must_use]
pub const fn binary(opc: Opc) -> Option<Binary> {
    match opc {
        Opc::Mul => op("*", MUL, false),
        Opc::UDiv => op("/", MUL, false),
        Opc::SDiv => op("/", MUL, true),
        Opc::URem => op("%", MUL, false),
        Opc::SRem => op("%", MUL, true),
        Opc::Add => op("+", ADD, false),
        Opc::Sub => op("-", ADD, false),
        Opc::Shl => op("<<", SHIFT, false),
        Opc::LShr => op(">>", SHIFT, false),
        Opc::AShr => op(">>", SHIFT, true),
        Opc::ULt => op("<", REL, false),
        Opc::ULe => op("<=", REL, false),
        Opc::SLt => op("<", REL, true),
        Opc::SLe => op("<=", REL, true),
        Opc::Eq => op("==", EQ, false),
        Opc::Ne => op("!=", EQ, false),
        Opc::And => op("&", BIT_AND, false),
        Opc::Xor => op("^", BIT_XOR, false),
        Opc::Or => op("|", BIT_OR, false),
        _ => None,
    }
}

/// Gives the operator text of the negation of the compare `op`: `ULt` gives `>=`. Another
/// opcode gives `None`.
#[must_use]
pub const fn negated(op: Opc) -> Option<&'static str> {
    match op {
        Opc::Eq => Some("!="),
        Opc::Ne => Some("=="),
        Opc::ULt | Opc::SLt => Some(">="),
        Opc::ULe | Opc::SLe => Some(">"),
        _ => None,
    }
}

/// Tells if a child with the number `child` needs parentheses under an operator with the
/// number `parent`. `right` is true for the right operand of a binary operator and for the
/// operand of a prefix operator.
#[must_use]
pub const fn parens(child: u8, parent: u8, right: bool) -> bool {
    child < parent || (right && child == parent)
}
