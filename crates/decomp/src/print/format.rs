//! The argument classes of a `printf` format string (C11 7.21.6.1, with the glibc flags).
//!
//! [`classes`] gives one class for each argument that the conversions of a format read, in
//! order:
//!
//! | Part | Class |
//! |---|---|
//! | `*` as the width or the precision | integer |
//! | `d i o u x X c s p n` and `C S` | integer |
//! | `f F e E g G a A` | floating |
//! | `%%` and `m` | no argument |
//!
//! These forms give `None`, because the register order does not tell their place:
//!
//! - a positional argument (`%1$d`),
//! - `L`, `q` or `ll` with a floating conversion: glibc reads a `long double`, which goes on
//!   the stack,
//! - a length other than `h`, `hh`, `l`, `ll`, `L`, `q`, `j`, `z`, `Z` and `t`,
//! - an unknown conversion, or a format that ends inside a conversion (`%5`),
//! - more than [`MAX_CONVERSIONS`] arguments or more than [`MAX_FORMAT`] bytes.

#[cfg(test)]
mod tests;

/// The largest format string in bytes that [`classes`] reads.
pub(crate) const MAX_FORMAT: usize = 4_096;

/// The largest number of arguments of one format.
pub(crate) const MAX_CONVERSIONS: usize = 64;

/// The class of one argument of a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// An integer or a pointer in an integer register.
    Int,
    /// A `double` in a floating register.
    Float,
}

/// The flag characters of a conversion.
const FLAGS: &[u8] = b"-+ #0'I";

/// The length modifier characters of a conversion.
const LENGTHS: &[u8] = b"hlqLjzZt";

/// The length modifiers that glibc takes.
const LENGTH_FORMS: [&[u8]; 11] = [
    b"", b"h", b"hh", b"l", b"ll", b"L", b"q", b"j", b"z", b"Z", b"t",
];

/// The length modifiers that make a floating conversion read a `long double`.
const LONG_DOUBLE: [&[u8]; 3] = [b"L", b"q", b"ll"];

/// Gives the argument classes of the format `fmt` in order (see the module doc).
pub(crate) fn classes(fmt: &[u8]) -> Option<Vec<Class>> {
    if fmt.len() > MAX_FORMAT {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = fmt;
    // Each pass takes at least one byte from `rest`, so the loop ends.
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'%' {
            continue;
        }
        rest = conversion(rest, &mut out)?;
        if out.len() > MAX_CONVERSIONS {
            return None;
        }
    }
    Some(out)
}

/// Reads one conversion after its `%` from `rest` and adds its classes to `out`. Gives the
/// bytes after the conversion, or `None` for a form of the module doc.
fn conversion<'a>(mut rest: &'a [u8], out: &mut Vec<Class>) -> Option<&'a [u8]> {
    if let Some(tail) = rest.strip_prefix(b"%") {
        return Some(tail);
    }
    rest = skip(rest, |b| b.is_ascii_digit());
    if rest.first() == Some(&b'$') {
        return None;
    }
    rest = skip(rest, |b| FLAGS.contains(&b));
    rest = field(rest, out);
    if let Some(tail) = rest.strip_prefix(b".") {
        rest = field(tail, out);
    }
    let after = skip(rest, |b| LENGTHS.contains(&b));
    let length = rest.get(..rest.len().saturating_sub(after.len()))?;
    if !LENGTH_FORMS.contains(&length) {
        return None;
    }
    let long_double = LONG_DOUBLE.contains(&length);
    let (&conv, tail) = after.split_first()?;
    match conv {
        b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'c' | b's' | b'p' | b'n' | b'C' | b'S' => {
            out.push(Class::Int);
        }
        b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' if !long_double => {
            out.push(Class::Float);
        }
        b'm' => {}
        _ => return None,
    }
    Some(tail)
}

/// Reads a width or a precision: digits, or `*` with one integer argument.
fn field<'a>(rest: &'a [u8], out: &mut Vec<Class>) -> &'a [u8] {
    if let Some(tail) = rest.strip_prefix(b"*") {
        out.push(Class::Int);
        return tail;
    }
    skip(rest, |b| b.is_ascii_digit())
}

/// Gives `rest` without the bytes at its start for which `keep` is true.
fn skip(rest: &[u8], keep: impl Fn(u8) -> bool) -> &[u8] {
    let n = rest.iter().take_while(|b| keep(**b)).count();
    rest.get(n..).unwrap_or_default()
}
