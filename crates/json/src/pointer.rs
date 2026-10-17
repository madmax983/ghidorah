//! The one pointer dialect of ghidorah: RFC 6901 plus a `*` segment.
//!
//! Batch references, `fields`, `expect` pointers, CLI `--select` and eval answer pointers
//! all use this module (design Section 11.2).
//!
//! - [`parse`] reads the text. `""` is the whole value. Each other pointer starts with `/`.
//!   In a segment, `~0` is `~` and `~1` is `/`. A segment of only `*` is [`Segment::Star`].
//! - [`get`] is plain RFC 6901: it gives one value, and `*` is the member name `*`.
//! - [`select`] maps each `*` over every item of an array, so it gives a list.
//!   On an object, `*` is the member name `*`, as in RFC 6901.
//!
//! An array index is `0` or a decimal number without a leading zero. The index `-` names
//! the item after the last item, so it never gives a value.

use std::fmt;
use std::str::FromStr;

use crate::value::Value;
use crate::write::push_segment;

/// One segment of a pointer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Segment {
    /// A member name or an array index, with the `~0` and `~1` escapes resolved.
    Key(String),
    /// The `*` segment.
    Star,
}

impl Segment {
    /// Gives the RFC 6901 token text of the segment, without escapes. `Star` gives `*`.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            Self::Key(key) => key,
            Self::Star => "*",
        }
    }
}

/// A parsed pointer: a list of segments. No segments means the whole value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Pointer {
    segments: Vec<Segment>,
}

impl Pointer {
    /// Makes the pointer of the whole value.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Makes a pointer from segments.
    #[must_use]
    pub const fn from_segments(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    /// Gives the segments in order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Tells if the pointer has a [`Segment::Star`], so [`select`] can give more than one value.
    #[must_use]
    pub fn has_star(&self) -> bool {
        self.segments.contains(&Segment::Star)
    }

    /// Adds `segment` at the end.
    pub fn push(&mut self, segment: Segment) {
        self.segments.push(segment);
    }
}

/// Writes the RFC 6901 text: `/` before each segment, with `~` as `~0` and `/` as `~1`.
///
/// The text of a parsed pointer parses back as the same pointer.
/// A `Key("*")` writes as `/*`, so it parses back as [`Segment::Star`].
impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = String::new();
        for segment in &self.segments {
            push_segment(&mut text, segment.token());
        }
        f.write_str(&text)
    }
}

impl FromStr for Pointer {
    type Err = PointerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// A pointer text that does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PointerError {
    /// The text is not empty, and it does not start with `/`.
    NoLeadingSlash,
    /// A `~` has no `0` or `1` after it. The offset is the byte offset of the `~`.
    BadEscape {
        /// The byte offset of the `~` in the pointer text.
        offset: usize,
    },
}

impl PointerError {
    /// Gives the stable text form: `E_POINTER_SLASH` or `E_POINTER_ESCAPE`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoLeadingSlash => "E_POINTER_SLASH",
            Self::BadEscape { .. } => "E_POINTER_ESCAPE",
        }
    }
}

impl fmt::Display for PointerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLeadingSlash => write!(
                f,
                "{}: a pointer that is not empty starts with '/'",
                self.code()
            ),
            Self::BadEscape { offset } => write!(
                f,
                "{} at byte {offset}: '~' must come before '0' or '1'",
                self.code()
            ),
        }
    }
}

impl std::error::Error for PointerError {}

/// Parses a pointer text.
///
/// # Errors
///
/// Returns [`PointerError::NoLeadingSlash`] for a text that is not empty and has no leading `/`.
/// Returns [`PointerError::BadEscape`] for a `~` that does not come before `0` or `1`.
pub fn parse(text: &str) -> Result<Pointer, PointerError> {
    if text.is_empty() {
        return Ok(Pointer::root());
    }
    let rest = text.strip_prefix('/').ok_or(PointerError::NoLeadingSlash)?;
    let mut segments = Vec::new();
    let mut offset = 1usize;
    for token in rest.split('/') {
        segments.push(segment(token, offset)?);
        offset = offset.saturating_add(token.len()).saturating_add(1);
    }
    Ok(Pointer { segments })
}

/// Reads one token that starts at the byte offset `base` of the pointer text.
fn segment(token: &str, base: usize) -> Result<Segment, PointerError> {
    if token == "*" {
        return Ok(Segment::Star);
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some((_, '0')) => out.push('~'),
                Some((_, '1')) => out.push('/'),
                _ => {
                    return Err(PointerError::BadEscape {
                        offset: base.saturating_add(i),
                    });
                }
            }
        } else {
            out.push(c);
        }
    }
    Ok(Segment::Key(out))
}

/// Gives the array index of `token`: `0`, or digits without a leading zero.
fn index(token: &str) -> Option<usize> {
    match token.as_bytes() {
        [b'0'] => Some(0),
        [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => token.parse().ok(),
        _ => None,
    }
}

/// Gives the child of `value` that `token` names, with the rules of RFC 6901.
fn step<'a>(value: &'a Value, token: &str) -> Option<&'a Value> {
    match value {
        Value::Object(object) => object.get(token),
        Value::Array(items) => items.get(index(token)?),
        _ => None,
    }
}

/// Gives the value at `pointer` with the rules of RFC 6901, or `None` when the path is missing.
///
/// A [`Segment::Star`] is the member name `*` here. Use [`select`] for the map form.
#[must_use]
pub fn get<'a>(root: &'a Value, pointer: &Pointer) -> Option<&'a Value> {
    pointer
        .segments
        .iter()
        .try_fold(root, |value, segment| step(value, segment.token()))
}

/// The result of [`select`]: the values found and the count of missing paths.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selection<'a> {
    /// The values, in document order.
    pub values: Vec<&'a Value>,
    /// The number of paths that end before the last segment.
    pub missing: usize,
    /// The concrete pointer of the first missing path in document order, for example `/items/2/id`.
    pub first_missing: Option<String>,
}

impl Selection<'_> {
    /// Tells if no path is missing.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.missing == 0
    }
}

/// Gives every value at `pointer`, with each `*` mapped over the items of an array.
///
/// A `*` over an empty array gives no values and no missing path.
/// A path that ends early counts in [`Selection::missing`]. The values keep document order.
/// The function uses no recursion.
#[must_use]
pub fn select<'a>(root: &'a Value, pointer: &Pointer) -> Selection<'a> {
    let segments = pointer.segments();
    let mut selection = Selection::default();
    // Each path step records its parent step, so a missing path can name its location.
    let mut steps: Vec<(Option<usize>, Step<'_>)> = Vec::new();
    // Depth-first walk in document order: (value, index of the next segment, path step).
    let mut stack: Vec<(&'a Value, usize, Option<usize>)> = vec![(root, 0, None)];
    while let Some((value, depth, node)) = stack.pop() {
        let Some(segment) = segments.get(depth) else {
            selection.values.push(value);
            continue;
        };
        let next = depth.saturating_add(1);
        if let (Segment::Star, Value::Array(items)) = (segment, value) {
            for (i, item) in items.iter().enumerate().rev() {
                stack.push((item, next, Some(steps.len())));
                steps.push((node, Step::Index(i)));
            }
            continue;
        }
        if let Some(child) = step(value, segment.token()) {
            stack.push((child, next, Some(steps.len())));
            steps.push((node, Step::Token(segment.token())));
        } else {
            selection.missing = selection.missing.saturating_add(1);
            if selection.first_missing.is_none() {
                selection.first_missing = Some(path_text(&steps, node, segment.token()));
            }
        }
    }
    selection
}

/// One step of a concrete path.
#[derive(Debug, Clone, Copy)]
enum Step<'p> {
    /// A member name or an index text of the pointer.
    Token(&'p str),
    /// An array index that a `*` segment gave.
    Index(usize),
}

/// Gives the pointer text of the path that ends at `node`, plus the token `last`.
fn path_text(steps: &[(Option<usize>, Step<'_>)], node: Option<usize>, last: &str) -> String {
    let mut tokens = Vec::new();
    let mut current = node;
    // A parent step comes before its child step, so this walk ends after at most `steps.len()` steps.
    while let Some(id) = current {
        let Some((parent, step)) = steps.get(id) else {
            break;
        };
        tokens.push(match step {
            Step::Token(token) => (*token).to_owned(),
            Step::Index(i) => i.to_string(),
        });
        current = parent.filter(|p| *p < id);
    }
    let mut text = String::new();
    for token in tokens.iter().rev() {
        push_segment(&mut text, token);
    }
    push_segment(&mut text, last);
    text
}
