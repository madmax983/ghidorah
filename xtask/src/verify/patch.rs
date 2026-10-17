//! Negative patches: one unified-diff hunk against one kernel file (ADR-0011).
//!
//! `xtask verify` applies each patch to a copy of the kernel. The copy must fail verification.
//! The hunk must match the current source exactly once. So a stale patch fails with an error.

use std::fmt;

/// One parsed patch: one file and one hunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The path of the changed file, relative to the workspace root.
    pub path: String,
    /// The lines of the hunk before the change: context lines and removed lines.
    pub old: Vec<String>,
    /// The lines of the hunk after the change: context lines and added lines.
    pub new: Vec<String>,
}

/// The cause of a patch failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The patch has no `+++ b/<path>` line.
    NoFile,
    /// The patch has more than one file, or not exactly one hunk.
    NotOneHunk,
    /// A hunk line has a bad form, or the line counts differ from the hunk header.
    BadHunk(String),
    /// The old lines of the hunk do not occur in the source.
    Stale,
    /// The old lines of the hunk occur more than one time in the source.
    Ambiguous,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFile => f.write_str("the patch names no file"),
            Self::NotOneHunk => {
                f.write_str("the patch does not have exactly one file and one hunk")
            }
            Self::BadHunk(line) => write!(f, "the hunk has a bad line: {line}"),
            Self::Stale => f.write_str("the hunk does not match the current source"),
            Self::Ambiguous => f.write_str("the hunk matches the source more than one time"),
        }
    }
}

impl std::error::Error for PatchError {}

/// The maximum count of hunk lines. A negative patch changes a few lines only.
const MAX_HUNK_LINES: usize = 4096;

/// One hunk while the parser reads it.
#[derive(Debug, Default)]
struct Hunk {
    old: Vec<String>,
    new: Vec<String>,
    old_left: usize,
    new_left: usize,
}

/// Reads the line count of one side of a hunk header, for example `-12,5` gives 5.
fn side_count(field: &str, sign: char) -> Option<usize> {
    let range = field.strip_prefix(sign)?;
    match range.split_once(',') {
        Some((start, count)) => {
            start.parse::<usize>().ok()?;
            count.parse().ok()
        }
        None => range.parse::<usize>().ok().map(|_| 1),
    }
}

/// Reads a hunk header such as `@@ -1,4 +1,5 @@ fn a()`.
fn header(line: &str) -> Result<Hunk, PatchError> {
    let bad = || PatchError::BadHunk(line.to_owned());
    let mut fields = line.split_whitespace().skip(1);
    let old_left = fields
        .next()
        .and_then(|f| side_count(f, '-'))
        .ok_or_else(bad)?;
    let new_left = fields
        .next()
        .and_then(|f| side_count(f, '+'))
        .ok_or_else(bad)?;
    if fields.next() != Some("@@") || old_left.max(new_left) > MAX_HUNK_LINES {
        return Err(bad());
    }
    Ok(Hunk {
        old_left,
        new_left,
        ..Hunk::default()
    })
}

/// Adds one body line to the open hunk.
fn body_line(hunk: &mut Hunk, line: &str) -> Result<(), PatchError> {
    let bad = || PatchError::BadHunk(line.to_owned());
    let (kind, text) = line.split_at_checked(1).unwrap_or((" ", ""));
    let to_old = matches!(kind, " " | "-");
    let to_new = matches!(kind, " " | "+");
    if !to_old && !to_new {
        return Err(bad());
    }
    if to_old {
        hunk.old_left = hunk.old_left.checked_sub(1).ok_or_else(bad)?;
        hunk.old.push(text.to_owned());
    }
    if to_new {
        hunk.new_left = hunk.new_left.checked_sub(1).ok_or_else(bad)?;
        hunk.new.push(text.to_owned());
    }
    Ok(())
}

/// Tells if `line` is a file header line or a "no newline" mark.
fn is_header(line: &str) -> bool {
    ["diff ", "index ", "--- ", "\\"]
        .iter()
        .any(|p| line.starts_with(p))
}

/// Parses a unified diff with one file and one hunk.
///
/// # Errors
///
/// Gives a [`PatchError`] when the text is not one file with one valid hunk.
pub fn parse(text: &str) -> Result<Patch, PatchError> {
    let mut path: Option<String> = None;
    let mut hunks: Vec<Hunk> = Vec::new();
    for line in text.lines() {
        if let Some(open) = hunks
            .last_mut()
            .filter(|h| h.old_left > 0 || h.new_left > 0)
        {
            if !line.starts_with('\\') {
                body_line(open, line)?;
            }
        } else if let Some(name) = line.strip_prefix("+++ ") {
            if path.is_some() {
                return Err(PatchError::NotOneHunk);
            }
            let name = name.split('\t').next().unwrap_or(name);
            path = Some(name.strip_prefix("b/").unwrap_or(name).to_owned());
        } else if line.starts_with("@@ ") {
            hunks.push(header(line)?);
        } else if hunks.is_empty() || is_header(line) {
            // A preamble line, a file header line or a "no newline" mark.
        } else {
            return Err(PatchError::BadHunk(line.to_owned()));
        }
    }
    let path = path.ok_or(PatchError::NoFile)?;
    let [hunk] = <[Hunk; 1]>::try_from(hunks).map_err(|_| PatchError::NotOneHunk)?;
    if hunk.old_left > 0 || hunk.new_left > 0 {
        return Err(PatchError::BadHunk("the hunk ends early".to_owned()));
    }
    Ok(Patch {
        path,
        old: hunk.old,
        new: hunk.new,
    })
}

/// Applies `patch` to `source` and gives the changed text.
///
/// # Errors
///
/// Gives [`PatchError::Stale`] or [`PatchError::Ambiguous`] when the old lines do not match one place.
pub fn apply(source: &str, patch: &Patch) -> Result<String, PatchError> {
    let lines: Vec<&str> = source.lines().collect();
    let width = patch.old.len();
    let mut found = (0..=lines.len().saturating_sub(width)).filter(|&at| {
        lines
            .get(at..at + width)
            .is_some_and(|run| run.iter().zip(&patch.old).all(|(a, b)| *a == b))
    });
    let at = found.next().ok_or(PatchError::Stale)?;
    if found.next().is_some() {
        return Err(PatchError::Ambiguous);
    }
    let mut out: Vec<&str> = lines.get(..at).unwrap_or_default().to_vec();
    out.extend(patch.new.iter().map(String::as_str));
    out.extend(lines.get(at + width..).unwrap_or_default());
    let mut text = out.join("\n");
    if source.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}
