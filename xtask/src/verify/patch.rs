//! Negative patches: one or two unified-diff hunks against one kernel file (ADR-0011).
//!
//! `xtask verify` applies each patch to a copy of the kernel. The copy must fail verification.
//! Each hunk must match the current source exactly once. So a stale patch fails with an error.
//! A patch can have two hunks. For example, a K5 patch changes a spec table and its exec copy.

use std::fmt;

/// The maximum count of hunks in one patch.
pub const MAX_HUNKS: usize = 2;

/// One hunk of a patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    /// The lines of the hunk before the change: context lines and removed lines.
    pub old: Vec<String>,
    /// The lines of the hunk after the change: context lines and added lines.
    pub new: Vec<String>,
}

/// One parsed patch: one file and its hunks in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The path of the changed file, relative to the workspace root.
    pub path: String,
    /// The hunks, from 1 to [`MAX_HUNKS`].
    pub hunks: Vec<Hunk>,
}

/// The cause of a patch failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The patch has no `+++ b/<path>` line.
    NoFile,
    /// The patch changes more than one file.
    TwoFiles,
    /// The patch has no hunk, or more than [`MAX_HUNKS`] hunks.
    HunkCount,
    /// A hunk line has a bad form, or the line counts differ from the hunk header.
    BadHunk(String),
    /// The old lines of a hunk do not occur in the source.
    Stale,
    /// The old lines of a hunk occur more than one time in the source.
    Ambiguous,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFile => f.write_str("the patch names no file"),
            Self::TwoFiles => f.write_str("the patch changes more than one file"),
            Self::HunkCount => write!(f, "the patch does not have 1 to {MAX_HUNKS} hunks"),
            Self::BadHunk(line) => write!(f, "the hunk has a bad line: {line}"),
            Self::Stale => f.write_str("a hunk does not match the current source"),
            Self::Ambiguous => f.write_str("a hunk matches the source more than one time"),
        }
    }
}

impl std::error::Error for PatchError {}

/// The maximum count of hunk lines. A negative patch changes a few lines only.
const MAX_HUNK_LINES: usize = 4096;

/// One hunk while the parser reads it.
#[derive(Debug, Default)]
struct Open {
    old: Vec<String>,
    new: Vec<String>,
    old_left: usize,
    new_left: usize,
}

impl Open {
    /// Tells if the hunk needs more body lines.
    const fn is_open(&self) -> bool {
        self.old_left > 0 || self.new_left > 0
    }
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
fn header(line: &str) -> Result<Open, PatchError> {
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
    Ok(Open {
        old_left,
        new_left,
        ..Open::default()
    })
}

/// Adds one body line to the open hunk.
fn body_line(hunk: &mut Open, line: &str) -> Result<(), PatchError> {
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

/// Parses a unified diff with one file and 1 to [`MAX_HUNKS`] hunks.
///
/// # Errors
///
/// Gives a [`PatchError`] when the text is not one file with 1 to [`MAX_HUNKS`] valid hunks.
pub fn parse(text: &str) -> Result<Patch, PatchError> {
    let mut path: Option<String> = None;
    let mut hunks: Vec<Open> = Vec::new();
    for line in text.lines() {
        if let Some(open) = hunks.last_mut().filter(|h| h.is_open()) {
            if !line.starts_with('\\') {
                body_line(open, line)?;
            }
        } else if let Some(name) = line.strip_prefix("+++ ") {
            if path.is_some() {
                return Err(PatchError::TwoFiles);
            }
            let name = name.split('\t').next().unwrap_or(name);
            path = Some(name.strip_prefix("b/").unwrap_or(name).to_owned());
        } else if line.starts_with("@@ ") {
            if hunks.len() >= MAX_HUNKS {
                return Err(PatchError::HunkCount);
            }
            hunks.push(header(line)?);
        } else if hunks.is_empty() || is_header(line) {
            // A preamble line, a file header line or a "no newline" mark.
        } else {
            return Err(PatchError::BadHunk(line.to_owned()));
        }
    }
    let path = path.ok_or(PatchError::NoFile)?;
    if hunks.is_empty() {
        return Err(PatchError::HunkCount);
    }
    if hunks.iter().any(Open::is_open) {
        return Err(PatchError::BadHunk("the hunk ends early".to_owned()));
    }
    let hunks = hunks
        .into_iter()
        .map(|h| Hunk {
            old: h.old,
            new: h.new,
        })
        .collect();
    Ok(Patch { path, hunks })
}

/// Applies one hunk to the lines of a source.
fn apply_hunk<'a>(lines: &[&'a str], hunk: &'a Hunk) -> Result<Vec<&'a str>, PatchError> {
    let width = hunk.old.len();
    let mut found = (0..=lines.len().saturating_sub(width)).filter(|&at| {
        lines
            .get(at..at.saturating_add(width))
            .is_some_and(|run| run.iter().zip(&hunk.old).all(|(a, b)| *a == b))
    });
    let at = found.next().ok_or(PatchError::Stale)?;
    if found.next().is_some() {
        return Err(PatchError::Ambiguous);
    }
    let mut out: Vec<&str> = lines.get(..at).unwrap_or_default().to_vec();
    out.extend(hunk.new.iter().map(String::as_str));
    out.extend(lines.get(at.saturating_add(width)..).unwrap_or_default());
    Ok(out)
}

/// Applies the hunks of `patch` to `source` in order and gives the changed text.
///
/// # Errors
///
/// Gives [`PatchError::Stale`] or [`PatchError::Ambiguous`] when the old lines of a hunk do not
/// match one place.
pub fn apply(source: &str, patch: &Patch) -> Result<String, PatchError> {
    let mut lines: Vec<&str> = source.lines().collect();
    for hunk in &patch.hunks {
        lines = apply_hunk(&lines, hunk)?;
    }
    let mut text = lines.join("\n");
    if source.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}
