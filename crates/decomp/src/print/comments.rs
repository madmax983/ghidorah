//! The comments in the text (design Section 8.3, AC-237).
//!
//! | Kind | Place |
//! |---|---|
//! | PLATE at the entry | before the function line |
//! | PRE, and PLATE at another address | before the first line whose range holds the address |
//! | POST | after the last line whose range holds the address |
//! | EOL | at the end of the first line whose range holds the address |
//!
//! When no line holds the address, the comment goes before the first line that starts after
//! the address, else before the last line. An EOL comment then gets a line of its own. Each
//! comment line has the range of its address, so the line map gives it a row.

use ghidorah_base::{BinText, Caps};
use ghidorah_db::CommentKind;

use super::{Line, LineKind};
use crate::view::View;

/// The largest number of characters of one comment line.
pub const MAX_COMMENT: usize = 400;

/// Gives the safe text of one comment line: the escapes of `BinText`.
fn clean(text: &str) -> String {
    BinText::new(text.as_bytes())
        .render(Caps::new(MAX_COMMENT, 0))
        .text
}

/// Tells if the range of `line` holds `addr`. A range of 0 bytes holds its start. The last
/// address is inclusive, so a range at the top of the address space holds `u64::MAX`.
fn holds(line: &Line, addr: u64) -> bool {
    line.span.is_some_and(|(s, n)| {
        let last = s.saturating_add(n.saturating_sub(1));
        s <= addr && addr <= last
    })
}

/// The comment lines before and after each line.
struct Places {
    before: Vec<Vec<Line>>,
    after: Vec<Vec<Line>>,
}

/// Gives the index of the line that a comment at `addr` goes before when no line holds it.
fn fallback(lines: &[Line], addr: u64) -> usize {
    lines
        .iter()
        .position(|l| l.span.is_some_and(|(s, _)| s > addr))
        .unwrap_or_else(|| lines.len().saturating_sub(1))
}

/// Gives the depth of the comments at the line `i`: the depth of the line, at least 1.
fn depth_at(lines: &[Line], i: usize) -> u16 {
    lines.get(i).map_or(1, |l| l.depth.max(1))
}

/// Gives the comment lines of one comment text at the depth of the line `at`.
fn comment_lines(text: &str, kind: CommentKind, addr: u64, len: u64, depth: u16) -> Vec<Line> {
    text.lines()
        .map(|part| Line {
            text: format!("{}// {}", "    ".repeat(usize::from(depth)), clean(part)),
            kind: LineKind::Comment,
            depth,
            ops: Vec::new(),
            span: Some((addr, len)),
            comment: Some(kind),
            calls: Vec::new(),
            strings: Vec::new(),
        })
        .collect()
}

impl Places {
    /// Puts the comment lines of `text` before (or after) the line `at`.
    fn put(
        &mut self,
        lines: &[Line],
        at: usize,
        after: bool,
        c: (u64, CommentKind, &str),
        len: u64,
    ) {
        let (addr, kind, text) = c;
        let new = comment_lines(text, kind, addr, len, depth_at(lines, at));
        let side = if after {
            &mut self.after
        } else {
            &mut self.before
        };
        if let Some(slot) = side.get_mut(at) {
            slot.extend(new);
        }
    }
}

/// Puts the comments of `comments` into `lines`.
pub(super) fn insert(
    mut lines: Vec<Line>,
    comments: &[(u64, CommentKind, String)],
    view: &View,
) -> Vec<Line> {
    if lines.is_empty() {
        return lines;
    }
    let mut places = Places {
        before: vec![Vec::new(); lines.len()],
        after: vec![Vec::new(); lines.len()],
    };
    for (addr, kind, text) in comments {
        let (addr, kind) = (*addr, *kind);
        let len = view.insn_len(addr).map_or(1, u64::from);
        let first = lines.iter().position(|l| holds(l, addr));
        match kind {
            CommentKind::Plate if addr == view.entry => {
                if let Some(slot) = places.before.get_mut(0) {
                    slot.extend(comment_lines(text, kind, addr, len, 0));
                }
            }
            CommentKind::Plate | CommentKind::Pre => {
                let at = first.unwrap_or_else(|| fallback(&lines, addr));
                places.put(&lines, at, false, (addr, kind, text), len);
            }
            CommentKind::Post => {
                if let Some(at) = lines.iter().rposition(|l| holds(l, addr)) {
                    places.put(&lines, at, true, (addr, kind, text), len);
                } else {
                    let at = fallback(&lines, addr);
                    places.put(&lines, at, false, (addr, kind, text), len);
                }
            }
            CommentKind::Eol => {
                let joined: Vec<String> = text.lines().map(clean).collect();
                let joined = joined.join(" ");
                if let Some(line) = first.and_then(|i| lines.get_mut(i)) {
                    line.text.push_str(" // ");
                    line.text.push_str(&joined);
                    line.comment = Some(CommentKind::Eol);
                } else {
                    let at = fallback(&lines, addr);
                    places.put(&lines, at, false, (addr, kind, &joined), len);
                }
            }
            CommentKind::Repeatable => {}
        }
    }
    let mut out = Vec::with_capacity(lines.len());
    for ((line, before), after) in lines.into_iter().zip(places.before).zip(places.after) {
        out.extend(before);
        out.push(line);
        out.extend(after);
    }
    out
}
