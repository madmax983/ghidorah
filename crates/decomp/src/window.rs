//! Line windows (design Section 8.3, AC-235).
//!
//! A [`Window`] is a run of lines of an [`Output`]. Line numbers start at 1. The default
//! window is the first [`DEFAULT_LINES`] lines. `next` names the first line of the next
//! window, so a reader can page through every line of every function.
//!
//! A window that holds only part of the lines also holds only part of the elided ranges and
//! the variables:
//!
//! | Member | Rows of the window |
//! |---|---|
//! | elided ranges | each range of a line of the window: the line with the highest start address at or below the range |
//! | variables | each variable that the text of the window names |
//!
//! So each elided range is in exactly one window. A window with every line holds every row.

use std::collections::BTreeSet;

use crate::linemap::{self, LineRow};
use crate::print::{CallRow, Line, VarRow};
use crate::{Elided, Output};

/// The default number of lines of a window.
pub const DEFAULT_LINES: usize = 150;

/// The largest number of lines of a window.
pub const MAX_LINES: usize = 1_000;

/// A window of lines.
#[derive(Debug, Clone, Copy)]
pub struct Window<'a> {
    /// The output.
    pub output: &'a Output,
    /// The number of the first line, from 1.
    pub start: usize,
    /// The number of lines.
    pub count: usize,
}

impl<'a> Window<'a> {
    /// Gives the window of `count` lines from the line `start`. The window ends at the last
    /// line. A start past the last line gives an empty window.
    #[must_use]
    pub fn new(output: &'a Output, start: usize, count: usize) -> Self {
        let start = start.max(1);
        let left = output.lines.len().saturating_sub(start.saturating_sub(1));
        Self {
            output,
            start,
            count: count.min(left),
        }
    }

    /// Gives the number of lines of the output.
    #[must_use]
    pub fn total(&self) -> usize {
        self.output.lines.len()
    }

    /// Tells if the window holds every line of the output.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.start == 1 && self.count == self.total()
    }

    /// Gives the elided ranges of the window in address order (see the module table).
    #[must_use]
    pub fn elided(&self) -> Vec<&'a Elided> {
        let all = &self.output.elided;
        if self.is_whole() {
            return all.iter().collect();
        }
        let mut starts: Vec<(u64, usize)> = self
            .output
            .lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| l.span.map(|(s, _)| (s, i)))
            .collect();
        starts.sort_unstable();
        let first = self.start.saturating_sub(1);
        let lines = first..first.saturating_add(self.count);
        all.iter()
            .filter(|e| {
                let k = starts.partition_point(|(s, _)| *s <= e.start);
                let owner = k
                    .checked_sub(1)
                    .and_then(|i| starts.get(i))
                    .or_else(|| starts.first())
                    .map_or(0, |x| x.1);
                lines.contains(&owner)
            })
            .collect()
    }

    /// Gives the variables that the text of the window names, in output order. A window with
    /// every line gives every variable.
    #[must_use]
    pub fn vars(&self) -> Vec<&'a VarRow> {
        let all = &self.output.vars;
        if self.is_whole() {
            return all.iter().collect();
        }
        let words: BTreeSet<&str> = self
            .lines()
            .iter()
            .flat_map(|l| {
                l.text
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            })
            .filter(|w| !w.is_empty())
            .collect();
        all.iter()
            .filter(|v| words.contains(v.name.as_str()))
            .collect()
    }

    /// Gives the lines of the window.
    #[must_use]
    pub fn lines(&self) -> &'a [Line] {
        let first = self.start.saturating_sub(1);
        self.output
            .lines
            .get(first..first.saturating_add(self.count))
            .unwrap_or_default()
    }

    /// Gives the text of the window: the lines with a newline after each one.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for line in self.lines() {
            out.push_str(&line.text);
            out.push('\n');
        }
        out
    }

    /// Gives the number of the first line after the window, or `None` at the end.
    #[must_use]
    pub fn next(&self) -> Option<usize> {
        let next = self.start.saturating_add(self.count);
        (self.count > 0 && next <= self.total()).then_some(next)
    }

    /// Gives the line map rows of the window.
    #[must_use]
    pub fn rows(&self) -> Vec<LineRow> {
        linemap::rows(self.start, self.lines())
    }

    /// Gives the calls of the window with their line numbers.
    #[must_use]
    pub fn calls(&self) -> Vec<(usize, &'a CallRow)> {
        self.numbered()
            .flat_map(|(n, l)| l.calls.iter().map(move |c| (n, c)))
            .collect()
    }

    /// Gives the string literals of the window with their line numbers.
    #[must_use]
    pub fn strings(&self) -> Vec<(usize, u64)> {
        self.numbered()
            .flat_map(|(n, l)| l.strings.iter().map(move |s| (n, *s)))
            .collect()
    }

    /// Gives the lines of the window with their numbers.
    fn numbered(&self) -> impl Iterator<Item = (usize, &'a Line)> + 'a {
        let start = self.start;
        self.lines()
            .iter()
            .enumerate()
            .map(move |(i, l)| (start.saturating_add(i), l))
    }
}
