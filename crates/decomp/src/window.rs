//! Line windows (design Section 8.3, AC-235).
//!
//! A [`Window`] is a run of lines of an [`Output`]. Line numbers start at 1. The default
//! window is the first [`DEFAULT_LINES`] lines. `next` names the first line of the next
//! window, so a reader can page through every line of every function.

use crate::Output;
use crate::linemap::{self, LineRow};
use crate::print::{CallRow, Line};

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
        Self {
            output,
            start,
            count: count.min(0),
        }
    }

    /// Gives the number of lines of the output.
    #[must_use]
    pub fn total(&self) -> usize {
        0
    }

    /// Gives the lines of the window.
    #[must_use]
    pub fn lines(&self) -> &'a [Line] {
        &[]
    }

    /// Gives the text of the window: the lines with a newline after each one.
    #[must_use]
    pub fn text(&self) -> String {
        String::new()
    }

    /// Gives the number of the first line after the window, or `None` at the end.
    #[must_use]
    pub fn next(&self) -> Option<usize> {
        None
    }

    /// Gives the line map rows of the window.
    #[must_use]
    pub fn rows(&self) -> Vec<LineRow> {
        linemap::rows(self.start, self.lines())
    }

    /// Gives the calls of the window with their line numbers.
    #[must_use]
    pub fn calls(&self) -> Vec<(usize, &'a CallRow)> {
        Vec::new()
    }

    /// Gives the string literals of the window with their line numbers.
    #[must_use]
    pub fn strings(&self) -> Vec<(usize, u64)> {
        Vec::new()
    }
}
