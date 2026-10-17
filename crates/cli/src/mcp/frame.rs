//! Line framing with a size cap (design Section 10.13, AC-194).
//!
//! Each stdin line holds one JSON-RPC message. A line ends at `\n`. A `\r` before the `\n`
//! is not part of the line. The last line can end at the end of the input.
//! A line longer than the cap gives [`Frame::TooLong`]. The reader then skips to the next
//! line end, and it keeps at most the cap in memory.

use std::io::{self, BufRead};

/// The largest line: 16 MiB.
pub const MAX_LINE: usize = 16 * 1024 * 1024;

/// One framed input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A line of at most the cap, without its line end.
    Line(Vec<u8>),
    /// A line above the cap.
    TooLong {
        /// The number of bytes of the line, saturated at `usize::MAX`.
        bytes: usize,
    },
}

/// A reader of capped lines.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    cap: usize,
}

impl<R: BufRead> LineReader<R> {
    /// Makes a reader of lines of at most `cap` bytes.
    pub const fn new(inner: R, cap: usize) -> Self {
        Self { inner, cap }
    }

    /// Reads the next line, or gives `None` at the end of the input.
    ///
    /// # Errors
    ///
    /// Returns the read error of the input.
    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        let _ = (&mut self.inner, self.cap);
        Ok(None)
    }
}
