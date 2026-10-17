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
        let mut line = Vec::new();
        let mut bytes: usize = 0;
        let mut last = None;
        let mut started = false;
        // A line keeps one byte more than the cap, so a `\r` before the line end fits.
        let keep = self.cap.saturating_add(1);
        loop {
            let buf = match self.inner.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if buf.is_empty() {
                return Ok(started.then(|| self.finish(line, bytes, last)));
            }
            started = true;
            let end = buf.iter().position(|&b| b == b'\n');
            let part = end.map_or(buf, |i| buf.get(..i).unwrap_or_default());
            bytes = bytes.saturating_add(part.len());
            last = part.last().copied().or(last);
            if bytes <= keep {
                line.extend_from_slice(part);
            }
            let used = end.map_or(buf.len(), |i| i.saturating_add(1));
            self.inner.consume(used);
            if end.is_some() {
                return Ok(Some(self.finish(line, bytes, last)));
            }
        }
    }

    /// Gives the frame of a whole line of `bytes` bytes that ends with `last`.
    ///
    /// A `\r` at the end does not count.
    fn finish(&self, mut line: Vec<u8>, bytes: usize, last: Option<u8>) -> Frame {
        let cr = last == Some(b'\r');
        let bytes = if cr { bytes.saturating_sub(1) } else { bytes };
        if bytes > self.cap {
            return Frame::TooLong { bytes };
        }
        if cr {
            let _ = line.pop();
        }
        Frame::Line(line)
    }
}
