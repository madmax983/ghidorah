//! Writes to stdout with the broken-pipe rule (design Section 10.14).
//!
//! A broken pipe on stdout ends the command with exit code 0. Another write error ends it
//! with exit code 2. [`Stop`] carries the reason to the command.

use std::io::{self, Write};

use crate::exit::Exit;

/// The reason that a command stops its output.
#[derive(Debug)]
pub enum Stop {
    /// The reader of stdout closed the pipe.
    BrokenPipe,
    /// Another write error.
    Io(io::Error),
}

impl Stop {
    /// Gives the stop reason of a write error.
    #[must_use]
    pub fn of(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::Io(error)
        }
    }

    /// Gives the exit code: 0 for a broken pipe, else 2.
    #[must_use]
    pub const fn exit(&self) -> Exit {
        match self {
            Self::BrokenPipe => Exit::Ok,
            Self::Io(_) => Exit::Usage,
        }
    }
}

/// Writes `text` and one line end to `out`, then flushes `out`.
///
/// # Errors
///
/// Returns [`Stop`] when the write or the flush fails.
pub fn line(out: &mut dyn Write, text: &str) -> Result<(), Stop> {
    out.write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(Stop::of)
}

/// Writes one log line to `err`. A failed write changes nothing.
pub fn log(err: &mut dyn Write, text: &str) {
    let _ = writeln!(err, "ghidorah: {text}");
    let _ = err.flush();
}
