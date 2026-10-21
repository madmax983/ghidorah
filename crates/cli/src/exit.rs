//! The exit codes of the command line (design Section 10.14).
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Success. A broken pipe on stdout also gives 0. |
//! | 1 | Tool error: an envelope with `ok: false`. |
//! | 2 | Usage or protocol error. |

/// The exit code of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exit {
    /// Code 0: success.
    Ok,
    /// Code 1: a tool error.
    ToolError,
    /// Code 2: a usage or protocol error.
    Usage,
}

impl Exit {
    /// Gives the process exit code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::ToolError => 1,
            Self::Usage => 2,
        }
    }

    /// Gives the exit code of an envelope: 0 for `ok: true`, else 1.
    #[must_use]
    pub const fn of_ok(ok: bool) -> Self {
        if ok { Self::Ok } else { Self::ToolError }
    }

    /// Gives the more severe of two exit codes.
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}
