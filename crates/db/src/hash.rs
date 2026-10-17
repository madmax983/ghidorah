//! The state hash: the one equality of program state in tests (design Section 3.12).
//!
//! `state_hash = sha256(JCS(facts))`. The fact dump of [`crate::codec::facts`] holds the
//! binary identity, both fact layers, the notes and the number of types. It leaves out the
//! progress rows, the marks, the counters of new IDs, the events and the epochs. The session
//! computes the hash on demand only, never on each commit.

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::sha256;
use ghidorah_json::{JcsError, write_jcs};

use crate::program::Program;

/// A SHA-256 state hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateHash(pub [u8; 32]);

impl fmt::Display for StateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Program {
    /// Gives the state hash: the SHA-256 of the JCS text of the fact dump.
    ///
    /// # Errors
    ///
    /// Returns the [`JcsError`] of a dump without a JCS form. The dump of a program has
    /// unique member names and integer numbers only, so the error does not occur.
    pub fn state_hash(&self) -> Result<StateHash, JcsError> {
        let text = write_jcs(&crate::codec::facts(self))?;
        Ok(StateHash(sha256(text.as_bytes())))
    }
}
