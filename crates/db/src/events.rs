//! The event ring (design Section 3.8).
//!
//! Each commit appends one [`Event`] for each table that it changes. An event holds the RAM
//! ranges and the fact keys that the commit changes in that table. The ring keeps the events
//! of the last [`EVENT_RING`] entries. The scheduler and the caches pull from it. There are
//! no callbacks.
//!
//! The ring drops the events of the oldest revisions as a whole. So the ring holds all
//! events of each revision that it holds (Section 3.11, invariant 7).

#[cfg(test)]
mod tests;

use std::collections::VecDeque;

use ghidorah_base::{Rev, TxId};
use ghidorah_kernel::RangeSet;

use crate::epochs::Table;
use crate::program::Program;
use crate::why::FactKey;

/// The largest number of events in the ring.
pub const EVENT_RING: usize = 4096;

/// The change of one table in one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The revision of the commit.
    pub rev: Rev,
    /// The transaction of the commit.
    pub tx: TxId,
    /// The table.
    pub kind: Table,
    /// The RAM addresses that the commit changes in the table.
    pub ranges: RangeSet,
    /// The keys of the facts that the commit changes in the table, in key order.
    pub ids: Vec<FactKey>,
}

/// The bounded ring of events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Events {
    ring: VecDeque<Event>,
    lost: Rev,
}

impl Events {
    /// Gives the number of events in the ring.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Tells if the ring holds no event.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Gives the events in commit order.
    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.ring.iter()
    }

    /// Gives the highest revision whose events the ring dropped, or 0.
    #[must_use]
    pub const fn lost(&self) -> Rev {
        self.lost
    }

    /// Gives the events of the revisions after `rev`, in commit order.
    ///
    /// `None` tells that the ring dropped an event after `rev`. Then the caller reads the
    /// tables again.
    #[must_use]
    pub fn since(&self, rev: Rev) -> Option<Vec<&Event>> {
        if rev < self.lost {
            return None;
        }
        Some(self.ring.iter().filter(|e| e.rev > rev).collect())
    }

    /// Appends the events of one commit. The oldest revisions leave the ring as a whole.
    ///
    /// A commit has at most one event per table, so the ring stays at [`EVENT_RING`] entries.
    pub(crate) fn push(&mut self, events: Vec<Event>) {
        while self.ring.len().saturating_add(events.len()) > EVENT_RING {
            let Some(rev) = self.ring.front().map(|e| e.rev) else {
                break;
            };
            while self.ring.front().is_some_and(|e| e.rev == rev) {
                self.ring.pop_front();
            }
            self.lost = self.lost.max(rev);
        }
        self.ring.extend(events);
    }
}

impl Program {
    /// Gives the event ring.
    #[must_use]
    pub fn events(&self) -> &Events {
        &self.changes().events
    }
}
