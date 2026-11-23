//! The op values of the block runs of the stack tracking.

use ghidorah_ir::{Arena, Val};

use super::Sp;

/// The op values of one block run, by value number. A slot holds a value only when its stamp
/// is the stamp of the current block run. One table serves all block runs of a function.
pub(super) struct Vals {
    slots: Vec<(u32, Sp)>,
    stamp: u32,
}

impl Vals {
    /// Makes a table for the values of `arena`.
    pub(super) fn new(arena: &Arena) -> Self {
        Self {
            slots: vec![(0, Sp::Unset); arena.val_count()],
            stamp: 0,
        }
    }

    /// Starts a block run: no slot holds a value.
    pub(super) fn start(&mut self) {
        if let Some(next) = self.stamp.checked_add(1) {
            self.stamp = next;
        } else {
            self.slots.fill((0, Sp::Unset));
            self.stamp = 1;
        }
    }

    /// Gives the value `v` of the current block run.
    pub(super) fn get(&self, v: Val) -> Option<Sp> {
        let i = usize::try_from(v.0).ok()?;
        self.slots
            .get(i)
            .filter(|(stamp, _)| *stamp == self.stamp)
            .map(|(_, sp)| *sp)
    }

    /// Sets the value `v` of the current block run.
    pub(super) fn set(&mut self, v: Val, sp: Sp) {
        let Ok(i) = usize::try_from(v.0) else {
            return;
        };
        if i >= self.slots.len() {
            self.slots.resize(i.saturating_add(1), (0, Sp::Unset));
        }
        if let Some(slot) = self.slots.get_mut(i) {
            *slot = (self.stamp, sp);
        }
    }
}
