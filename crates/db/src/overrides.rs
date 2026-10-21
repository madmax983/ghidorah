//! The flow override manager (design Sections 3.4 and 7.5).
//!
//! The key is the address of an instruction. An override changes the flow that analysis
//! gives the instruction. The manager sorts an `IndirectTargets` list and removes its
//! duplicates. The list holds at most [`MAX_TARGETS`] addresses.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Address;

use crate::fact::{Fact, Invalid, Origin, WriteError, put};

/// The largest number of indirect targets of one site.
pub const MAX_TARGETS: usize = 1024;

/// A flow override.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowOverride {
    /// Execution continues at this address after the instruction.
    Fallthrough(Address),
    /// The call is a jump, for example a tail call.
    CallAsJump,
    /// The jump is a call.
    JumpAsCall,
    /// The targets of an indirect call or jump. Analysis treats the site as resolved.
    IndirectTargets(Vec<Address>),
}

impl FlowOverride {
    /// Gives the output name, for example `indirect_targets`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Fallthrough(_) => "fallthrough",
            Self::CallAsJump => "call_as_jump",
            Self::JumpAsCall => "jump_as_call",
            Self::IndirectTargets(_) => "indirect_targets",
        }
    }
}

impl fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The flow overrides of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowOverrides {
    map: BTreeMap<Address, Fact<FlowOverride>>,
}

impl FlowOverrides {
    /// Gives the number of overrides.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no override.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the override at `at`.
    #[must_use]
    pub fn get(&self, at: Address) -> Option<&Fact<FlowOverride>> {
        self.map.get(&at)
    }

    /// Gives all overrides in address order.
    pub fn iter(&self) -> impl Iterator<Item = (Address, &Fact<FlowOverride>)> {
        self.map.iter().map(|(a, o)| (*a, o))
    }

    /// Sets the override at `at` by the write rule. `None` removes it. Gives the old fact.
    ///
    /// The targets of `IndirectTargets` change to sorted order without duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_TARGETS`] targets, or [`WriteError::Blocked`]
    /// with the current override.
    pub(crate) fn set(
        &mut self,
        at: Address,
        flow: Option<FlowOverride>,
        origin: &Origin,
    ) -> Result<Option<Fact<FlowOverride>>, WriteError<FlowOverride>> {
        let flow = match flow {
            Some(FlowOverride::IndirectTargets(mut targets)) => {
                targets.sort_unstable();
                targets.dedup();
                if targets.len() > MAX_TARGETS {
                    return Err(Invalid::TooMany {
                        count: targets.len(),
                        max: MAX_TARGETS,
                    }
                    .into());
                }
                Some(FlowOverride::IndirectTargets(targets))
            }
            other => other,
        };
        put(&mut self.map, at, flow, origin)
    }
}
