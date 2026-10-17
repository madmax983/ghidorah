//! The cancellation map (design Section 2.4, ADR-0003).
//!
//! The reader registers a flag for each request before the worker gets it.
//! `notifications/cancelled { requestId }` sets the flag of that request.
//! The worker checks the flag before the call, and the tool checks it at fuel checkpoints.
//! The worker sends no reply for a cancelled request (AC-169e).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::mcp::rpc::RequestId;

/// The cancel flags of the requests in flight.
#[derive(Debug, Clone, Default)]
pub struct CancelMap {
    flags: Arc<Mutex<BTreeMap<RequestId, Arc<AtomicBool>>>>,
}

impl CancelMap {
    /// Makes an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the flag of request `id`. A new ID gets a new flag that is not set.
    #[must_use]
    pub fn register(&self, id: &RequestId) -> Arc<AtomicBool> {
        let mut flags = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(flags.entry(id.clone()).or_default())
    }

    /// Sets the flag of request `id`. Gives `false` when no request has that ID.
    #[must_use]
    pub fn cancel(&self, id: &RequestId) -> bool {
        let flags = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
        flags.get(id).is_some_and(|flag| {
            flag.store(true, Ordering::Relaxed);
            true
        })
    }

    /// Removes the flag of request `id` after its reply.
    pub fn finish(&self, id: &RequestId) {
        let mut flags = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = flags.remove(id);
    }

    /// Gives the number of requests in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flags
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Tells if no request is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
