//! The progress sender (design Section 10.13).
//!
//! A `tools/call` request with `_meta.progressToken` gets one
//! `notifications/progress { progressToken, progress, total?, message }` for each report of
//! the tool. [`forward`] runs on its own thread while the tool runs. It drops a report whose
//! `progress` is not above the last one, so `progress` increases strictly.

use std::sync::mpsc::Receiver;

use ghidorah_json::Value;
use ghidorah_tools::Progress;

/// The method of a progress notification.
pub const METHOD: &str = "notifications/progress";

/// Gives the notification of one report.
#[must_use]
pub fn notification(token: &Value, report: &Progress) -> Value {
    let _ = (token, report);
    Value::Null
}

/// Sends a notification through `emit` for each report of `reports` until the channel closes.
///
/// Gives the number of sent notifications.
pub fn forward(reports: &Receiver<Progress>, token: &Value, emit: &(dyn Fn(Value) + Sync)) -> u64 {
    let _ = (reports, token, emit);
    0
}
