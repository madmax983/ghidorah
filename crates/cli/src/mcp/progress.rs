//! The progress sender (design Section 10.13).
//!
//! A `tools/call` request with `_meta.progressToken` gets one
//! `notifications/progress { progressToken, progress, total?, message }` for each report of
//! the tool. [`forward`] runs on its own thread while the tool runs. It drops a report whose
//! `progress` is not above the last one, so `progress` increases strictly.

use std::sync::mpsc::Receiver;

use ghidorah_json::{Object, Value};
use ghidorah_tools::Progress;

use crate::mcp::rpc;

/// The method of a progress notification.
pub const METHOD: &str = "notifications/progress";

/// Gives the notification of one report.
#[must_use]
pub fn notification(token: &Value, report: &Progress) -> Value {
    let mut params = Object::new();
    params.push("progressToken", token.clone());
    params.push("progress", Value::from(report.progress));
    if let Some(total) = report.total {
        params.push("total", Value::from(total));
    }
    params.push("message", Value::from(report.message.as_str()));
    rpc::notification(METHOD, Value::Object(params))
}

/// Sends a notification through `emit` for each report of `reports` until the channel closes.
///
/// Gives the number of sent notifications.
pub fn forward(reports: &Receiver<Progress>, token: &Value, emit: &(dyn Fn(Value) + Sync)) -> u64 {
    let mut last = None;
    let mut sent: u64 = 0;
    for report in reports {
        if last.is_some_and(|l| report.progress <= l) {
            continue;
        }
        last = Some(report.progress);
        emit(notification(token, &report));
        sent = sent.saturating_add(1);
    }
    sent
}
