//! The tool handlers: one file per tool (design Section 10.4, ADR-0005).
//!
//! Each file exports `pub const SPEC: ToolSpec<Session>`. The shipped list in
//! [`crate::registry`] names each `SPEC` in the fixed `tools/list` order. This module is a
//! plain list of the handler files.

pub mod calc;
pub mod history_list;
pub mod history_undo;
pub mod load;
pub mod tool_search;
