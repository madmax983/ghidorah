//! The tool handlers: one file per tool (design Section 10.4, ADR-0005).
//!
//! Each file exports `pub const SPEC: ToolSpec<Session>`. The shipped list in
//! [`crate::registry`] names each `SPEC` in the fixed `tools/list` order. This module is a
//! plain list of the handler files. [`func_sections`] holds the renderers of the read tools.

pub mod addr_info;
pub mod analysis_run;
pub mod calc;
pub mod comment_set;
pub mod func_get;
pub mod func_list;
pub mod func_sections;
pub mod history_list;
pub mod history_undo;
pub mod load;
pub mod mem_read;
pub mod note_write;
pub mod search;
pub mod session_brief;
pub mod survey;
pub mod symbol_rename;
pub mod tool_search;
pub mod xref_list;
