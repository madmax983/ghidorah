//! The tool surface of ghidorah: one registry for all surfaces (ADR-0005).
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`api`] | [`Request`], [`Envelope`], [`dispatch()`], [`dispatch_with`] and the [`Host`] trait | Section 10.1 |
//! | [`spec`] | [`ToolSpec`], [`ArgSpec`], groups, actions, examples, annotations, profiles | Section 10.1 |
//! | [`registry`] | [`Registry`], the shipped list and the registry lint | Section 10.1, AC-129, AC-222 |
//! | [`args`] | The argument parser, the global arguments and [`Args`] | Section 10.2 |
//! | [`schema`] | The JSON Schema subset and the `tools/list` entry | Section 10.1 |
//! | [`outshape`] | [`OutputShape`] and its fit check | Section 10.1 |
//! | [`dispatch`](mod@dispatch) | The pipeline, [`Ctx`] and [`Payload`] | Sections 10.6, 10.9 |
//! | [`envelope`] | The result envelope, warnings and pages | Section 10.6 |
//! | [`budget`] | The budget writer: K6 fit, copies and section weights | Section 10.9 |
//! | [`errors`] | [`ToolError`] and the frozen error object | Section 10.8 |
//! | [`hints`] | Executable `next` calls and their check | Section 10.6, AC-143 |
//! | [`content`] | Content modes and exact result sizes | Section 10.10 |
//!
//! The crate does no file or network I/O in this module set. Hosts give the session state.

pub mod api;
pub mod args;
pub mod budget;
pub mod content;
pub mod dispatch;
pub mod envelope;
pub mod errors;
pub mod hints;
pub mod outshape;
pub mod registry;
pub mod schema;
pub mod spec;

pub use api::{Host, Progress, Request, dispatch, dispatch_with};
pub use args::{Args, Format, Globals, Shape};
pub use content::ContentMode;
pub use dispatch::{Ctx, Item, KeyPart, ListPayload, Members, Payload, SortKey, Total};
pub use envelope::{AnalysisInfo, AnalysisState, Envelope, Frame, Page, Warning};
pub use errors::{Candidate, ErrorParts, ToolError};
pub use hints::Call;
pub use outshape::{Field, Fit, OutputShape};
pub use registry::{LintFinding, LintRule, Registry};
pub use spec::{
    ActionSpec, Annotations, ArgKind, ArgSpec, BinaryArg, Example, FuelSpec, Group, GroupRule,
    Handler, ListSpec, Profile, Role, ToolSpec,
};
