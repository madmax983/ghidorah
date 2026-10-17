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
//! | [`session`] | [`Session`], the host of the shipped tools, and [`RunConfig`] | Sections 10.2, 10.11 |
//! | [`roots`] | The path roots of `binary_load` | Section 10.16, ADR-0022 |
//! | [`resolve`] | The address resolver: the rule order and the target table | Section 10.5, ADR-0007 |
//! | [`cursor`] | Keyset cursors | Section 10.9, ADR-0021 |
//! | [`coerce`] | Lenient coercion of argument values | Section 10.2 |
//! | [`profiles`] | Profiles, the tool allowlist and the `tools/list` entries | Section 10.3 |
//! | [`instructions`] | The generated server instructions | Section 10.15 |
//! | [`tool_search`](mod@tool_search) | The `tool_search` index, the synonyms and the topics | Section 10.4 |
//! | [`demo`] | The built-in demo binary | Section 10.4 |
//! | [`calc`](mod@calc) | The `calc` expression engine | Section 10.4 |
//! | [`handlers`] | The tool handlers, one file per tool | Section 10.4 |
//!
//! The modules of the pipeline do no file or network I/O. Only [`roots`] reads files, for
//! `binary_load`.

pub mod api;
pub mod args;
pub mod budget;
pub mod calc;
pub mod coerce;
pub mod content;
pub mod cursor;
pub mod demo;
pub mod dispatch;
pub mod envelope;
pub mod errors;
pub mod handlers;
pub mod hints;
pub mod instructions;
pub mod outshape;
pub mod profiles;
pub mod registry;
pub mod resolve;
pub mod roots;
pub mod schema;
pub mod session;
pub mod spec;
pub mod tool_search;

pub use api::{Host, Progress, Request, dispatch, dispatch_with};
pub use args::{Args, Format, Globals, Shape};
pub use content::ContentMode;
pub use dispatch::{Ctx, Item, KeyPart, ListPayload, Members, Payload, SortKey, Total};
pub use envelope::{AnalysisInfo, AnalysisState, Envelope, Frame, Page, Warning};
pub use errors::{Candidate, ErrorParts, ToolError};
pub use hints::Call;
pub use outshape::{Field, Fit, OutputShape};
pub use profiles::ProfileSet;
pub use registry::{LintFinding, LintRule, Registry};
pub use roots::Roots;
pub use session::{OpenBinary, RunConfig, Session, SessionConfig};
pub use spec::{
    ActionSpec, Annotations, ArgKind, ArgSpec, BinaryArg, Example, FuelSpec, Group, GroupRule,
    Handler, ListSpec, Profile, Role, ToolSpec,
};
