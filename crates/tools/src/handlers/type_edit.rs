//! `type_edit`: apply a C type or a prototype (design Sections 9.5 and 10.4, tool 20).
//!
//! | `target` | Argument | Fact | Band |
//! |---|---|---|---|
//! | a function: `fn:`, an entry or a name | `signature` | `SetSignature` | 800 |
//! | a variable: `var:` | `type` | `SetVarFact` with the type | - |
//! | another address | `type` | `SetDataDef` with the size of the type | 100 |
//!
//! The C text parses in `sig` or `type` mode (design Section 9.2) into the type store of the
//! program. The journal line keeps the text, so a reopen gives the same types. A text that
//! does not parse gives `C_PARSE_ERROR` with `details.errors`. The name in a prototype does
//! not rename the function.
//!
//! The result is `{ applied: { target, old, new }, rev, analysis? }`. `old` and `new` are C
//! texts, and `old` is `null` when no fact was there. A signature re-runs only the bands 800
//! and above, so the other analysis facts stay (AC-210). A data definition re-runs from band
//! 100. `dry_run: true` gives the planned edits and changes nothing.

use ghidorah_base::ErrorCode;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{
    Annotations, ArgKind, ArgSpec, Example, FuelSpec, Group, GroupRule, Profile, Role, ToolSpec,
};

/// The longest C text.
pub const MAX_C: usize = 4_000;

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The function, the variable or the data: an address, a name, a fn: ID or a var: ID.",
    )
    .required(),
    ArgSpec::new(
        "type",
        Role::Param,
        ArgKind::Str(MAX_C),
        "The C type text of a variable or of the data at an address, for example char [16].",
    ),
    ArgSpec::new(
        "signature",
        Role::Param,
        ArgKind::Str(MAX_C),
        "One C prototype of a function, for example int check(const char *input).",
    ),
];

const APPLIED: &[Field] = &[
    Field::req("target", OutputShape::Str),
    Field::req("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("new", OutputShape::Str),
];

const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
];

const FIELDS: &[Field] = &[
    Field::req("applied", OutputShape::Obj(APPLIED)),
    Field::req("rev", OutputShape::Int),
    Field::opt("analysis", OutputShape::Obj(ANALYSIS)),
];

/// `type_edit`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Apply a C type",
    summary: "Apply a C type or a prototype to an address, a function or a variable.",
    description: "Apply a C type or a prototype to an address, a function or a variable. \
                  Send signature with one C prototype for a function. \
                  Send type with C type text for a var: ID or for the data at an address. \
                  A signature re-runs the analysis bands 800 and above, and data at an address re-runs the analysis from band 100. \
                  Text that does not parse gives C_PARSE_ERROR with the line, the column and the expected tokens. \
                  The name in the prototype does not rename the function.",
    args: ARGS,
    groups: &[Group {
        members: &["type", "signature"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    analysis_affecting: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: r#"{"target":"fn:0x11e0","signature":"int check_password(const char *input)"}"#,
            golden: "tests/golden/tools/type_edit.1.json",
        },
        Example {
            args: r#"{"target":"0x2004","type":"char [26]"}"#,
            golden: "tests/golden/tools/type_edit.2.json",
        },
        Example {
            args: r#"{"target":"var:0x11e0/param:0","type":"const char *","dry_run":true}"#,
            golden: "tests/golden/tools/type_edit.3.json",
        },
    ],
    force: true,
    fuel: Some(FuelSpec {
        default: super::func_edit::DEFAULT_STEPS,
        cap: super::func_edit::MAX_STEPS,
    }),
    ..ToolSpec::base("type_edit", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ErrorCode::InternalError))
}
