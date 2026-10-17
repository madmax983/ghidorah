//! `binary_load`: load a binary (design Section 10.4, tool 1).
//!
//! Exactly one of `path`, `builtin` and `binary_id` names the binary:
//!
//! | Argument | Source |
//! |---|---|
//! | `path` | a file under a root (Section 10.16, AC-147) |
//! | `builtin` | a built-in binary of [`crate::demo`] with no root check |
//! | `binary_id` | a binary that is open in the session |
//!
//! The load probes the format, maps the file and makes the program. A binary that is open
//! already gives `already_loaded: true` and no second copy. With an analysis engine in the
//! session, the load then runs the analysis within `max_steps`. Without one, the analysis
//! state is `none`. A dry run loads the file and reports it, but opens nothing.

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{
    Annotations, ArgKind, ArgSpec, BinaryArg, Example, FuelSpec, Group, GroupRule, Profile, Role,
    ToolSpec,
};

/// The default fuel of the analysis of one load (Section 7.2).
pub const DEFAULT_STEPS: u64 = 100_000_000;

/// The largest `max_steps` of one load.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The longest path in characters.
pub const MAX_PATH_CHARS: usize = 4_096;

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "path",
        Role::Param,
        ArgKind::Str(MAX_PATH_CHARS),
        "The path of the file. A relative path starts at the first root of the server.",
    ),
    ArgSpec::new(
        "builtin",
        Role::Param,
        ArgKind::Enum(&crate::demo::BUILTINS),
        "The name of a built-in binary. The demo binary is a small password check.",
    ),
    ArgSpec::new(
        "binary_id",
        Role::Param,
        ArgKind::Str(64),
        "The ID of a binary that is open in the session.",
    ),
    ArgSpec::new(
        "format",
        Role::Param,
        ArgKind::Enum(&["auto", "elf", "raw"]),
        "The file format. The value auto lets the probe find the format.",
    )
    .default_json("\"auto\""),
    ArgSpec::new(
        "arch",
        Role::Param,
        ArgKind::Enum(&["x86_64"]),
        "The machine of a raw blob.",
    )
    .default_json("\"x86_64\""),
    ArgSpec::new(
        "base",
        Role::Param,
        ArgKind::Addr,
        "The load address of a raw blob, as a 0x hex string.",
    ),
    ArgSpec::new(
        "entry",
        Role::Param,
        ArgKind::Addr,
        "The entry address of a raw blob, as a 0x hex string.",
    ),
    ArgSpec::new(
        "analysis",
        Role::Param,
        ArgKind::Enum(&["none", "triage", "full"]),
        "How far the analysis runs after the load.",
    )
    .default_json("\"full\""),
];

const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
];
const BY_CODE: &[Field] = &[
    Field::req("code", OutputShape::Str),
    Field::req("count", OutputShape::Int),
];
const BY_CODE_ITEM: OutputShape = OutputShape::Obj(BY_CODE);
const DIAGNOSTICS: &[Field] = &[
    Field::req("total", OutputShape::Int),
    Field::req("by_code", OutputShape::List(&BY_CODE_ITEM)),
];
const FIELDS: &[Field] = &[
    Field::req("binary_id", OutputShape::Str),
    Field::req("sha256", OutputShape::Str),
    Field::req("file_name", OutputShape::Str),
    Field::req("format", OutputShape::Str),
    Field::req("arch", OutputShape::Str),
    Field::req("kind", OutputShape::Str),
    Field::req("entry", OutputShape::Nullable(&OutputShape::Addr)),
    Field::req("size", OutputShape::Int),
    Field::req("already_loaded", OutputShape::Bool),
    Field::req("read_only", OutputShape::Bool),
    Field::req("analysis", OutputShape::Obj(ANALYSIS)),
    Field::req("diagnostics", OutputShape::Obj(DIAGNOSTICS)),
];

/// `binary_load`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Load a binary",
    summary: "Load a binary for analysis: an ELF file under a root, a raw blob, the built-in demo or an open binary by its ID.",
    description: "Load a binary for analysis: an ELF file under a root, a raw blob, the built-in demo or an open binary by its ID. \
                  Send exactly one of path, builtin and binary_id. \
                  A relative path starts at the first root of the server, and a path outside the roots gives PATH_OUTSIDE_ROOT. \
                  The probe finds the format. Send format raw with base for a blob of x86-64 code. \
                  A binary that is open already gives already_loaded true. \
                  The analysis runs after the load within max_steps. \
                  The result gives the binary_id. Send it in later calls when more than one binary is open.",
    args: ARGS,
    groups: &[Group {
        members: &["path", "builtin", "binary_id"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    profiles: &[Profile::Full, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"builtin":"demo"}"#,
            golden: "tests/golden/tools/binary_load.1.json",
        },
        Example {
            args: r#"{"path":"fixtures/bin/two_helpers.gcc-O2","format":"elf","analysis":"none"}"#,
            golden: "tests/golden/tools/binary_load.2.json",
        },
        Example {
            args: r#"{"path":"fixtures/bin/hello.gcc-O2","format":"raw","arch":"x86_64","base":"0x400000","entry":"0x401040","analysis":"triage"}"#,
            golden: "tests/golden/tools/binary_load.3.json",
        },
        Example {
            args: r#"{"path":"fixtures/bin/loops.gcc-O2","max_steps":1000,"dry_run":true}"#,
            golden: "tests/golden/tools/binary_load.4.json",
        },
        Example {
            args: r#"{"binary_id":"467a43b75d95c826"}"#,
            golden: "tests/golden/tools/binary_load.5.json",
        },
    ],
    binary: BinaryArg::None,
    fuel: Some(FuelSpec {
        default: DEFAULT_STEPS,
        cap: MAX_STEPS,
    }),
    ..ToolSpec::base("binary_load", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}
