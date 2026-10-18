//! `batch_run`: run dependent tool steps in one call (design Section 11, tool 22).
//!
//! The argument tables and the output shape live here. The executor lives in
//! [`crate::batch`]. The handler calls [`crate::batch::run`].
//!
//! | Argument | Kind | Rule |
//! |---|---|---|
//! | `steps` | 1 to 32 objects `{ id, tool, args?, expect?, claim? }` | required |
//! | `return` | step IDs | the default is the last step |
//! | `on_error` | `stop` or `continue` | the default is `continue` for a read-only batch; a batch with edits always stops |
//! | `label` | text | the label of the one transaction |
//! | `resume` | `{ from_step, bindings }` | the replay of a batch that stopped on its fuel |
//!
//! The global arguments `binary_id`, `max_chars`, `max_steps`, `max_ms`, `dry_run`,
//! `expected_rev` and `session` go only at the top level.

use crate::args::Args;
use crate::batch::{self, DEFAULT_FUEL, MAX_FUEL, MAX_GUARDS, MAX_STEP_ID, MAX_STEPS, OPS};
use crate::budget::LARGE_MAX_CHARS;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{
    Annotations, ArgKind, ArgSpec, BinaryArg, Example, FuelSpec, Profile, Role, ToolSpec,
};

/// The largest number of resume bindings.
pub const MAX_BINDINGS: usize = 64;

/// The largest pointer text of a guard or a binding.
pub const MAX_POINTER: usize = 512;

/// Every fixed text of the handler and of the executor that an agent reads.
pub const TEXTS: &[&str] = batch::TEXTS;

const GUARD_MEMBERS: &[ArgSpec] = &[
    ArgSpec::new(
        "ptr",
        Role::Param,
        ArgKind::Str(MAX_POINTER),
        "A JSON pointer into the step envelope, for example /data/items.",
    )
    .required(),
    ArgSpec::new(
        "op",
        Role::Param,
        ArgKind::Enum(&OPS),
        "The test of the guard.",
    )
    .required(),
    ArgSpec::new(
        "value",
        Role::Param,
        ArgKind::Json,
        "The value of the test. The op exists does not need it.",
    ),
];

const GUARD: ArgSpec = ArgSpec::new(
    "guard",
    Role::Param,
    ArgKind::Obj(GUARD_MEMBERS),
    "One guard on the step envelope.",
);

const CLAIM_ARG: ArgSpec = ArgSpec::new(
    "arg",
    Role::Param,
    ArgKind::Json,
    "One argument of the relation: an ID, an address, a number or a glob.",
);

const CLAIM_MEMBERS: &[ArgSpec] = &[
    ArgSpec::new(
        "rel",
        Role::Param,
        ArgKind::Str(32),
        "The relation, for example calls.",
    )
    .required(),
    ArgSpec::new(
        "args",
        Role::Param,
        ArgKind::List(&CLAIM_ARG, 4),
        "The arguments of the relation.",
    )
    .required(),
];

const CLAIM: ArgSpec = ArgSpec::new(
    "claim",
    Role::Param,
    ArgKind::Obj(CLAIM_MEMBERS),
    "One relation claim. The fact_check verdict must be supported.",
);

const STEP_MEMBERS: &[ArgSpec] = &[
    ArgSpec::new(
        "id",
        Role::Param,
        ArgKind::Str(MAX_STEP_ID),
        "The step ID: a lower case letter, then up to 15 lower case letters, digits or _.",
    )
    .required(),
    ArgSpec::new(
        "tool",
        Role::Param,
        ArgKind::Str(64),
        "The tool of the step.",
    )
    .required(),
    ArgSpec::new(
        "args",
        Role::Param,
        ArgKind::Json,
        "The arguments of the tool. An object {$ref, ptr, partial?} takes a value of an earlier step.",
    ),
    ArgSpec::new(
        "expect",
        Role::Param,
        ArgKind::List(&GUARD, MAX_GUARDS),
        "Guards on the step envelope. A failed guard gives EXPECT_FAILED.",
    ),
    ArgSpec::new(
        "claim",
        Role::Param,
        ArgKind::List(&CLAIM, MAX_GUARDS),
        "Relation claims after the step. A claim that is not supported gives EXPECT_FAILED.",
    ),
];

const STEP: ArgSpec = ArgSpec::new(
    "step",
    Role::Param,
    ArgKind::Obj(STEP_MEMBERS),
    "One step: a tool call.",
);

const STEP_ID: ArgSpec = ArgSpec::new(
    "step_id",
    Role::Param,
    ArgKind::Str(MAX_STEP_ID),
    "A step ID.",
);

const BINDING_MEMBERS: &[ArgSpec] = &[
    ArgSpec::new(
        "step",
        Role::Param,
        ArgKind::Str(MAX_STEP_ID),
        "The ID of a completed step.",
    )
    .required(),
    ArgSpec::new(
        "ptr",
        Role::Param,
        ArgKind::Str(MAX_POINTER),
        "The pointer of the reference.",
    )
    .required(),
    ArgSpec::new(
        "value",
        Role::Param,
        ArgKind::Json,
        "The value that the reference gave.",
    )
    .required(),
];

const BINDING: ArgSpec = ArgSpec::new(
    "binding",
    Role::Param,
    ArgKind::Obj(BINDING_MEMBERS),
    "The value of one reference to a completed step.",
);

const RESUME_MEMBERS: &[ArgSpec] = &[
    ArgSpec::new(
        "from_step",
        Role::Param,
        ArgKind::Str(MAX_STEP_ID),
        "The ID of the first step that did not complete.",
    )
    .required(),
    ArgSpec::new(
        "bindings",
        Role::Param,
        ArgKind::List(&BINDING, MAX_BINDINGS),
        "The values of the references to the completed steps.",
    ),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "steps",
        Role::Param,
        ArgKind::List(&STEP, MAX_STEPS),
        "The steps in run order. A step can refer only to an earlier step.",
    )
    .required(),
    ArgSpec::new(
        "return",
        Role::Param,
        ArgKind::List(&STEP_ID, MAX_STEPS),
        "The steps whose data the result holds. The default is the last step.",
    ),
    ArgSpec::new(
        "on_error",
        Role::Param,
        ArgKind::Enum(&["stop", "continue"]),
        "What a read-only batch does after a failed step. A batch with edits always stops.",
    ),
    ArgSpec::new(
        "label",
        Role::Param,
        ArgKind::Str(128),
        "The label of the transaction. The default joins the tool names of the edit steps.",
    ),
    ArgSpec::new(
        "resume",
        Role::Param,
        ArgKind::Obj(RESUME_MEMBERS),
        "The data.resume of a batch that stopped on its fuel. The completed steps do not run again.",
    ),
];

const PAGE_FIELDS: &[Field] = &[
    Field::req("returned", OutputShape::Int),
    Field::opt("total", OutputShape::Int),
    Field::opt("total_lower_bound", OutputShape::Int),
    Field::req("truncated", OutputShape::Bool),
    Field::opt("next_cursor", OutputShape::Str),
    Field::opt("hint", OutputShape::Str),
];
const ENTRY: &[Field] = &[
    Field::req("id", OutputShape::Str),
    Field::req("tool", OutputShape::Str),
    Field::req("ok", OutputShape::Bool),
    Field::req("chars", OutputShape::Int),
    Field::req("fuel", OutputShape::Int),
    Field::opt("resumed", OutputShape::Bool),
    Field::opt("data", OutputShape::Any),
    Field::opt("omitted", OutputShape::Obj(OMITTED)),
    Field::opt("error", OutputShape::Any),
    Field::opt("page", OutputShape::Obj(PAGE_FIELDS)),
    Field::opt("warnings", OutputShape::List(&OutputShape::Any)),
    Field::opt("next", OutputShape::List(&OutputShape::Any)),
];
const OMITTED: &[Field] = &[Field::req("chars", OutputShape::Int)];
const ENTRY_SHAPE: OutputShape = OutputShape::Obj(ENTRY);
const USED: &[Field] = &[
    Field::req("chars", OutputShape::Int),
    Field::req("fuel", OutputShape::Int),
    Field::req("steps", OutputShape::Int),
];
const BOUND: &[Field] = &[
    Field::req("step", OutputShape::Str),
    Field::req("ptr", OutputShape::Str),
    Field::req("value", OutputShape::Any),
];
const BOUND_SHAPE: OutputShape = OutputShape::Obj(BOUND);
const RESUME: &[Field] = &[
    Field::req("from_step", OutputShape::Str),
    Field::req("bindings", OutputShape::List(&BOUND_SHAPE)),
];
const FIELDS: &[Field] = &[
    Field::req("steps", OutputShape::List(&ENTRY_SHAPE)),
    Field::req("budget_used", OutputShape::Obj(USED)),
    Field::opt("stopped_by", OutputShape::Str),
    Field::opt("deterministic", OutputShape::Bool),
    Field::opt("resume", OutputShape::Obj(RESUME)),
];

/// `batch_run`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Run a batch of steps",
    summary: "Run up to 32 dependent tool steps in one batch call, with references, guards and one transaction for edits.",
    description: "Run up to 32 dependent tool steps in one batch call, with references, guards and one transaction for edits. \
                  A step argument {\"$ref\":\"s1\",\"ptr\":\"/data/items/*/id\"} takes values of an earlier step. \
                  Only the steps in return send their data. \
                  A batch with edits commits once with one rev, or rolls back.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations {
        read_only: false,
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    mutating: true,
    profiles: &Profile::ALL,
    examples: &[
        Example {
            args: r#"{"steps":[{"id":"s1","tool":"search","args":{"kind":"string","query":"password","limit":5}},{"id":"s2","tool":"xref_list","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/id"}},"expect":[{"ptr":"/data/items","op":"len_gt","value":0}]},{"id":"s3","tool":"func_get","args":{"targets":{"$ref":"s2","ptr":"/data/items/*/from_func/id"}}}],"return":["s3"]}"#,
            golden: "tests/golden/batch/batch_run.1.json",
        },
        Example {
            args: r#"{"steps":[{"id":"rename","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},{"id":"note","tool":"comment_set","args":{"target":"0x1080","kind":"plate","text":"The entry reads the input and checks it."}},{"id":"check","tool":"addr_info","args":{"target":"0x1090"},"expect":[{"ptr":"/data/symbol/name","op":"eq","value":"read_input"}]}],"return":["check"],"label":"rename and comment"}"#,
            golden: "tests/golden/batch/batch_run.2.json",
        },
        Example {
            args: r#"{"steps":[{"id":"s1","tool":"symbol_rename","args":{"target":"fn:0x11e0","name":"verify_password","force":true}}],"dry_run":true}"#,
            golden: "tests/golden/batch/batch_run.3.json",
        },
    ],
    binary: BinaryArg::Optional,
    max_chars: LARGE_MAX_CHARS,
    fuel: Some(FuelSpec {
        default: DEFAULT_FUEL,
        cap: MAX_FUEL,
    }),
    ..ToolSpec::base("batch_run", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    batch::run(session, args, ctx)
}
