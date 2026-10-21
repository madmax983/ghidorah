//! `func_edit`: create or delete functions and override the analysis (design Section 10.4,
//! tool 19).
//!
//! Each action commits one agent fact. Then the call runs the shadow re-analysis from the
//! start band of the edit within `max_steps` (design Section 3.9):
//!
//! | Action | Arguments | Fact | Band |
//! |---|---|---|---|
//! | `create` | `target` (the entry), `name` | `CreateFunction`, and `SetName` with a name | 100 |
//! | `delete` (destructive) | `target` (`fn:`) | `DeleteFunction` with its variable facts and plate comment | 100 |
//! | `set_noreturn` | `target`, `noreturn` | `SetNoreturn` | 100 |
//! | `set_jumptable` | `at` (an indirect jump), `targets` (the case addresses) | `SetJumpTable` | 100 |
//! | `set_flow` | `at`, `flow: { kind, to? }` | `SetFlowOverride`. The kind `clear` removes it. | 100 |
//! | `set_call_targets` | `at` (an indirect call or jump), `targets` (`fn:` or `imp:` IDs) | `SetFlowOverride(IndirectTargets)` | 100 |
//! | `add_ref` | `ref: { from, to, kind }` | `AddRef` with the source `agent` | 100 |
//! | `remove_ref` (destructive) | `ref: { from, to, kind }` | `RemoveRef` | 100 |
//!
//! The result is `{ action, target, rev, analysis: { state, steps_used } }`. `target` is the ID
//! of the changed fact: a `fn:` ID, the address of the site or a `ref:` ID.
//!
//! - Only a function that an agent or a user made can go. Analysis finds the other functions
//!   again, so `delete` of such a function gives `NOT_FOUND`.
//! - A `create` in the body of another function gives `BODY_OVERLAP`. The candidate names the
//!   owner.
//! - A re-analysis that stops on the fuel gives `W_ANALYSIS_STALE`. `analysis_run` resumes it.
//! - A complete re-analysis gives `W_FACT_ORPHANED` for each agent fact that lost its anchor
//!   (design Section 3.9) and `W_AGENT_OVERRIDE_CONFLICT` when the analysis disagrees with
//!   the override.
//! - `dry_run: true` gives the planned edits in `diff` and changes nothing.
//!
//! The `plan` module checks the inputs. The `edit` module holds the commit steps that
//! `type_edit` also uses.

pub(crate) mod edit;
mod plan;

use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{
    ActionSpec, Annotations, ArgKind, ArgSpec, Example, FuelSpec, Profile, Role, ToolSpec,
};

/// The default fuel of the re-analysis after an edit (design Section 3.9).
pub const DEFAULT_STEPS: u64 = 2_000_000;

/// The largest `max_steps` of one edit.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The largest number of `targets` of one call: the cap of a jump table.
pub const MAX_TARGETS: usize = 1_024;

/// The longest name of a new function.
pub const MAX_NAME: usize = 1_024;

/// The actions in schema order.
pub const ACTIONS_LIST: [&str; 8] = [
    "create",
    "delete",
    "set_noreturn",
    "set_jumptable",
    "set_flow",
    "set_call_targets",
    "add_ref",
    "remove_ref",
];

/// The kinds of `flow.kind`.
pub const FLOW_KINDS: [&str; 4] = ["fallthrough", "call_as_jump", "jump_as_call", "clear"];

/// The kinds of `ref.kind`: the reference type names of design Section 3.4.
pub const REF_KINDS: [&str; 11] = [
    "unconditional_call",
    "conditional_call",
    "computed_call",
    "unconditional_jump",
    "conditional_jump",
    "computed_jump",
    "data",
    "read",
    "write",
    "read_write",
    "param",
];

/// The `why` of the repair call with `force: true`.
pub const WHY_FORCE: &str = "Send the call again with force true when the change is correct.";

/// The `why` of the remedy of an orphaned fact that lost its function.
pub const WHY_CREATE: &str = "Make the function again at its entry.";

/// The `why` of the remedy of a re-analysis that stopped on its fuel.
pub const WHY_RESUME: &str = "Complete the re-analysis of the binary.";

/// The `why` of the remedy of an override that the analysis disagrees with.
pub const WHY_CONFLICT: &str = "Set the value of the analysis when the override is not correct.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_FORCE, WHY_CREATE, WHY_RESUME, WHY_CONFLICT];

/// The actions that act on one function.
const ON_FUNC: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_noreturn"),
];

/// The actions that act on one site.
const ON_SITE: &[(&str, &str)] = &[
    ("action", "set_jumptable"),
    ("action", "set_flow"),
    ("action", "set_call_targets"),
];

/// The actions that act on one reference.
const ON_REF: &[(&str, &str)] = &[("action", "add_ref"), ("action", "remove_ref")];

/// The actions other than those that act on one function.
const NOT_FUNC: &[(&str, &str)] = &[
    ("action", "set_jumptable"),
    ("action", "set_flow"),
    ("action", "set_call_targets"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

/// The actions other than those that act on one site.
const NOT_SITE: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_noreturn"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

/// The actions other than those that act on one reference.
const NOT_REF: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_noreturn"),
    ("action", "set_jumptable"),
    ("action", "set_flow"),
    ("action", "set_call_targets"),
];

/// The actions other than `create`.
const NOT_CREATE: &[(&str, &str)] = &[
    ("action", "delete"),
    ("action", "set_noreturn"),
    ("action", "set_jumptable"),
    ("action", "set_flow"),
    ("action", "set_call_targets"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

/// The actions other than `set_noreturn`.
const NOT_NORETURN: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_jumptable"),
    ("action", "set_flow"),
    ("action", "set_call_targets"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

/// The actions that take `targets`.
const WITH_TARGETS: &[(&str, &str)] =
    &[("action", "set_jumptable"), ("action", "set_call_targets")];

/// The actions that take no `targets`.
const NO_TARGETS: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_noreturn"),
    ("action", "set_flow"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

/// The actions that take no `flow`.
const NO_FLOW: &[(&str, &str)] = &[
    ("action", "create"),
    ("action", "delete"),
    ("action", "set_noreturn"),
    ("action", "set_jumptable"),
    ("action", "set_call_targets"),
    ("action", "add_ref"),
    ("action", "remove_ref"),
];

const FLOW_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "kind",
        Role::Param,
        ArgKind::Enum(&FLOW_KINDS),
        "The new flow of the instruction. The kind clear removes the override.",
    )
    .required(),
    ArgSpec::new(
        "to",
        Role::Param,
        ArgKind::Addr,
        "The next address of the kind fallthrough.",
    ),
];

const REF_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "from",
        Role::Param,
        ArgKind::Addr,
        "The source: the start of an instruction or of a data definition.",
    )
    .required(),
    ArgSpec::new("to", Role::Param, ArgKind::Addr, "The destination address.").required(),
    ArgSpec::new(
        "kind",
        Role::Param,
        ArgKind::Enum(&REF_KINDS),
        "The reference type, for example unconditional_call or read.",
    )
    .required(),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "action",
        Role::Selector,
        ArgKind::Enum(&ACTIONS_LIST),
        "The change to make.",
    )
    .required(),
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The function: an entry address, a name or a fn: ID.",
    )
    .required_when(ON_FUNC)
    .forbidden_when(NOT_FUNC),
    ArgSpec::new(
        "at",
        Role::At,
        ArgKind::Addr,
        "The instruction of the override: an indirect jump, an indirect call or a branch.",
    )
    .required_when(ON_SITE)
    .forbidden_when(NOT_SITE),
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(MAX_NAME),
        "The name of the new function.",
    )
    .forbidden_when(NOT_CREATE),
    ArgSpec::new(
        "noreturn",
        Role::Param,
        ArgKind::Bool,
        "The value true marks a function that does not return.",
    )
    .required_when(&[("action", "set_noreturn")])
    .forbidden_when(NOT_NORETURN),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "The case addresses of a jump table, or the fn: and imp: IDs of an indirect call.",
    )
    .required_when(WITH_TARGETS)
    .forbidden_when(NO_TARGETS),
    ArgSpec::new(
        "flow",
        Role::Param,
        ArgKind::Obj(FLOW_ARGS),
        "The flow override: a kind, and the next address of the kind fallthrough.",
    )
    .required_when(&[("action", "set_flow")])
    .forbidden_when(NO_FLOW),
    ArgSpec::new(
        "ref",
        Role::Param,
        ArgKind::Obj(REF_ARGS),
        "The reference: its source, its destination and its type.",
    )
    .required_when(ON_REF)
    .forbidden_when(NOT_REF),
];

/// The example of `create`.
pub const EXAMPLE_CREATE: &str = r#"{"action":"create","target":"0x11d0"}"#;

/// The example of `delete`. It needs the function of [`EXAMPLE_CREATE`].
pub const EXAMPLE_DELETE: &str = r#"{"action":"delete","target":"fn:0x11d0"}"#;

/// The example of `add_ref`.
pub const EXAMPLE_ADD_REF: &str =
    r#"{"action":"add_ref","ref":{"from":"0x10f8","to":"0x11d0","kind":"data"}}"#;

/// The example of `remove_ref`. It needs the reference of [`EXAMPLE_ADD_REF`].
pub const EXAMPLE_REMOVE_REF: &str =
    r#"{"action":"remove_ref","ref":{"from":"0x10f8","to":"0x11d0","kind":"data"}}"#;

/// The example of `set_noreturn`.
const EXAMPLE_NORETURN: &str = r#"{"action":"set_noreturn","target":"fn:0x11e0","noreturn":false}"#;

/// The example of `set_jumptable`.
const EXAMPLE_JUMPTABLE: &str = r#"{"action":"set_jumptable","at":"0x1170","targets":["0x1178"]}"#;

/// The example of `set_flow`.
const EXAMPLE_FLOW: &str = r#"{"action":"set_flow","at":"0x10c7","flow":{"kind":"call_as_jump"}}"#;

/// The example of `set_call_targets`.
const EXAMPLE_CALLS: &str =
    r#"{"action":"set_call_targets","at":"0x1014","targets":["fn:0x11c0"]}"#;

/// Gives the setup example of an example: the example that makes the fact it changes.
#[must_use]
pub fn setup_of(example: &str) -> Option<&'static str> {
    match example {
        EXAMPLE_DELETE => Some(EXAMPLE_CREATE),
        EXAMPLE_REMOVE_REF => Some(EXAMPLE_ADD_REF),
        _ => None,
    }
}

const ACTIONS: &[ActionSpec] = &[
    action(
        "create",
        "Make a function at an entry that the analysis did not find.",
        EXAMPLE_CREATE,
        false,
    ),
    action(
        "delete",
        "Remove a function that an agent made, with its variable facts and its plate comment.",
        EXAMPLE_DELETE,
        true,
    ),
    action(
        "set_noreturn",
        "Mark a function that does not return, or that returns.",
        EXAMPLE_NORETURN,
        false,
    ),
    action(
        "set_jumptable",
        "Set the case addresses of the jump table of an indirect jump.",
        EXAMPLE_JUMPTABLE,
        false,
    ),
    action(
        "set_flow",
        "Change the flow of an instruction: a new next address, a call as a jump or a jump as a call.",
        EXAMPLE_FLOW,
        false,
    ),
    action(
        "set_call_targets",
        "Set the functions or imports that an indirect call or jump reaches.",
        EXAMPLE_CALLS,
        false,
    ),
    action(
        "add_ref",
        "Add a reference with the source agent.",
        EXAMPLE_ADD_REF,
        false,
    ),
    action(
        "remove_ref",
        "Remove a reference that an agent added.",
        EXAMPLE_REMOVE_REF,
        true,
    ),
];

/// Makes one action.
const fn action(
    value: &'static str,
    line: &'static str,
    example: &'static str,
    destructive: bool,
) -> ActionSpec {
    ActionSpec {
        value,
        line,
        example,
        destructive,
    }
}

const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
];

const FIELDS: &[Field] = &[
    Field::req("action", OutputShape::Str),
    Field::req("target", OutputShape::Str),
    Field::req("rev", OutputShape::Int),
    Field::req("analysis", OutputShape::Obj(ANALYSIS)),
];

/// `func_edit`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Edit functions and overrides",
    summary: "Create or delete functions and override the analysis: noreturn, jump-table targets, flow, indirect call targets and references.",
    description: "Create or delete functions and override the analysis: noreturn, jump-table targets, flow, indirect call targets and references. \
                  Each action commits one agent fact and runs the re-analysis within max_steps. \
                  The analysis never replaces an override. \
                  The actions delete and remove_ref remove only the facts of an agent or a user.",
    args: ARGS,
    actions: ACTIONS,
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations {
        read_only: false,
        destructive: true,
        idempotent: true,
        open_world: false,
    },
    mutating: true,
    analysis_affecting: true,
    profiles: &[Profile::Full],
    examples: &[
        example(EXAMPLE_CREATE, "tests/golden/tools/func_edit.1.json"),
        example(EXAMPLE_DELETE, "tests/golden/tools/func_edit.2.json"),
        example(EXAMPLE_NORETURN, "tests/golden/tools/func_edit.3.json"),
        example(EXAMPLE_JUMPTABLE, "tests/golden/tools/func_edit.4.json"),
        example(EXAMPLE_FLOW, "tests/golden/tools/func_edit.5.json"),
        example(EXAMPLE_CALLS, "tests/golden/tools/func_edit.6.json"),
        example(EXAMPLE_ADD_REF, "tests/golden/tools/func_edit.7.json"),
        example(EXAMPLE_REMOVE_REF, "tests/golden/tools/func_edit.8.json"),
    ],
    force: true,
    fuel: Some(FuelSpec {
        default: DEFAULT_STEPS,
        cap: MAX_STEPS,
    }),
    ..ToolSpec::base("func_edit", run)
};

/// Makes one executed example.
const fn example(args: &'static str, golden: &'static str) -> Example {
    Example { args, golden }
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    crate::handlers::func_sections::x86_only(p)?;
    let plan = plan::Plan::of(p, args)?;
    let focus = plan.focus(p);
    let out = edit::run(session, args, ctx, focus, |tx| plan.apply(tx, args))?;
    let mut result = Object::new();
    result.push("action", Value::from(args.action().unwrap_or_default()));
    result.push("target", Value::from(plan.target()));
    result.push("rev", Value::from(out.rev));
    result.push("analysis", edit::analysis(out.report, ctx));
    Ok(Payload::Object(result))
}
