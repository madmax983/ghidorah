//! `fact_check`: check claims and explain facts (design Sections 10.4 and 11.8, tool 11).
//!
//! The call takes up to 20 claims and up to 10 fact IDs. The result is
//! `{ verdicts, explanations, rules }`:
//!
//! | Member | Item |
//! |---|---|
//! | `verdicts` | `{ claim, verdict, evidence, basis: { complete, gaps, stopped_by? } }`, or `{ claim, error }` for a claim whose arguments do not resolve |
//! | `explanations` | the why tree of each ID: `{ id, fact, rule?, source?, premises, truncated?, cycle? }`, or `{ id, error }` |
//! | `rules` | `{ rule, doc }` for each rule of the trees, in code order |
//!
//! The arguments of a claim resolve by the column kinds of the relation catalog
//! ([`ghidorah_analysis::facts::CATALOG`]). A `fn` argument uses the function family of the
//! target table (design Section 10.5). When the analysis is not complete, a `refuted` verdict
//! changes to `unknown`, because a negative verdict is not sound on a partial analysis.

use ghidorah_analysis::facts::NAMES;
use ghidorah_json::Object;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The largest number of claims of one call.
pub const MAX_CLAIMS: usize = 20;

/// The largest number of fact IDs of one call.
pub const MAX_EXPLAIN: usize = 10;

/// The largest number of arguments of one claim.
pub const MAX_ARGS: usize = 3;

/// The longest fact ID.
pub const MAX_ID: usize = 1_024;

/// The largest number of evidence items and gaps of one verdict.
pub const MAX_ITEMS: usize = 20;

/// The fuel of the check of one claim.
pub const CLAIM_FUEL: u64 = 20_000_000;

/// The `why` of the hint that reads a gap.
pub const WHY_GAP: &str = "Read the site that blocks a refuted verdict.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_GAP];

const CLAIM_ARG: ArgSpec = ArgSpec::new(
    "arg",
    Role::Param,
    ArgKind::Json,
    "One argument: an ID, an address, a name, a glob, a reference kind or an integer.",
);

const CLAIM_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "rel",
        Role::Param,
        ArgKind::Enum(&NAMES),
        "The relation of the claim, for example calls.",
    )
    .required(),
    ArgSpec::new(
        "args",
        Role::Param,
        ArgKind::List(&CLAIM_ARG, MAX_ARGS),
        "The arguments of the relation in relation order.",
    )
    .required(),
];

const CLAIM: ArgSpec = ArgSpec::new(
    "claim",
    Role::Param,
    ArgKind::Obj(CLAIM_ARGS),
    "One claim: a relation and its arguments.",
);

const FACT_ID: ArgSpec = ArgSpec::new(
    "id",
    Role::Param,
    ArgKind::Str(MAX_ID),
    "One fact ID, for example fn:0x1149, ref:0x10a1>0x1060:unconditional_call or 0x1149.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "claims",
        Role::Param,
        ArgKind::List(&CLAIM, MAX_CLAIMS),
        "Up to 20 claims. Each claim gets the verdict supported, refuted or unknown.",
    ),
    ArgSpec::new(
        "explain",
        Role::Param,
        ArgKind::List(&FACT_ID, MAX_EXPLAIN),
        "Up to 10 fact IDs. The result gives the why tree of each fact.",
    ),
    ArgSpec::new(
        "depth",
        Role::Param,
        ArgKind::Int { min: 1, max: 10 },
        "The depth of each why tree in premise levels.",
    )
    .default_json("3"),
    ArgSpec::new(
        "max_nodes",
        Role::Param,
        ArgKind::Int { min: 1, max: 1_000 },
        "The largest number of nodes in all why trees.",
    )
    .default_json("200"),
];

const BASIS: &[Field] = &[
    Field::req("complete", OutputShape::Bool),
    Field::req("gaps", OutputShape::List(&OutputShape::Str)),
    Field::opt("stopped_by", OutputShape::Str),
];

const VERDICT: &[Field] = &[
    Field::req("claim", OutputShape::Any),
    Field::opt("verdict", OutputShape::Str),
    Field::opt("evidence", OutputShape::List(&OutputShape::Str)),
    Field::opt("basis", OutputShape::Obj(BASIS)),
    Field::opt("error", OutputShape::Any),
];

const RULE: &[Field] = &[
    Field::req("rule", OutputShape::Str),
    Field::req("doc", OutputShape::Str),
];

const FIELDS: &[Field] = &[
    Field::req("verdicts", OutputShape::List(&OutputShape::Obj(VERDICT))),
    Field::req("explanations", OutputShape::List(&OutputShape::Any)),
    Field::req("rules", OutputShape::List(&OutputShape::Obj(RULE))),
];

/// The claims of the first example: each relation of the catalog on the demo binary.
const EX_CLAIMS: &str = concat!(
    r#"{"claims":["#,
    r#"{"rel":"calls","args":["main","imp:puts"]},"#,
    r#"{"rel":"calls","args":["check_password","imp:puts"]},"#,
    r#"{"rel":"calls","args":["fn:0x1000","main"]},"#,
    r#"{"rel":"reaches","args":["main","imp:strlen",2]},"#,
    r#"{"rel":"uses_import","args":["check_password","imp:strlen"]},"#,
    r#"{"rel":"refs_string","args":["main","Access*"]},"#,
    r#"{"rel":"refs_addr","args":["main","0x202d"]},"#,
    r#"{"rel":"xref","args":["0x10a1","imp:puts","call"]},"#,
    r#"{"rel":"const_arg","args":["imp:puts",0,"str:0x202d"]},"#,
    r#"{"rel":"has_syscall","args":["main","sys:write"]},"#,
    r#"{"rel":"noreturn","args":["main"]},"#,
    r#"{"rel":"in_func","args":["0x10a1","main"]}"#,
    r#"]}"#
);

/// `fact_check`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Check claims and explain facts",
    summary: "Check claims with supported, refuted or unknown verdicts, and explain why a fact exists.",
    description: "Check claims with supported, refuted or unknown verdicts, and explain why a fact exists. \
                  Send claims with a relation and its arguments, for example calls with the arguments main and imp:puts. \
                  Send explain with fact IDs to get the why tree of each fact. \
                  A refuted verdict is sound: the facts that the relation reads are complete. \
                  An indirect call with no target gives unknown, and basis.gaps lists the sites that block a refuted verdict. \
                  Call func_edit with the action set_call_targets to give a site its targets.",
    args: ARGS,
    groups: &[Group {
        members: &["claims", "explain"],
        rule: GroupRule::AtLeastOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: EX_CLAIMS,
            golden: "tests/golden/tools/fact_check.1.json",
        },
        Example {
            args: r#"{"explain":["fn:0x11e0","ref:0x10a1>0x1060:unconditional_call"],"depth":2,"max_nodes":20}"#,
            golden: "tests/golden/tools/fact_check.2.json",
        },
    ],
    max_chars: crate::budget::LARGE_MAX_CHARS,
    ..ToolSpec::base("fact_check", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session.bound(&ctx.frame)?, args);
    Ok(Payload::Object(Object::new()))
}
