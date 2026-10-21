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

mod parse;
mod render;

use std::collections::BTreeMap;

use ghidorah_analysis::facts::explain::{DEFAULT_DEPTH, DEFAULT_NODES};
use ghidorah_analysis::facts::{
    Checker, ExplainError, Gap, NAMES, Outcome, Verdict, explain, key_of,
};
use ghidorah_base::{ErrorCode, Fuel};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};

pub use parse::atom;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::{Inactive, ToolError};
use crate::handlers::func_sections as fs;
use crate::hints::Call;
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
pub const MAX_ITEMS: usize = render::MAX_ITEMS;

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
    .default_json(text_of(&DEPTH_DIGITS)),
    ArgSpec::new(
        "max_nodes",
        Role::Param,
        ArgKind::Int { min: 1, max: 1_000 },
        "The largest number of nodes in all why trees.",
    )
    .default_json(text_of(&NODES_DIGITS)),
];

/// The digits of [`DEFAULT_DEPTH`]: the JSON default of `depth`.
const DEPTH_DIGITS: [u8; digit_count(DEFAULT_DEPTH as u64)] = digits(DEFAULT_DEPTH as u64);

/// The digits of [`DEFAULT_NODES`]: the JSON default of `max_nodes`.
const NODES_DIGITS: [u8; digit_count(DEFAULT_NODES as u64)] = digits(DEFAULT_NODES as u64);

/// Gives the number of decimal digits of `value`.
const fn digit_count(value: u64) -> usize {
    let mut count = 1;
    let mut rest = value / 10;
    while rest > 0 {
        count += 1;
        rest /= 10;
    }
    count
}

/// Gives the decimal digits of `value` in `N` bytes. `N` is the [`digit_count`] of `value`.
const fn digits<const N: usize>(value: u64) -> [u8; N] {
    let mut out = [b'0'; N];
    let mut rest = value;
    let mut at = N;
    while at > 0 {
        at -= 1;
        out[at] = match rest % 10 {
            0 => b'0',
            1 => b'1',
            2 => b'2',
            3 => b'3',
            4 => b'4',
            5 => b'5',
            6 => b'6',
            7 => b'7',
            8 => b'8',
            _ => b'9',
        };
        rest /= 10;
    }
    out
}

/// Gives `bytes` as text. Bytes that are not UTF-8 give empty text.
const fn text_of(bytes: &'static [u8]) -> &'static str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => "",
    }
}

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

/// Checks one claim on `program` and gives its verdict entry. A claim whose arguments do not
/// resolve gives `{ claim, error }`. On a partial analysis, `refuted` changes to `unknown`.
///
/// The `claim` guards of `batch_run` use the same function, so a guard and a direct call give
/// the same verdict. A guard reads only the verdict, so the hint of an error entry names only
/// tools of every profile ([`Inactive::any_profile`]).
#[must_use]
pub fn check_claim(checker: &mut Checker<'_>, claim: &Value, path: &str, partial: bool) -> Value {
    check_one(checker, claim, path, partial, &Inactive::any_profile()).0
}

/// Checks one claim. Gives the verdict entry and the outcome of a claim that resolves. The
/// hint of an error entry names no tool of `inactive`.
fn check_one(
    checker: &mut Checker<'_>,
    claim: &Value,
    path: &str,
    partial: bool,
    inactive: &Inactive,
) -> (Value, Option<Outcome>) {
    match atom(checker.program(), claim, path) {
        Ok(a) => {
            let mut out = checker.check(&a, &mut Fuel::new(CLAIM_FUEL));
            if partial {
                out.weaken();
            }
            (render::verdict(claim, &out, partial), Some(out))
        }
        Err(e) => (render::error("claim", claim, &e, inactive), None),
    }
}

/// Gives the error of a fact ID that does not explain.
fn explain_error(e: &ExplainError, path: &str) -> ToolError {
    match e {
        ExplainError::NotFound(kind) => ToolError::new(ErrorCode::NotFound)
            .var("kind", kind)
            .path(path)
            .detail("kind", Value::from(*kind)),
        ExplainError::BadId(_) => ToolError::new(ErrorCode::InvalidArgument)
            .var("field", path.strip_prefix('/').unwrap_or(path))
            .path(path)
            .detail(
                "expected",
                Value::from(
                    "a fact ID: fn:, ref:, str:, jt:, sym:, var:, imp:, exp:, note: or 0x hex",
                ),
            ),
    }
}

/// Gives the trees of the fact IDs `ids` and the rules of the trees. The hint of an error
/// entry names no tool of `inactive`.
fn trees(
    p: &Program,
    ids: &[Value],
    (depth, max_nodes): (u32, usize),
    inactive: &Inactive,
) -> (Vec<Value>, Value) {
    let mut rules = BTreeMap::new();
    let mut nodes = max_nodes;
    let mut out = Vec::with_capacity(ids.len());
    for (i, id) in ids.iter().enumerate() {
        let path = format!("/explain/{i}");
        let text = id.as_str().unwrap_or_default();
        match key_of(p, text) {
            Ok(key) => out.push(render::tree(
                &explain(p, &key, depth, &mut nodes),
                &mut rules,
            )),
            Err(e) => out.push(render::error("id", id, &explain_error(&e, &path), inactive)),
        }
    }
    (out, render::rules(&rules))
}

/// Gives the first site gap of an `unknown` verdict.
fn first_gap(out: &Outcome) -> Option<String> {
    if out.verdict != Verdict::Unknown {
        return None;
    }
    out.gaps.iter().find_map(|g| match g {
        Gap::Site(a) if a.is_ram() => Some(a.to_string()),
        _ => None,
    })
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    fs::x86_only(p)?;
    let partial = ctx.frame.partial();
    let mut checker = Checker::new(p);
    let mut verdicts = Vec::new();
    let mut gap = None;
    for (i, claim) in args.list("claims").unwrap_or_default().iter().enumerate() {
        let path = format!("/claims/{i}");
        let (entry, out) = check_one(&mut checker, claim, &path, partial, &ctx.inactive);
        if gap.is_none() {
            gap = out.as_ref().and_then(first_gap);
        }
        verdicts.push(entry);
    }
    let depth = args
        .int("depth")
        .and_then(|d| u32::try_from(d).ok())
        .unwrap_or(DEFAULT_DEPTH);
    let max_nodes = args
        .int("max_nodes")
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(DEFAULT_NODES);
    let (explanations, rules) = trees(
        p,
        args.list("explain").unwrap_or_default(),
        (depth, max_nodes),
        &ctx.inactive,
    );
    if let Some(at) = gap {
        ctx.hint(Call::new(
            "addr_info",
            Value::object([("target", Value::from(at))]),
            WHY_GAP,
        ));
    }
    let mut out = Object::new();
    out.push("verdicts", Value::Array(verdicts));
    out.push("explanations", Value::Array(explanations));
    out.push("rules", rules);
    Ok(Payload::Object(out))
}
