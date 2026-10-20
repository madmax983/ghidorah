//! `func_get`: get one or more functions with selected sections (design Section 10.4, tool 5).
//!
//! The result of one function is `{ id, name, entry, size, parts, signature, start_reason,
//! confidence, flags, caveats, <sections>, omitted? }`. [`super::func_sections`] renders the
//! sections. With `targets`, the result is `{ items: [{ input, ok, data | error }],
//! ok_count, error_count }` in input order, and one bad item never fails the call (AC-144).
//!
//! Budget (design Section 10.9): with `targets`, the budget first splits evenly per target.
//! The sections of one function split their part by weight in include order: `disasm` 3,
//! `ir` 3, every other section 1. A section that needs less gives the rest to the later
//! sections. A row section that does not fit keeps the rows that fit and gets a
//! `next_cursor`. Send it in `cursors` for the next rows (AC-154b). Another section that
//! does not fit goes to `omitted` with its exact size (AC-154a).
//!
//! A call with `disasm` or `ir` marks the function `visited`. The mark changes no fact and no
//! `rev`.

pub mod remedy;
mod render;

use ghidorah_analysis::CallGraph;
use ghidorah_base::{BinaryId, ErrorCode, FuncId, WarningCode};
use ghidorah_db::{FuncProgress, MetaLine, Program};
use ghidorah_json::Value;

use self::render::{Cursors, Job, Marks, cursors, one};
use super::func_sections::{self as fs, Namer, Render};
use crate::args::{Args, Format};
use crate::budget::split_even;
use crate::dispatch::{Ctx, Payload};
use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The sections of `func_get` in schema order.
pub const SECTIONS: [&str; 13] = [
    "summary",
    "disasm",
    "ir",
    "decomp",
    "xrefs",
    "callers",
    "callees",
    "strings",
    "vars",
    "notes",
    "why",
    "cfg",
    "jumptables",
];

/// The IR levels of `ir_opts.level`.
pub const IR_LEVELS: [&str; 2] = ["l0", "l1"];

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 50;

/// The default number of disassembly rows.
pub const DEFAULT_DISASM_LIMIT: i64 = 200;

/// The largest number of disassembly rows.
pub const MAX_DISASM_LIMIT: i64 = 2_000;

const SECTION_ITEM: ArgSpec = ArgSpec::new(
    "section",
    Role::Param,
    ArgKind::Enum(&SECTIONS),
    "One section of the function.",
);

const CURSORS: &[ArgSpec] = &[
    ArgSpec::new(
        "disasm",
        Role::Param,
        ArgKind::Str(1_024),
        "The disasm.next_cursor of the previous call.",
    ),
    ArgSpec::new(
        "ir",
        Role::Param,
        ArgKind::Str(1_024),
        "The ir.next_cursor of the previous call.",
    ),
    ArgSpec::new(
        "decomp",
        Role::Param,
        ArgKind::Str(1_024),
        "The decomp.next_cursor of the previous call.",
    ),
];

const IR_OPTS: &[ArgSpec] = &[ArgSpec::new(
    "level",
    Role::Param,
    ArgKind::Enum(&IR_LEVELS),
    "The IR level: l0 for the lifted ops, l1 for the SSA form after the passes.",
)
.default_json("\"l0\"")];

/// The largest number of lines of one decompile window.
pub const MAX_LINES: i64 = 1_000;

const LINES: &[ArgSpec] = &[
    ArgSpec::new(
        "start",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: 1_000_000,
        },
        "The number of the first line, from 1.",
    )
    .default_json("1"),
    ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_LINES,
        },
        "The largest number of lines.",
    )
    .default_json("150"),
];

const PASSES: &[ArgSpec] = &[
    ArgSpec::new(
        "fold",
        Role::Param,
        ArgKind::Bool,
        "Put each value with one use into its use.",
    )
    .default_json("true"),
    ArgSpec::new(
        "sailr",
        Role::Param,
        ArgKind::Bool,
        "Run the SAILR-lite passes: canary removal, noreturn calls and tail calls.",
    )
    .default_json("true"),
    ArgSpec::new(
        "canary",
        Role::Param,
        ArgKind::Bool,
        "Remove the stack canary check. It needs sailr.",
    )
    .default_json("true"),
    ArgSpec::new(
        "tailcall",
        Role::Param,
        ArgKind::Bool,
        "Show a tail jump as return f(..). It needs sailr.",
    )
    .default_json("true"),
];

const DECOMP_OPTS: &[ArgSpec] = &[
    ArgSpec::new(
        "lines",
        Role::Param,
        ArgKind::Obj(LINES),
        "The window of lines to return.",
    ),
    ArgSpec::new(
        "passes",
        Role::Param,
        ArgKind::Obj(PASSES),
        "The decompiler passes to turn on or off.",
    ),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The function: an address in its body, a name or a fn: ID.",
    )
    .aliases(&["id", "addr", "address", "function"]),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 50 functions. Each item gets its own result.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&SECTION_ITEM, 13),
        "The sections to return in this order.",
    )
    .default_json("[\"summary\"]"),
    ArgSpec::new(
        "ir_opts",
        Role::Param,
        ArgKind::Obj(IR_OPTS),
        "The options of the ir section.",
    ),
    ArgSpec::new(
        "decomp_opts",
        Role::Param,
        ArgKind::Obj(DECOMP_OPTS),
        "The options of the decomp section: the window of lines and the passes.",
    ),
    ArgSpec::new(
        "disasm_limit",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_DISASM_LIMIT,
        },
        "The largest number of disassembly rows.",
    )
    .default_json("200"),
    ArgSpec::new(
        "cursors",
        Role::Param,
        ArgKind::Obj(CURSORS),
        "The section cursors of the previous call, to get the next rows of a section.",
    ),
];

const FIELDS: &[Field] = &[
    Field::opt("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::opt("name", OutputShape::Str),
    Field::opt("entry", OutputShape::Addr),
    Field::opt("size", OutputShape::Int),
    Field::opt("parts", OutputShape::Any),
    Field::opt("signature", OutputShape::Any),
    Field::opt("start_reason", OutputShape::Str),
    Field::opt("confidence", OutputShape::Int),
    Field::opt("flags", OutputShape::List(&OutputShape::Str)),
    Field::opt("caveats", OutputShape::Any),
    Field::opt("summary", OutputShape::Any),
    Field::opt("disasm", OutputShape::Any),
    Field::opt("ir", OutputShape::Any),
    Field::opt("decomp", OutputShape::Any),
    Field::opt("xrefs", OutputShape::Any),
    Field::opt("callers", OutputShape::Any),
    Field::opt("callees", OutputShape::Any),
    Field::opt("strings", OutputShape::Any),
    Field::opt("vars", OutputShape::Any),
    Field::opt("notes", OutputShape::Any),
    Field::opt("why", OutputShape::Any),
    Field::opt("cfg", OutputShape::Any),
    Field::opt("jumptables", OutputShape::Any),
    Field::opt("omitted", OutputShape::Any),
    Field::opt("budgets", OutputShape::Any),
    Field::opt("items", OutputShape::Any),
    Field::opt("ok_count", OutputShape::Int),
    Field::opt("error_count", OutputShape::Int),
];

/// `func_get`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Get functions",
    summary: "Get one or more functions with selected sections: summary, disassembly, IR, decompiled C, xrefs, callers, callees, strings, variables, notes, why, CFG and jump tables.",
    description: "Get one or more functions with selected sections: summary, disassembly, IR, decompiled C, xrefs, callers, callees, strings, variables, notes, why, CFG and jump tables. \
                  Send target, or targets for up to 50 functions. \
                  The sections share max_chars by weight. A cut section gives next_cursor: send it in cursors. \
                  A call with disasm, ir or decomp marks the function as visited, and this mark changes no fact.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "targets"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"target":"main"}"#,
            golden: "tests/golden/tools/func_get.1.json",
        },
        Example {
            args: r#"{"target":"fn:0x1080","include":["disasm","callees"],"disasm_limit":8}"#,
            golden: "tests/golden/tools/func_get.2.json",
        },
        Example {
            args: r#"{"targets":["main","0x11e0"],"include":["summary","strings"]}"#,
            golden: "tests/golden/tools/func_get.3.json",
        },
        Example {
            args: r#"{"target":"main","include":["decomp"],"decomp_opts":{"lines":{"start":1,"count":40}}}"#,
            golden: "tests/golden/tools/func_get.4.json",
        },
    ],
    max_chars: crate::budget::LARGE_MAX_CHARS,
    ..ToolSpec::base("func_get", run)
};

/// The smallest share of a section that the handler renders. A section with a smaller
/// share goes to `omitted` with `null`.
pub const MIN_SHARE: u64 = 48;

/// The characters of the wrapper of one item of a `targets` result.
const ITEM_WRAPPER: u64 = 64;

/// Gives the sections of the call in include order.
fn included(args: &Args) -> Vec<&'static str> {
    let names: Vec<&str> = args
        .list("include")
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut out: Vec<&'static str> = Vec::new();
    for name in names {
        if let Some(s) = SECTIONS.iter().find(|s| **s == name)
            && !out.contains(s)
        {
            out.push(s);
        }
    }
    if out.is_empty() && !args.given("include") {
        out.push("summary");
    }
    out
}

/// Gives the function of one target input, or `NOT_FOUND` for an ID of no function.
fn func_of(program: &Program, input: &Value, path: &str) -> Result<FuncId, ToolError> {
    let (func, _) = crate::resolve::function(program, input, &fs::site(path))?;
    if program.func(func).is_none() {
        return Err(ToolError::new(ErrorCode::NotFound)
            .var("kind", "function")
            .path(path)
            .detail("kind", Value::from("function")));
    }
    Ok(func)
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let (data, marks, id) = {
        let binary = session.bound(&ctx.frame)?;
        let program = &binary.program;
        fs::x86_only(program)?;
        let include = included(args);
        let namer = Namer::new();
        let graph = CallGraph::build(program);
        let limit = args.int("disasm_limit").unwrap_or(DEFAULT_DISASM_LIMIT);
        let frame = ctx.frame.clone();
        let mut job = Job {
            render: Render {
                program,
                graph: &graph,
                namer: &namer,
                caps: fs::caps(ctx),
            },
            include: &include,
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            cursors: Cursors::default(),
            session,
            frame: &frame,
            args,
            mode: ctx.budget.mode,
            detailed: ctx.format == Format::Detailed,
            decomp: fs::decomp_opts(args),
            ir_l1: args
                .get("ir_opts")
                .and_then(|o| o.get("level"))
                .and_then(Value::as_str)
                == Some("l1"),
        };
        job.cursors = cursors(&job).map_err(|e| first_rows(args, e))?;
        let room = fs::room(ctx);
        let mut marks = Marks::default();
        let data = if let Some(targets) = args.list("targets") {
            let n = targets.len().max(1);
            let wrap = ITEM_WRAPPER.saturating_mul(u64::try_from(n).unwrap_or(u64::MAX));
            let shares = split_even(room.saturating_sub(wrap), n);
            let fuel = &mut ctx.fuel;
            let out = fs::per_item("targets", targets, |i, input| {
                let path = fs::item_path("targets", i);
                let func = func_of(program, input, &path)?;
                let share = shares.get(i).copied().unwrap_or(0);
                one(&job, func, share, fuel, &mut marks)
            });
            Value::Object(out)
        } else {
            let input = args.get("target").cloned().unwrap_or_default();
            let func = func_of(program, &input, "/target")?;
            one(&job, func, room, &mut ctx.fuel, &mut marks)?
        };
        namer.finish(ctx);
        (data, marks, binary.id)
    };
    for at in &marks.intrinsic {
        let mut warning = Warning::new(WarningCode::LiftUnsupported);
        warning.at = Some(ghidorah_base::hex::u64_text(*at));
        ctx.warn(warning);
    }
    mark_visited(session, id, &marks.visited);
    match data {
        Value::Object(object) => Ok(Payload::Object(object)),
        _ => Err(ToolError::new(ErrorCode::InternalError)),
    }
}

/// Marks each function of `funcs` as visited. A failed journal write keeps the mark in
/// memory, so the read still succeeds.
fn mark_visited(session: &mut Session, id: BinaryId, funcs: &[FuncId]) {
    for func in funcs {
        let Some(row) = session.binary(id).map(|b| b.program.progress().get(*func)) else {
            return;
        };
        if row.visited {
            continue;
        }
        let line = MetaLine::Progress {
            func: *func,
            row: FuncProgress {
                visited: true,
                ..row
            },
        };
        let _ = session.write_meta(id, &line);
    }
}

/// Adds the repair call of a cursor error: the call without `cursors`.
fn first_rows(args: &Args, error: ToolError) -> ToolError {
    let mut object = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = object.remove("cursors");
    error.next(Call::new(
        "func_get",
        Value::Object(object),
        fs::WHY_FIRST_ROWS,
    ))
}
