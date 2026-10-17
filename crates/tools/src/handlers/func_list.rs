//! `func_list`: list and filter the functions (design Section 10.4, tool 4).
//!
//! Each item is `{ id, addr, name, size, start_reason, confidence, flags, callers, callees,
//! caveats, visited, named }`. `flags` lists `noreturn`, `thunk` and `varargs`. `caveats`
//! lists the warning codes of the caveats.
//!
//! | `sort` | Order | Sort key |
//! |---|---|---|
//! | `addr` (default) | entry, low first | `(addr)` |
//! | `name` | name, then entry | `(name, addr)` |
//! | `size` | size, large first | `(rank, addr)` |
//! | `priority` | the frozen priority of design Section 7.11 | `(rank, addr)` |
//! | `in_degree` | references to the entry from outside the body, many first | `(rank, addr)` |
//!
//! The rank of a descending sort is `u64::MAX` minus the value, or the priority position.
//! `priority` reads only the analysis layer, so names, comments and `visited` never change it
//! (AC-157). The filter `visited` is a live filter.

use std::collections::BTreeMap;

use ghidorah_analysis::analyzers::metrics;
use ghidorah_analysis::{CallGraph, Callee};
use ghidorah_base::{FuncId, Glob};
use ghidorah_db::{FuncView, Program, StartReason};
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, Item, KeyPart, ListPayload, Payload, SortKey};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, ListSpec, Profile, Role, ToolSpec};

/// The default page size of `func_list`.
pub const DEFAULT_LIMIT: u32 = 100;

/// The sort orders.
pub const SORTS: [&str; 5] = ["addr", "name", "size", "priority", "in_degree"];

/// The page hint of a long result.
pub const HINT_NARROW: &str =
    "Add filter.name, filter.min_confidence or filter.calls to narrow the list.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW];

/// The names of the start reasons in the order of design Section 7.3.
const REASONS: [&str; 10] = [
    StartReason::Entry.name(),
    StartReason::Symbol.name(),
    StartReason::PltStub.name(),
    StartReason::Main.name(),
    StartReason::Pdata.name(),
    StartReason::Fde.name(),
    StartReason::Call.name(),
    StartReason::TailCall.name(),
    StartReason::Endbr.name(),
    StartReason::Agent.name(),
];

const REASON_ITEM: ArgSpec = ArgSpec::new(
    "reason",
    Role::Param,
    ArgKind::Enum(&REASONS),
    "One start reason.",
);

const SIZE: ArgKind = ArgKind::Int {
    min: 0,
    max: 9_007_199_254_740_991,
};

const FILTER: &[ArgSpec] = &[
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(256),
        "A glob for the name, for example parse_*.",
    ),
    ArgSpec::new(
        "min_confidence",
        Role::Param,
        ArgKind::Int { min: 0, max: 100 },
        "The lowest confidence, 0 to 100.",
    ),
    ArgSpec::new(
        "start_reason",
        Role::Param,
        ArgKind::List(&REASON_ITEM, 10),
        "Keep the functions with one of these start reasons.",
    ),
    ArgSpec::new(
        "visited",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions that a func_get call read, or the others.",
    ),
    ArgSpec::new(
        "named",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a real name, or the functions with a default name.",
    ),
    ArgSpec::new(
        "typed",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a signature, or the others.",
    ),
    ArgSpec::new(
        "has_caveat",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a caveat, or the others.",
    ),
    ArgSpec::new(
        "calls",
        Role::Param,
        ArgKind::Str(256),
        "A glob for the name of an import that the function calls, for example recv*.",
    ),
    ArgSpec::new("size_min", Role::Param, SIZE, "The smallest size in bytes."),
    ArgSpec::new("size_max", Role::Param, SIZE, "The largest size in bytes."),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "filter",
        Role::Param,
        ArgKind::Obj(FILTER),
        "The filters. A function must pass every filter of the object.",
    ),
    ArgSpec::new(
        "sort",
        Role::Param,
        ArgKind::Enum(&SORTS),
        "The order of the list. The value priority gives the most interesting functions first.",
    )
    .default_json("\"addr\""),
];

const ITEM: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("addr", OutputShape::Addr),
    Field::req("name", OutputShape::Str),
    Field::req("size", OutputShape::Int),
    Field::req("start_reason", OutputShape::Str),
    Field::req("confidence", OutputShape::Int),
    Field::req("flags", OutputShape::List(&OutputShape::Str)),
    Field::req("callers", OutputShape::Int),
    Field::req("callees", OutputShape::Int),
    Field::req("caveats", OutputShape::List(&OutputShape::Str)),
    Field::req("visited", OutputShape::Bool),
    Field::req("named", OutputShape::Bool),
];
const ITEM_SHAPE: OutputShape = OutputShape::Obj(ITEM);
const FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::List(&ITEM_SHAPE)),
    Field::opt("cols", OutputShape::List(&OutputShape::Str)),
    Field::opt(
        "rows",
        OutputShape::List(&OutputShape::List(&OutputShape::Any)),
    ),
    Field::opt("count", OutputShape::Int),
];

/// `func_list`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "List the functions",
    summary: "List and filter the functions of a binary, and sort them by address, name, size or priority.",
    description: "List and filter the functions of a binary, and sort them by address, name, size or priority. \
                  Each item gives the ID, the entry, the name, the size, the start reason, the confidence, the counts of callers and callees, and the caveats. \
                  The sort priority puts functions with risky imports, many references and strings first. \
                  Each analysis run fixes the priority order, so names and visits do not change it. \
                  Send filter to narrow the list, and cursor for the next page.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"sort":"priority","limit":5}"#,
            golden: "tests/golden/tools/func_list.1.json",
        },
        Example {
            args: r#"{"filter":{"name":"*pass*"}}"#,
            golden: "tests/golden/tools/func_list.2.json",
        },
    ],
    max_chars: crate::budget::LIST_MAX_CHARS,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("func_list", run)
};

/// The filters of one call.
struct Filter {
    name: Option<Glob>,
    min_confidence: Option<u8>,
    reasons: Vec<String>,
    visited: Option<bool>,
    named: Option<bool>,
    typed: Option<bool>,
    has_caveat: Option<bool>,
    calls: Option<Glob>,
    size_min: Option<u64>,
    size_max: Option<u64>,
}

impl Filter {
    /// Reads the filters of the call.
    fn of(args: &Args) -> Result<Self, ToolError> {
        let f = args.get("filter");
        let text = |k: &str| f.and_then(|f| f.get(k)).and_then(Value::as_str);
        let flag = |k: &str| f.and_then(|f| f.get(k)).and_then(Value::as_bool);
        let int = |k: &str| f.and_then(|f| f.get(k)).and_then(Value::as_u64);
        let reasons = f
            .and_then(|f| f.get("start_reason"))
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        Ok(Self {
            name: text("name")
                .map(|g| fs::glob(g, "/filter/name"))
                .transpose()?,
            min_confidence: int("min_confidence").and_then(|c| u8::try_from(c).ok()),
            reasons,
            visited: flag("visited"),
            named: flag("named"),
            typed: flag("typed"),
            has_caveat: flag("has_caveat"),
            calls: text("calls")
                .map(|g| fs::glob(g, "/filter/calls"))
                .transpose()?,
            size_min: int("size_min"),
            size_max: int("size_max"),
        })
    }

    /// Tells if the function `f` with `name`, `size` and its facts passes every filter.
    fn keeps(&self, p: &Program, graph: &CallGraph, f: &FuncView<'_>, name: &Facts) -> bool {
        let func = f.func;
        let calls_ok = self.calls.as_ref().is_none_or(|g| {
            graph.callees(f.id()).iter().any(|c| match c {
                Callee::Import(i) => i.name().is_some_and(|n| g.matches(n)),
                Callee::Func(_) => false,
            })
        });
        self.name.as_ref().is_none_or(|g| g.matches(&name.raw))
            && self.min_confidence.is_none_or(|c| func.confidence >= c)
            && (self.reasons.is_empty()
                || self.reasons.iter().any(|r| r == func.start_reason.name()))
            && self
                .visited
                .is_none_or(|v| p.progress().get(f.id()).visited == v)
            && self.named.is_none_or(|v| name.named == v)
            && self.typed.is_none_or(|v| f.sig.is_some() == v)
            && self.has_caveat.is_none_or(|v| func.caveats.is_empty() != v)
            && self.size_min.is_none_or(|m| name.size >= m)
            && self.size_max.is_none_or(|m| name.size <= m)
            && calls_ok
    }
}

/// The name and size facts of one function.
struct Facts {
    raw: String,
    named: bool,
    size: u64,
}

/// Gives the number of references to the entry of `f` from outside its body.
fn in_degree(p: &Program, f: &FuncView<'_>) -> u64 {
    let refs = p.refs_to(f.id().0);
    let outside = refs
        .iter()
        .filter(|r| {
            let from = r.value.key.from;
            !(from.is_ram() && f.func.body.contains(from.off))
        })
        .count();
    u64::try_from(outside).unwrap_or(u64::MAX)
}

/// Gives the item of one function.
fn item(p: &Program, graph: &CallGraph, f: &FuncView<'_>, facts: &Facts, namer: &Namer) -> Value {
    let func = f.func;
    let id = f.id();
    let mut flags = Vec::new();
    if f.noreturn.is_some_and(|n| n.value) {
        flags.push(Value::from("noreturn"));
    }
    if func.flags.thunk {
        flags.push(Value::from("thunk"));
    }
    if func.flags.varargs {
        flags.push(Value::from("varargs"));
    }
    let caveats = func
        .caveats
        .iter()
        .map(|c| Value::from(c.code.info().name))
        .collect();
    let callers = graph.callers(&Callee::Func(id)).len();
    let mut out = Object::new();
    out.push("id", Value::from(id.to_string()));
    out.push("addr", fs::addr(id.0));
    out.push("name", Value::from(namer.text(&facts.raw)));
    out.push("size", Value::from(facts.size));
    out.push("start_reason", Value::from(func.start_reason.name()));
    out.push("confidence", Value::from(func.confidence));
    out.push("flags", Value::Array(flags));
    out.push("callers", Value::from(callers));
    out.push("callees", Value::from(graph.callees(id).len()));
    out.push("caveats", Value::Array(caveats));
    out.push("visited", Value::Bool(p.progress().get(id).visited));
    out.push("named", Value::Bool(facts.named));
    Value::Object(out)
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let filter = Filter::of(args)?;
    let sort = args.str("sort").unwrap_or("addr");
    let graph = CallGraph::build(p);
    let namer = Namer::new();
    let ranks: BTreeMap<FuncId, u64> = metrics::priority(p)
        .iter()
        .enumerate()
        .map(|(i, r)| (r.func, u64::try_from(i).unwrap_or(u64::MAX)))
        .collect();
    let mut items = Vec::new();
    for f in p.funcs() {
        let id = f.id();
        let name = p.name(id.0);
        let facts = Facts {
            raw: name
                .as_ref()
                .map_or_else(|| id.0.to_string(), |n| n.text.clone()),
            named: name.is_some_and(|n| !n.is_default()),
            size: u64::try_from(f.func.size()).unwrap_or(u64::MAX),
        };
        if !filter.keeps(p, &graph, &f, &facts) {
            continue;
        }
        let addr = KeyPart::Int(id.0.off);
        let key = match sort {
            "name" => vec![KeyPart::Text(facts.raw.clone()), addr],
            "size" => vec![KeyPart::Int(u64::MAX - facts.size), addr],
            "priority" => vec![
                KeyPart::Int(ranks.get(&id).copied().unwrap_or(u64::MAX)),
                addr,
            ],
            "in_degree" => vec![KeyPart::Int(u64::MAX - in_degree(p, &f)), addr],
            _ => vec![addr],
        };
        items.push(Item {
            key: SortKey(key),
            value: item(p, &graph, &f, &facts, &namer),
        });
    }
    namer.finish(ctx);
    let mut list = ListPayload::new(items);
    list.narrow = Some(HINT_NARROW.to_owned());
    Ok(Payload::List(list))
}
