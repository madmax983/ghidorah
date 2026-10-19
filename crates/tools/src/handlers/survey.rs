//! `binary_survey`: survey a loaded binary (design Section 10.4, tool 2).
//!
//! The result has one member per included section, in the order of [`SECTIONS`]:
//!
//! | Section | Content |
//! |---|---|
//! | `identity` | file name, SHA-256, format, machine, kind, image base, entry, size, build ID |
//! | `protections` | the checksec flags of the loader, or `null` |
//! | `segments`, `sections` | the loader rows with IDs, starts, sizes and permissions |
//! | `imports` | the libraries, and the imports in groups by Tier-0 category |
//! | `exports` | the exports with their addresses |
//! | `strings` | the referenced strings, the most referenced first, with up to 3 functions each |
//! | `entries` | the entry points |
//! | `functions` | the counts by start reason, and the first functions in priority order |
//! | `syscalls` | the syscall numbers of the sites, with their site counts |
//! | `notes` | the ELF notes |
//! | `coverage` | the coverage counts and the first worklist items |
//! | `languages` | the C++, Rust and Go hints of design Section 9.6 |
//! | `diagnostics` | the loader diagnostics by code, with the first 5 places of each code |
//!
//! Budget: the sections share the envelope budget by the weights of [`weight`]. A section
//! that needs less gives the rest to the later sections. A list section that does not fit
//! keeps the first items that fit and gets `omitted: { count, next }`. `next` is the
//! `search` call that lists the rest, when a search kind exists for the section.
//!
//! On a binary for another machine, the code sections stay empty, and the result carries
//! `W_ARCH_UNSUPPORTED` (design Section 4.1).

mod imports;
mod parts;

use ghidorah_analysis::CallGraph;
use ghidorah_base::WarningCode;
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::content::{self, ContentMode};
use crate::dispatch::{Ctx, Payload};
use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Profile, Role, ToolSpec};

/// The sections in output order.
pub const SECTIONS: [&str; 14] = [
    "identity",
    "protections",
    "segments",
    "sections",
    "imports",
    "exports",
    "strings",
    "entries",
    "functions",
    "syscalls",
    "notes",
    "coverage",
    "languages",
    "diagnostics",
];

/// The largest number of functions in `functions.top`.
pub const TOP_FUNCTIONS: usize = 20;

/// The largest number of referencing functions of one string.
pub const STRING_FUNCS: usize = 3;

/// The largest number of places of one diagnostic code.
pub const DIAG_PLACES: usize = 5;

/// The largest number of worklist items in `coverage`.
pub const WORK_ITEMS: usize = 5;

/// The `why` of the `func_list` hint.
pub const WHY_PRIORITY: &str = "List the functions in priority order.";

/// The `why` of the `func_get` hint on `main`.
pub const WHY_MAIN: &str = "Read the main function.";

/// The `why` of a `search` call that lists the rest of a cut section.
pub const WHY_REST: &str = "List the items that the survey leaves out.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_PRIORITY, WHY_MAIN, WHY_REST];

/// Gives the budget weight of a section: 3 for `strings` and `functions`, 2 for `imports`
/// and `sections`, else 1.
#[must_use]
pub fn weight(section: &str) -> u64 {
    match section {
        "strings" | "functions" => 3,
        "imports" | "sections" => 2,
        _ => 1,
    }
}

const SECTION_ITEM: ArgSpec = ArgSpec::new(
    "section",
    Role::Param,
    ArgKind::Enum(&SECTIONS),
    "One section of the survey.",
);

const ARGS: &[ArgSpec] = &[ArgSpec::new(
    "include",
    Role::Param,
    ArgKind::List(&SECTION_ITEM, 14),
    "The sections of the survey in output order. The default is all 14 sections.",
)];

const FIELDS: &[Field] = &[
    Field::opt("identity", OutputShape::Any),
    Field::opt("protections", OutputShape::Any),
    Field::opt("segments", OutputShape::Any),
    Field::opt("sections", OutputShape::Any),
    Field::opt("imports", OutputShape::Any),
    Field::opt("exports", OutputShape::Any),
    Field::opt("strings", OutputShape::Any),
    Field::opt("entries", OutputShape::Any),
    Field::opt("functions", OutputShape::Any),
    Field::opt("syscalls", OutputShape::Any),
    Field::opt("notes", OutputShape::Any),
    Field::opt("coverage", OutputShape::Any),
    Field::opt("languages", OutputShape::Any),
    Field::opt("diagnostics", OutputShape::Any),
];

/// `binary_survey`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Survey a binary",
    summary: "Survey a loaded binary: identity, protections, sections, imports, strings, entry points, functions, syscalls and coverage.",
    description: "Survey a loaded binary: identity, protections, sections, imports, strings, entry points, functions, syscalls and coverage. \
                  Call it first after binary_load. \
                  A section that does not fit gives omitted with a search call for the rest. \
                  Send include to get fewer sections.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: "{}",
            golden: "tests/golden/tools/binary_survey.1.json",
        },
        Example {
            args: r#"{"include":["identity","protections","imports"]}"#,
            golden: "tests/golden/tools/binary_survey.2.json",
        },
    ],
    max_chars: crate::budget::SURVEY_MAX_CHARS,
    ..ToolSpec::base("binary_survey", run)
};

/// Gives the characters of the member `"name":value,` in the result.
fn member(mode: ContentMode, name: &str, value: &Value) -> u64 {
    content::cost(
        &format!("\"{name}\":{},", ghidorah_json::write(value)),
        mode,
    )
}

/// Gives the value of `part` that fits `share`: the whole section, else the first items of
/// its list that fit. A section with no list always comes whole.
fn fit(part: &parts::Part, name: &str, share: u64, mode: ContentMode) -> (Value, u64) {
    let n = part.list.len();
    let full = part.value(n);
    let need = member(mode, name, &full);
    if need <= share || part.key.is_none() {
        return (full, need);
    }
    let mut k = 0;
    let mut cost = member(mode, name, &part.value(0));
    for item in &part.list {
        let next = cost
            .saturating_add(content::cost(&ghidorah_json::write(item), mode))
            .saturating_add(mode.copies());
        if next > share {
            break;
        }
        cost = next;
        k += 1;
    }
    loop {
        let value = part.value(k);
        let exact = member(mode, name, &value);
        if exact <= share || k == 0 {
            return (value, exact);
        }
        k -= 1;
    }
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let binary = session.bound(&ctx.frame)?;
    let p = &binary.program;
    let include = included(args);
    let namer = Namer::new();
    let graph = CallGraph::build(p);
    let c = parts::Ctx {
        program: p,
        file_name: &binary.file_name,
        namer: &namer,
        caps: fs::caps(ctx),
    };
    let mode = ctx.budget.mode;
    let built: Vec<(&'static str, parts::Part)> = include
        .iter()
        .map(|name| (*name, parts::part(&c, name, &graph, &mut ctx.fuel)))
        .collect();
    // The members of each section without its list items come first. The list items then
    // share the rest by weight.
    let room = fs::room(ctx);
    let heads: Vec<u64> = built
        .iter()
        .map(|(name, part)| member(mode, name, &part.value(0)))
        .collect();
    let mut free =
        u128::from(room.saturating_sub(heads.iter().fold(0, |a: u64, h| a.saturating_add(*h))));
    let mut left: u128 = built
        .iter()
        .filter(|(_, part)| part.key.is_some())
        .map(|(name, _)| u128::from(weight(name)))
        .sum();
    let mut out = Object::new();
    for ((name, part), head) in built.iter().zip(&heads) {
        let w = if part.key.is_some() {
            u128::from(weight(name))
        } else {
            0
        };
        let share = u64::try_from(free.saturating_mul(w) / left.max(1)).unwrap_or(u64::MAX);
        left = left.saturating_sub(w);
        let (value, used) = fit(part, name, head.saturating_add(share), mode);
        free = free.saturating_sub(u128::from(used.saturating_sub(*head)));
        out.push(*name, value);
    }
    // A budget below the fixed members drops whole sections from the end.
    while fs::chars(ctx, &Value::Object(out.clone())) > room && !out.is_empty() {
        let last = out
            .members()
            .last()
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        let _ = out.remove(&last);
    }
    let id = Value::from(binary.id.to_string());
    let main = p
        .funcs()
        .iter()
        .find(|f| p.name(f.id().0).is_some_and(|n| n.text == "main"))
        .map(ghidorah_db::FuncView::id);
    let x86 = p.meta().arch.is_x86_64();
    namer.finish(ctx);
    if !x86 {
        ctx.warn(Warning::new(WarningCode::ArchUnsupported));
    }
    ctx.hint(Call::new(
        "func_list",
        Value::object([("binary_id", id.clone()), ("sort", Value::from("priority"))]),
        WHY_PRIORITY,
    ));
    if let Some(main) = main {
        ctx.hint(Call::new(
            "func_get",
            Value::object([("binary_id", id), ("target", Value::from(main.to_string()))]),
            WHY_MAIN,
        ));
    }
    Ok(Payload::Object(out))
}

/// Gives the included sections of the call in output order.
#[must_use]
pub fn included(args: &Args) -> Vec<&'static str> {
    let Some(list) = args.list("include") else {
        return SECTIONS.to_vec();
    };
    SECTIONS
        .iter()
        .filter(|s| list.iter().any(|v| v.as_str() == Some(**s)))
        .copied()
        .collect()
}
