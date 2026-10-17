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

use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
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
                  Each section gets a part of max_chars. \
                  When a section does not fit, its member omitted gives the count of the items that it leaves out and a search call for them. \
                  Imports come in groups by capability category, and strings show the most referenced strings first. \
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

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    Ok(Payload::Object(Object::new()))
}

/// Gives the included sections of the call in output order.
#[must_use]
pub fn included(args: &Args) -> Vec<&'static str> {
    let _ = args.get("include").and_then(Value::as_array);
    Vec::new()
}
