//! `binary_load`: load a binary (design Section 10.4, tool 1).
//!
//! Exactly one of `path`, `builtin` and `binary_id` names the binary:
//!
//! | Argument | Source |
//! |---|---|
//! | `path` | a file under a root (Section 10.16, AC-147) |
//! | `builtin` | a built-in binary of [`crate::demo`] with no root check |
//! | `binary_id` | a binary that is open in the session, or a project in the projects root |
//!
//! The load probes the format, maps the file and makes the program. A binary that is open
//! already gives `already_loaded: true` and no second copy. The binary ID is the hash of the
//! bytes, so a binary keeps the load settings (`file_format`, `base`, `entry`) of its first
//! load. Other settings give `INVALID_ARGUMENT` with `details.reason: "load_spec_differs"`. A session with a projects root
//! opens the project of the binary, or makes a new one (design Section 3.10). A reopen by
//! `binary_id` reads only the input copy of the project, with no root check.
//!
//! With an analysis engine in the session, the load then runs the analysis within
//! `max_steps`, in fuel slices with one progress report per slice. A cancel stops the run at
//! the next slice end, and the load stays. A project with a current analysis needs no run. A
//! project with changed analysis inputs starts a re-analysis. Without an engine, the analysis
//! state is `none`. A dry run loads the file and reports it, but opens nothing.
//!
//! A default projects root inside a git working tree keeps no project (ADR-0022). Then the
//! result holds `persisted: false` and `persist_reason`, so the agent knows that its edits
//! stay in memory only.
//!
//! A project lock of a process that is not alive gives `PROJECT_LOCKED` with `stale: true`.
//! Then `next[0]` is the same call with `break_lock: true`. The flag holds for that call only,
//! and the lock code replaces only a stale lock.

use std::collections::BTreeMap;

use ghidorah_base::{BinaryId, DiagCode, ErrorCode, WarningCode, hex};
use ghidorah_db::{LoadSpec, Program};
use ghidorah_json::{Object, Value};
use ghidorah_loader::{
    self as loader, Detected, Diagnostic, EntryKind, Kind, LoadError, LoadOpts, probe,
};

use super::func_sections::safe;
use crate::args::Args;
use crate::demo::builtin;
use crate::dispatch::{Ctx, Payload};
use crate::envelope::{Mutation, Warning};
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::session::{Admitted, OpenBinary, Session, Store, Until};
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

/// The `why` of the `binary_survey` hint after a load.
pub const WHY_SURVEY: &str = "Survey the binary that the call loaded.";

/// The `why` of the repair call of a stale project lock.
pub const WHY_BREAK_LOCK: &str = "The owner of the project lock is not alive. Send the call again with break_lock true to replace the lock.";

/// The `why` of the repair call of a load with other load settings than the first load.
pub const WHY_STORED_SPEC: &str = "Open the binary with the load settings of its first load.";

/// The `details.expected` of a load with other load settings than the first load.
pub const EXPECTED_STORED_SPEC: &str = "the load settings of details.stored";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[
    WHY_SURVEY,
    WHY_BREAK_LOCK,
    WHY_STORED_SPEC,
    EXPECTED_STORED_SPEC,
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "path",
        Role::Param,
        ArgKind::Str(MAX_PATH_CHARS),
        "The path of the file. A relative path starts at each root of the server in order. The first match is the file.",
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
        "The ID of a binary that is open in the session, or of a project on disk.",
    ),
    ArgSpec::new(
        "file_format",
        Role::Param,
        ArgKind::Enum(&["auto", "elf", "pe", "raw"]),
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
    ArgSpec::new(
        "break_lock",
        Role::Param,
        ArgKind::Bool,
        "Replace a stale project lock: a lock whose owner process is not alive. A live owner keeps its lock.",
    )
    .default_json("false"),
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
    Field::opt("persisted", OutputShape::Bool),
    Field::opt("persist_reason", OutputShape::Str),
    Field::req("analysis", OutputShape::Obj(ANALYSIS)),
    Field::req("diagnostics", OutputShape::Obj(DIAGNOSTICS)),
];

/// `binary_load`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Load a binary",
    summary: "Load a binary for analysis: an ELF or PE file under a root, a raw blob, the built-in demo or an open binary by its ID.",
    description: "Load a binary for analysis: an ELF or PE file under a root, a raw blob, the built-in demo or an open binary by its ID. \
                  Send exactly one of path, builtin and binary_id. \
                  Send file_format raw and base for a blob of x86-64 code. \
                  The analysis runs after the load within max_steps. \
                  Use the binary_id of the result in later calls.",
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
            args: r#"{"path":"fixtures/bin/two_helpers.gcc-O2","file_format":"elf","analysis":"none"}"#,
            golden: "tests/golden/tools/binary_load.2.json",
        },
        Example {
            args: r#"{"path":"fixtures/bin/hello.gcc-O2","file_format":"raw","arch":"x86_64","base":"0x400000","entry":"0x401040","analysis":"triage"}"#,
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

/// Gives the error of a failed load (Section 4.8).
fn load_error(error: &LoadError) -> ToolError {
    match error {
        LoadError::TooLarge { size, limit } => ToolError::new(ErrorCode::LimitExceeded)
            .detail("size", Value::from(*size))
            .detail("limit", Value::from(*limit)),
        LoadError::UnsupportedFormat {
            detected,
            supported,
        } => ToolError::new(ErrorCode::UnsupportedFormat)
            .detail("detected", Value::from(detected.as_str()))
            .detail(
                "supported",
                Value::Array(supported.iter().map(|s| Value::from(*s)).collect()),
            ),
        LoadError::Malformed(diag) => malformed(diag),
    }
}

/// Gives `FORMAT_MALFORMED` with `details.diagnostic`.
fn malformed(diag: &Diagnostic) -> ToolError {
    let mut out = Object::new();
    out.push("code", Value::from(diag.code.name()));
    out.push("path", Value::from(diag.path.as_str()));
    let hexes = [
        ("offset", diag.offset),
        ("need", diag.need),
        ("have", diag.have),
    ];
    for (key, value) in hexes {
        if let Some(v) = value {
            out.push(key, Value::from(hex::u64_text(v)));
        }
    }
    ToolError::new(ErrorCode::FormatMalformed).detail("diagnostic", Value::Object(out))
}

/// Reads an address argument of a raw load: a JSON integer or `0x` hex text.
fn raw_addr(args: &Args, name: &str) -> Result<Option<u64>, ToolError> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(text) => hex::parse_u64(text.trim()),
        _ => None,
    };
    parsed.map(Some).ok_or_else(|| {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", name)
            .path(&format!("/{name}"))
            .detail("expected", Value::from("a 0x hex address"))
    })
}

/// Gives the load settings of the call.
fn load_opts(args: &Args) -> Result<LoadOpts, ToolError> {
    let raw = args.str("file_format") == Some("raw");
    if !raw {
        if let Some(name) = ["base", "entry"].into_iter().find(|n| args.given(n)) {
            return Err(ToolError::new(ErrorCode::InvalidArgument)
                .var("field", name)
                .path(&format!("/{name}"))
                .detail(
                    "expected",
                    Value::from("no base and no entry, except with file_format raw"),
                ));
        }
        return Ok(LoadOpts::AUTO);
    }
    let Some(base) = raw_addr(args, "base")? else {
        return Err(ToolError::new(ErrorCode::MissingArgument)
            .var("field", "base")
            .path("/base")
            .detail(
                "example",
                Value::object([
                    ("path", Value::from("blob.bin")),
                    ("file_format", Value::from("raw")),
                    ("base", Value::from("0x400000")),
                ]),
            ));
    };
    Ok(LoadOpts::raw(base, raw_addr(args, "entry")?))
}

/// Gives how the project reads the input copy again.
fn load_spec(args: &Args) -> Result<LoadSpec, ToolError> {
    if args.str("file_format") != Some("raw") {
        return Ok(LoadSpec::Auto);
    }
    Ok(LoadSpec::Raw {
        base: raw_addr(args, "base")?.unwrap_or(0),
        entry: raw_addr(args, "entry")?,
    })
}

/// Gives the JSON form of load settings: `{ format: "auto" }` or
/// `{ format: "raw", base, entry }`.
fn spec_json(spec: LoadSpec) -> Value {
    match spec {
        LoadSpec::Auto => Value::object([("format", Value::from("auto"))]),
        LoadSpec::Raw { base, entry } => Value::object([
            ("format", Value::from("raw")),
            ("base", Value::from(hex::u64_text(base))),
            ("entry", entry.map(hex::u64_text).into()),
        ]),
    }
}

/// Gives the error of a load of the binary `id` with the settings `asked` when its first load
/// used `stored`: `INVALID_ARGUMENT` with `details.reason: "load_spec_differs"`,
/// `details.stored` and `next[0]` `binary_load { binary_id }`. The binary ID is the hash of
/// the bytes only, so one binary has one set of load settings.
pub(crate) fn spec_differs(id: BinaryId, stored: LoadSpec, asked: LoadSpec) -> ToolError {
    let field = match (stored, asked) {
        (LoadSpec::Raw { base: a, .. }, LoadSpec::Raw { base: b, .. }) if a != b => "base",
        (LoadSpec::Raw { .. }, LoadSpec::Raw { .. }) => "entry",
        _ => "file_format",
    };
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .path(&format!("/{field}"))
        .detail("reason", Value::from("load_spec_differs"))
        .detail("stored", spec_json(stored))
        .detail("expected", Value::from(EXPECTED_STORED_SPEC))
        .next(Call::new(
            "binary_load",
            Value::object([("binary_id", Value::from(id.to_string()))]),
            WHY_STORED_SPEC,
        ))
}

/// Gives the name and the bytes of the file of the call.
fn read_input(session: &Session, args: &Args) -> Result<(String, Vec<u8>), ToolError> {
    if let Some(name) = args.str("builtin") {
        return builtin(name)
            .map(|(file, bytes)| (file.to_owned(), bytes.to_vec()))
            .ok_or_else(|| ToolError::new(ErrorCode::NotFound).var("kind", "builtin"));
    }
    let path = args.str("path").unwrap_or_default();
    let limit = session.config().limits.file_size;
    match session.config().roots.read(path, limit) {
        Ok(file) => Ok((file.file_name, file.bytes)),
        Err(error) if error.field_path.is_none() => Err(error.path("/path")),
        Err(error) => Err(error),
    }
}

/// Gives the program of the bytes of the call.
fn make_program(session: &Session, args: &Args, bytes: &[u8]) -> Result<Program, ToolError> {
    let limits = session.config().limits;
    let opts = load_opts(args)?;
    if args.str("file_format") == Some("elf") && !matches!(probe(bytes), Detected::Elf { .. }) {
        return Err(malformed(
            &Diagnostic::new(DiagCode::BadMagic, "elf.ident").at(0),
        ));
    }
    if args.str("file_format") == Some("pe") && !matches!(probe(bytes), Detected::Pe { .. }) {
        return Err(malformed(
            &Diagnostic::new(DiagCode::BadMagic, "pe.signature").at(0),
        ));
    }
    let (binary, mem) = loader::load(bytes, &opts, &limits).map_err(|e| load_error(&e))?;
    Program::from_binary(binary, mem, &limits).map_err(|_| ToolError::new(ErrorCode::InternalError))
}

/// Gives the result object of a binary. `refusal` is the reason why the binary has no
/// project on disk: then the object holds `persisted: false` and `persist_reason`. The file
/// name comes from the file system, so it has the escapes of [`safe`], as in other outputs.
fn report(binary: &OpenBinary, already: bool, steps_used: u64, refusal: Option<&str>) -> Object {
    let program = &binary.program;
    let meta = program.meta();
    let kind = match meta.kind {
        Kind::Exec => "exec",
        Kind::Dyn => "dyn",
        Kind::Raw => "raw",
    };
    let entry = program
        .binary()
        .entry_points
        .iter()
        .find(|e| e.kind == EntryKind::Entry)
        .map(|e| Value::from(hex::u64_text(e.addr)))
        .unwrap_or_default();
    let state = binary.analysis.map_or("none", |a| a.state.as_str());
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for diag in &program.binary().diagnostics {
        *counts.entry(diag.code.name()).or_default() += 1;
    }
    let kept = u64::try_from(program.binary().diagnostics.len()).unwrap_or(u64::MAX);
    let by_code = counts
        .into_iter()
        .map(|(code, count)| {
            Value::object([("code", Value::from(code)), ("count", Value::from(count))])
        })
        .collect();
    let mut out = Object::new();
    out.push("binary_id", Value::from(binary.id.to_string()));
    out.push("sha256", Value::from(hex::encode(&meta.sha256)));
    out.push("file_name", Value::from(safe(&binary.file_name)));
    out.push("format", Value::from(meta.format.name()));
    out.push("arch", Value::from(meta.arch.to_string()));
    out.push("kind", Value::from(kind));
    out.push("entry", entry);
    out.push("size", Value::from(meta.file_size));
    out.push("already_loaded", Value::Bool(already));
    out.push("read_only", Value::Bool(binary.read_only));
    if let Some(reason) = refusal {
        out.push("persisted", Value::Bool(false));
        out.push("persist_reason", Value::from(safe(reason)));
    }
    out.push(
        "analysis",
        Value::object([
            ("state", Value::from(state)),
            ("steps_used", Value::from(steps_used)),
        ]),
    );
    out.push(
        "diagnostics",
        Value::object([
            (
                "total",
                Value::from(kept.saturating_add(program.binary().diagnostics_dropped)),
            ),
            ("by_code", Value::Array(by_code)),
        ]),
    );
    out
}

/// Adds the repair call of a stale project lock to `error`: the same call with
/// `break_lock: true`. Another error, or an error with a repair call, stays the same.
fn lock_repair(error: ToolError, args: &Args) -> ToolError {
    let stale = error.code == ErrorCode::ProjectLocked
        && error.details.as_ref().and_then(|d| d.get("stale")) == Some(&Value::Bool(true));
    if !stale || !error.next.is_empty() || args.bool("break_lock") == Some(true) {
        return error;
    }
    let mut call = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = call.insert("break_lock", Value::Bool(true));
    error.next(Call::new(
        "binary_load",
        Value::Object(call),
        WHY_BREAK_LOCK,
    ))
}

/// Runs the analysis that the call asks for after an open. Gives the fuel used.
fn analyze_after(
    session: &mut Session,
    id: BinaryId,
    admitted: Admitted,
    args: &Args,
    ctx: &mut Ctx,
) -> Result<u64, ToolError> {
    let until = match args.str("analysis") {
        Some("none") => return Ok(0),
        Some("triage") => Until::Triage,
        _ => Until::Full,
    };
    let run = match admitted {
        Admitted::Fresh => session.analyze_sliced(id, until, ctx)?,
        Admitted::Current => None,
        Admitted::Stale(band) => session.reanalyze_sliced(id, band, ctx)?,
    };
    Ok(run.map_or(0, |r| r.steps_used))
}

/// Opens the binary `text` for a call with `binary_id`: an open binary, else its project.
fn open_by_id(
    session: &mut Session,
    text: &str,
    args: &Args,
    ctx: &mut Ctx,
) -> Result<Payload, ToolError> {
    let Ok(id) = BinaryId::parse(text) else {
        return Err(session.unknown_binary());
    };
    if session.binary(id).is_some() {
        return finish(session, id, true, 0, ctx);
    }
    let break_lock = args.bool("break_lock").unwrap_or(false);
    let reopened = session
        .reopen_with(id, break_lock)
        .map_err(|e| lock_repair(e, args))?;
    let Some((admitted, warnings)) = reopened else {
        return Err(session.unknown_binary_id(text));
    };
    ctx.warnings.extend(warnings);
    let steps = analyze_after(session, id, admitted, args, ctx)?;
    finish(session, id, false, steps, ctx)
}

/// Sets the frame of the call to the loaded binary and gives the payload.
///
/// A call with the default session label echoes the label of the binary. For example, a
/// project with one `mcp-` label in its journal gives `mcp-2`.
fn finish(
    session: &Session,
    id: BinaryId,
    already: bool,
    steps_used: u64,
    ctx: &mut Ctx,
) -> Result<Payload, ToolError> {
    let binary = session
        .binary(id)
        .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
    if ctx.frame.session == session.new_label() {
        ctx.frame.session.clone_from(&binary.label);
    }
    ctx.frame.binary_id = Some(id.to_string());
    ctx.frame.rev = binary.program.rev().0;
    ctx.frame.analysis = binary.analysis;
    ctx.mutation = Some(Mutation {
        tx: None,
        noop: already,
        diff: None,
    });
    if !binary.program.meta().arch.is_x86_64() {
        ctx.warn(Warning::new(WarningCode::ArchUnsupported));
    }
    ctx.hint(Call::new(
        "binary_survey",
        Value::object([("binary_id", Value::from(id.to_string()))]),
        WHY_SURVEY,
    ));
    let refusal = session.store(id).and_then(Store::persist_reason);
    Ok(Payload::Object(report(
        binary, already, steps_used, refusal,
    )))
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    if let Some(text) = args.str("binary_id") {
        return open_by_id(session, text, args, ctx);
    }
    let (file_name, bytes) = read_input(session, args)?;
    let program = make_program(session, args, &bytes)?;
    let id = program.meta().binary_id;
    if session.binary(id).is_some() {
        let asked = load_spec(args)?;
        if let Some(stored) = session
            .store(id)
            .and_then(Store::load_spec)
            .filter(|s| *s != asked)
        {
            return Err(spec_differs(id, stored, asked));
        }
        return finish(session, id, true, 0, ctx);
    }
    let binary = OpenBinary {
        id,
        program,
        file_name,
        read_only: session.config().read_only,
        label: session.new_label(),
        analysis: None,
    };
    if args.globals().dry_run {
        ctx.mutation = Some(Mutation {
            tx: None,
            noop: true,
            diff: Some(Value::Array(Vec::new())),
        });
        return Ok(Payload::Object(report(&binary, false, 0, None)));
    }
    let break_lock = args.bool("break_lock").unwrap_or(false);
    let (admitted, warnings) = session
        .admit(binary, &bytes, load_spec(args)?, break_lock)
        .map_err(|e| lock_repair(e, args))?;
    ctx.warnings.extend(warnings);
    let steps = analyze_after(session, id, admitted, args, ctx)?;
    finish(session, id, false, steps, ctx)
}
