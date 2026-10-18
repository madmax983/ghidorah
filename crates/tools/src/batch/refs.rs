//! References between batch steps (design Sections 11.2 to 11.4).
//!
//! A reference is an object `{ "$ref": <step ID>, "ptr": <pointer>, "partial"?: true }` in
//! place of one argument value. Before the run, [`find`] reads the references of a step.
//! Then [`typed`] checks the output shape of the source tool at the pointer against the argument.
//! In the run, [`resolve`] reads the value from the envelope of the source step.
//!
//! | Pointer | Value | Target |
//! |---|---|---|
//! | no `*` | the one value at the pointer | any argument whose kind fits |
//! | with `*` | the list of the selected values, without duplicates, in first order | a list argument |

use std::collections::BTreeSet;

use ghidorah_base::{ErrorCode, Fuel, IdKind, did_you_mean};
use ghidorah_json::pointer::{self, Pointer, Segment};
use ghidorah_json::{Object, Value};

use crate::args::{check_value, globals_of};
use crate::errors::{Candidate, ToolError};
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Role, ToolSpec};

/// The member name of the step ID of a reference.
pub const REF_KEY: &str = "$ref";

/// The fuel of the did-you-mean scan of the candidate paths.
const DYM_FUEL: u64 = 200_000;

/// The largest number of candidate paths of one value.
const MAX_PATHS: usize = 64;

/// The deepest level of the candidate paths.
const MAX_PATH_DEPTH: usize = 5;

/// The spec of one address in an address list.
const ADDR_ITEM: ArgSpec = ArgSpec::new("item", Role::Param, ArgKind::Addr, "An address.");

/// One part of the path of a reference inside the step arguments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// An object member.
    Key(String),
    /// An array item.
    Index(usize),
}

/// One reference in the arguments of a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The path of the reference object inside the step arguments.
    pub at: Vec<Part>,
    /// The index of the source step.
    pub source: usize,
    /// The pointer text.
    pub ptr: String,
    /// The parsed pointer.
    pub pointer: Pointer,
    /// `true` when the reference accepts a truncated source page.
    pub partial: bool,
    /// The spec of the argument, or `None` for a position of any JSON value.
    pub spec: Option<ArgSpec>,
}

impl Reference {
    /// Gives the JSON pointer of the reference in the batch arguments of step `step`.
    #[must_use]
    pub fn path(&self, step: usize) -> String {
        let mut out = format!("/steps/{step}/args");
        for part in &self.at {
            out.push('/');
            match part {
                Part::Key(key) => out.push_str(&key.replace('~', "~0").replace('/', "~1")),
                Part::Index(i) => out.push_str(&i.to_string()),
            }
        }
        out
    }

    /// Gives the largest number of values of the target list, or `None` for no list.
    #[must_use]
    pub fn cap(&self) -> Option<usize> {
        match self.spec.map(|s| s.kind) {
            Some(ArgKind::AddrList(max) | ArgKind::List(_, max)) => Some(max),
            _ => None,
        }
    }

    /// Tells if the pointer reads the `data` member of the source envelope.
    #[must_use]
    pub fn reads_data(&self) -> bool {
        self.pointer.segments().first() == Some(&Segment::Key("data".to_owned()))
    }
}

/// Gives the `BAD_REFERENCE` error at `path` with `details.expected`.
fn bad(path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::BadReference)
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives the candidates of `options`, the nearest to `given` first.
fn ranked(given: &str, options: &[String], label: &str) -> Vec<Candidate> {
    let mut fuel = Fuel::new(DYM_FUEL);
    let near = did_you_mean(given, options.iter().map(String::as_str), &mut fuel);
    let mut out: Vec<String> = near.into_iter().map(|s| s.name).collect();
    for option in options {
        if !out.contains(option) {
            out.push(option.clone());
        }
    }
    out.iter().map(|o| Candidate::text(o, label)).collect()
}

/// Reads one reference object at `at`. `earlier` holds the IDs of the steps before `step`.
fn reference(
    object: &Object,
    at: &[Part],
    spec: Option<&ArgSpec>,
    earlier: &[&str],
    step: usize,
) -> Result<Reference, ToolError> {
    let mut r = Reference {
        at: at.to_vec(),
        source: 0,
        ptr: String::new(),
        pointer: Pointer::root(),
        partial: false,
        spec: spec.copied(),
    };
    let path = r.path(step);
    let shape = "a reference {\"$ref\": step ID, \"ptr\": pointer, \"partial\"?: true}";
    if object
        .iter()
        .any(|(k, _)| !matches!(k, REF_KEY | "ptr" | "partial"))
    {
        return Err(bad(&path, shape));
    }
    let id = object
        .get(REF_KEY)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(source) = earlier.iter().position(|e| *e == id) else {
        let ids: Vec<String> = earlier.iter().map(|e| (*e).to_owned()).collect();
        return Err(bad(&path, "the ID of an earlier step").candidates(ranked(id, &ids, "step")));
    };
    let ptr = object
        .get("ptr")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(&path, shape))?;
    r.pointer =
        pointer::parse(ptr).map_err(|_| bad(&path, "a JSON pointer such as /data/items/*/id"))?;
    r.partial = match object.get("partial") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(bad(&path, shape)),
    };
    ptr.clone_into(&mut r.ptr);
    r.source = source;
    Ok(r)
}

/// Walks one value of the step arguments for references.
fn walk(
    value: &Value,
    spec: Option<&ArgSpec>,
    at: &mut Vec<Part>,
    earlier: &[&str],
    step: usize,
    out: &mut Vec<Reference>,
) -> Result<(), ToolError> {
    match value {
        Value::Object(object) if object.contains_key(REF_KEY) => {
            out.push(reference(object, at, spec, earlier, step)?);
        }
        Value::Object(object) => {
            let members = match spec.map(|s| s.kind) {
                Some(ArgKind::Obj(members)) => members,
                _ => &[],
            };
            for (key, member) in object.iter() {
                at.push(Part::Key(key.to_owned()));
                let child = members.iter().find(|m| m.name == key);
                walk(member, child, at, earlier, step, out)?;
                at.pop();
            }
        }
        Value::Array(items) => {
            let item = match spec.map(|s| s.kind) {
                Some(ArgKind::List(item, _)) => Some(item),
                Some(ArgKind::AddrList(_)) => Some(&ADDR_ITEM),
                _ => None,
            };
            for (i, member) in items.iter().enumerate() {
                at.push(Part::Index(i));
                walk(member, item, at, earlier, step, out)?;
                at.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

/// Finds the references in the arguments `args` of step `step` of `tool`. `earlier` holds the
/// IDs of the steps before it.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` for a reference object that does not parse, or that names no
/// earlier step.
pub fn find(
    tool: &ToolSpec<Session>,
    args: &Value,
    earlier: &[&str],
    step: usize,
) -> Result<Vec<Reference>, ToolError> {
    let globals = globals_of(tool);
    let mut out = Vec::new();
    let Value::Object(object) = args else {
        return Ok(out);
    };
    for (key, value) in object.iter() {
        let spec = tool
            .arg(key)
            .or_else(|| globals.iter().find(|g| g.name == key));
        let mut at = vec![Part::Key(key.to_owned())];
        walk(value, spec, &mut at, earlier, step, &mut out)?;
    }
    Ok(out)
}

/// The members of a result envelope and their shapes, `data` aside.
const PAGE: &[Field] = &[
    Field::req("returned", OutputShape::Int),
    Field::opt("total", OutputShape::Int),
    Field::opt("total_lower_bound", OutputShape::Int),
    Field::req("truncated", OutputShape::Bool),
    Field::opt("next_cursor", OutputShape::Str),
    Field::opt("hint", OutputShape::Str),
];
const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("rev", OutputShape::Int),
];
const TEXT: &[Field] = &[
    Field::req("text", OutputShape::Str),
    Field::req("hex", OutputShape::Str),
    Field::req("len", OutputShape::Int),
    Field::opt("truncated", OutputShape::Bool),
    Field::req("src", OutputShape::Str),
];

/// Gives the shape of the envelope member `name` of a step of `tool`.
fn member(tool: &ToolSpec<Session>, name: &str) -> Option<OutputShape> {
    Some(match name {
        "data" => tool.output,
        "ok" | "partial" | "noop" => OutputShape::Bool,
        "rev" => OutputShape::Int,
        "binary_id" | "session" | "tx" => OutputShape::Str,
        "analysis" => OutputShape::Obj(ANALYSIS),
        "page" => OutputShape::Obj(PAGE),
        "warnings" | "next" => OutputShape::List(&OutputShape::Any),
        "diff" | "error" => OutputShape::Any,
        _ => return None,
    })
}

/// The members of a result envelope.
const ENVELOPE: [&str; 13] = [
    "ok",
    "binary_id",
    "rev",
    "session",
    "analysis",
    "partial",
    "data",
    "page",
    "warnings",
    "next",
    "tx",
    "noop",
    "diff",
];

/// Gives the candidate paths of the fields of `shape` below `prefix`.
fn shape_paths(shape: OutputShape, prefix: &str) -> Vec<String> {
    match shape {
        OutputShape::Obj(fields) => fields
            .iter()
            .map(|f| format!("{prefix}/{}", f.name))
            .collect(),
        OutputShape::Text => TEXT
            .iter()
            .map(|f| format!("{prefix}/{}", f.name))
            .collect(),
        OutputShape::List(inner) => {
            let star = format!("{prefix}/*");
            match inner {
                OutputShape::Obj(fields) => fields
                    .iter()
                    .map(|f| format!("{star}/{}", f.name))
                    .collect(),
                _ => vec![star],
            }
        }
        OutputShape::Nullable(inner) => shape_paths(*inner, prefix),
        _ => vec![prefix.to_owned()],
    }
}

/// The shape at a pointer of a source envelope: the shape and `true` for a `*` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Typed {
    /// The shape of one value at the pointer.
    pub shape: OutputShape,
    /// `true` when the pointer has a `*` segment, so the reference gives a list.
    pub star: bool,
}

/// Gives the shape at `pointer` of the envelope of a step of `tool`.
///
/// # Errors
///
/// Returns the candidate paths of the level where the pointer leaves the shape.
pub fn shape_at(tool: &ToolSpec<Session>, pointer: &Pointer) -> Result<Typed, Vec<String>> {
    let mut star = false;
    let mut prefix = String::new();
    let mut shape: Option<OutputShape> = None;
    for segment in pointer.segments() {
        let token = segment.token();
        let Some(current) = shape else {
            shape = Some(
                member(tool, token)
                    .ok_or_else(|| ENVELOPE.iter().map(|m| format!("/{m}")).collect::<Vec<_>>())?,
            );
            prefix = format!("/{token}");
            continue;
        };
        let current = match current {
            OutputShape::Nullable(inner) => *inner,
            other => other,
        };
        let next = match (current, segment) {
            (OutputShape::Any, _) => OutputShape::Any,
            (OutputShape::Obj(fields), Segment::Key(key)) => fields
                .iter()
                .find(|f| f.name == key)
                .map(|f| f.shape)
                .ok_or_else(|| shape_paths(current, &prefix))?,
            (OutputShape::Text, Segment::Key(key)) => TEXT
                .iter()
                .find(|f| f.name == key)
                .map(|f| f.shape)
                .ok_or_else(|| shape_paths(current, &prefix))?,
            (OutputShape::List(inner), Segment::Star) => {
                star = true;
                *inner
            }
            (OutputShape::List(inner), Segment::Key(key)) if key.parse::<usize>().is_ok() => *inner,
            _ => return Err(shape_paths(current, &prefix)),
        };
        prefix.push('/');
        prefix.push_str(token);
        shape = Some(next);
    }
    let shape =
        shape.ok_or_else(|| ENVELOPE.iter().map(|m| format!("/{m}")).collect::<Vec<_>>())?;
    Ok(Typed { shape, star })
}

/// Tells if a value of `shape` fits an argument of `kind`.
fn fits(shape: OutputShape, kind: &ArgKind) -> bool {
    use OutputShape as S;
    let shape = match shape {
        S::Nullable(inner) => *inner,
        other => other,
    };
    if shape == S::Any || *kind == ArgKind::Json {
        return true;
    }
    match kind {
        ArgKind::Addr => matches!(shape, S::Addr | S::Id(_) | S::Str | S::Int),
        ArgKind::AddrList(_) => matches!(shape, S::List(inner) if fits(*inner, &ArgKind::Addr)),
        ArgKind::List(item, _) => matches!(shape, S::List(inner) if fits(*inner, &item.kind)),
        ArgKind::Id(kinds) => match shape {
            S::Id(kind) => kinds.contains(&kind),
            S::Str => true,
            _ => false,
        },
        ArgKind::Int { .. } => shape == S::Int,
        ArgKind::Str(_) => matches!(shape, S::Str | S::Addr | S::Id(_)),
        ArgKind::Enum(_) => shape == S::Str,
        ArgKind::Bool => shape == S::Bool,
        ArgKind::Obj(_) => matches!(shape, S::Obj(_) | S::Text),
        ArgKind::Json => true,
    }
}

/// Checks the type of reference `r` of step `step` against the source tool `source`.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` with the candidate paths in three cases. The pointer leaves the
/// output shape, the shape does not fit the argument, or a `*` reference does not go into a list.
pub fn typed(r: &Reference, source: &ToolSpec<Session>, step: usize) -> Result<Typed, ToolError> {
    let path = r.path(step);
    let typed = shape_at(source, &r.pointer).map_err(|paths| {
        bad(&path, "a path of the output of the source step")
            .candidates(ranked(&r.ptr, &paths, "path"))
    })?;
    let Some(spec) = r.spec else {
        return Ok(typed);
    };
    let ok = if typed.star {
        let item = match spec.kind {
            ArgKind::AddrList(_) => Some(ArgKind::Addr),
            ArgKind::List(item, _) => Some(item.kind),
            ArgKind::Json => Some(ArgKind::Json),
            _ => None,
        };
        item.is_some_and(|k| fits(typed.shape, &k))
    } else {
        fits(typed.shape, &spec.kind)
    };
    if ok {
        Ok(typed)
    } else if typed.star && r.cap().is_none() {
        Err(bad(&path, "a list argument for a pointer with *"))
    } else {
        Err(bad(&path, "a value of the kind of the argument"))
    }
}

/// Gives a value that the parser of `kind` accepts, for the check of the arguments before
/// the run.
#[must_use]
pub fn sample(kind: &ArgKind) -> Value {
    match kind {
        ArgKind::Addr => Value::from(0_u64),
        ArgKind::AddrList(_) => Value::Array(vec![Value::from(0_u64)]),
        ArgKind::Id(kinds) => Value::from(kinds.first().map_or("fn:0x0", |k| sample_id(*k))),
        ArgKind::Int { min, .. } => Value::from(*min),
        ArgKind::Str(_) => Value::from("x"),
        ArgKind::Enum(values) => Value::from(values.first().copied().unwrap_or_default()),
        ArgKind::Bool => Value::Bool(false),
        ArgKind::Obj(members) => Value::Object(
            members
                .iter()
                .filter(|m| m.required)
                .map(|m| (m.name, sample(&m.kind)))
                .collect(),
        ),
        ArgKind::List(item, _) => Value::Array(vec![sample(&item.kind)]),
        ArgKind::Json => Value::Null,
    }
}

/// Gives an ID text of `kind` that the ID grammar accepts.
#[must_use]
pub const fn sample_id(kind: IdKind) -> &'static str {
    match kind {
        IdKind::Func => "fn:0x0",
        IdKind::Block => "bb:0x0",
        IdKind::Op => "op:0x0:0",
        IdKind::Import => "imp:x",
        IdKind::Export => "exp:x",
        IdKind::Syscall => "sys:read",
        IdKind::Section => "sec:0:x",
        IdKind::Segment => "seg:0",
        IdKind::Str => "str:0x0",
        IdKind::JumpTable => "jt:0x0",
        IdKind::External => "ext:0x0",
        IdKind::File => "file:0x0",
        IdKind::Sym => "sym:x",
        IdKind::Var => "var:0x0/stack:-0x8",
        IdKind::Note => "note:1",
        IdKind::Set => "set:x",
        IdKind::Type => "t:int",
        IdKind::Tx => "tx:1",
        IdKind::Ref => "ref:0x0>0x1:read",
    }
}

/// Gives the value at `at` in `root`, or `None` for a missing path.
#[must_use]
pub fn get_at<'v>(root: &'v Value, at: &[Part]) -> Option<&'v Value> {
    at.iter().try_fold(root, |value, part| match (part, value) {
        (Part::Key(key), Value::Object(object)) => object.get(key),
        (Part::Index(i), Value::Array(items)) => items.get(*i),
        _ => None,
    })
}

/// Sets the value at `at` in `root`. A missing path leaves `root` as it is.
pub fn set_at(root: &mut Value, at: &[Part], new: Value) {
    let mut slot = root;
    for part in at {
        let next = match (part, slot) {
            (Part::Key(key), Value::Object(object)) => object.get_mut(key),
            (Part::Index(i), Value::Array(items)) => items.get_mut(*i),
            _ => None,
        };
        let Some(next) = next else { return };
        slot = next;
    }
    *slot = new;
}

/// Gives the candidate paths of the values of `value` below `prefix`: arrays give `*`.
fn value_paths(value: &Value, prefix: &str, depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_PATHS {
        return;
    }
    match value {
        Value::Object(object) if depth < MAX_PATH_DEPTH => {
            for (key, member) in object.iter() {
                let path = format!("{prefix}/{key}");
                out.push(path.clone());
                value_paths(member, &path, depth + 1, out);
            }
        }
        Value::Array(items) if depth < MAX_PATH_DEPTH => {
            if let Some(first) = items.first() {
                value_paths(first, &format!("{prefix}/*"), depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Gives the candidate paths of the data of the envelope `source`.
fn data_paths(source: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(data) = source.get("data") {
        value_paths(data, "/data", 0, &mut out);
    }
    out.truncate(MAX_PATHS);
    out
}

/// Gives the value of reference `r` of step `step` in the envelope `source`.
///
/// The value of a `*` pointer has no duplicate.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` for a truncated source page without `partial`, a missing path, or
/// a value that does not fit the argument. The candidates are the paths of the source data.
/// Returns `PLUCK_TOO_LONG` with `details: { count, cap }` when a `*` pointer gives more
/// values than the cap of the target list.
pub fn resolve(r: &Reference, source: &Value, step: usize) -> Result<Value, ToolError> {
    let path = r.path(step);
    let truncated = source.pointer("/page/truncated") == Some(&Value::Bool(true));
    let missing = |given: &str| {
        bad(&path, "a path of the data of the source step").candidates(ranked(
            given,
            &data_paths(source),
            "path",
        ))
    };
    if truncated && r.reads_data() && !r.partial {
        return Err(bad(&path, "a complete source page, or partial true")
            .detail("source_truncated", Value::Bool(true)));
    }
    let value = if r.pointer.has_star() {
        let selection = pointer::select(source, &r.pointer);
        if let (false, Some(first)) = (r.partial, &selection.first_missing) {
            return Err(missing(first));
        }
        let mut seen = BTreeSet::new();
        let values: Vec<Value> = selection
            .values
            .into_iter()
            .filter(|v| seen.insert(ghidorah_json::write(v)))
            .cloned()
            .collect();
        if let Some(cap) = r.cap().filter(|cap| values.len() > *cap) {
            return Err(ToolError::new(ErrorCode::PluckTooLong)
                .path(&path)
                .detail("count", Value::from(values.len()))
                .detail("cap", Value::from(cap)));
        }
        Value::Array(values)
    } else {
        pointer::get(source, &r.pointer)
            .cloned()
            .ok_or_else(|| missing(&r.ptr))?
    };
    check(r, &value, step)?;
    Ok(value)
}

/// Checks a resolved value of reference `r` against its argument.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` with `details.expected` when the value does not fit.
pub fn check(r: &Reference, value: &Value, step: usize) -> Result<(), ToolError> {
    let Some(spec) = r.spec else {
        return Ok(());
    };
    check_value(&spec, value).map_err(|e| {
        let expected = e
            .details
            .as_ref()
            .and_then(|d| d.get("expected"))
            .and_then(Value::as_str)
            .unwrap_or("a value of the kind of the argument")
            .to_owned();
        bad(&r.path(step), &expected)
    })
}
