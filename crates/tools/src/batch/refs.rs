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

use ghidorah_base::{ErrorCode, Fuel, did_you_mean};
use ghidorah_json::pointer::{self, Pointer, Segment};
use ghidorah_json::{Object, Value};

use super::shapes::{Typed, fits, shape_at};
use crate::args::{check_value, globals_of};
use crate::errors::{Candidate, ToolError};
use crate::outshape::OutputShape;
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
                Part::Key(key) => out.push_str(&escape(key)),
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

/// Checks the type of reference `r` of step `step` against the source tool `source`.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` with the candidate paths in three cases. The pointer leaves the
/// output shape, the shape does not fit the argument, or a `*` reference does not go into a list.
/// For a shape that does not fit, the candidates are the data paths whose shapes fit.
pub fn typed(r: &Reference, source: &ToolSpec<Session>, step: usize) -> Result<Typed, ToolError> {
    let path = r.path(step);
    let typed = shape_at(source, &r.pointer).map_err(|paths| {
        bad(&path, "a path of the output of the source step")
            .candidates(ranked(&r.ptr, &paths, "path"))
    })?;
    let Some(spec) = r.spec else {
        return Ok(typed);
    };
    if shape_fits(&spec, typed.shape, typed.star) {
        return Ok(typed);
    }
    let expected = if typed.star && r.cap().is_none() {
        "a list argument for a pointer with *"
    } else {
        "a value of the kind of the argument"
    };
    let mut tree = Vec::new();
    shape_tree(
        source.output,
        "/data",
        r.cap().is_some(),
        false,
        0,
        &mut tree,
    );
    let paths = pick(
        tree.into_iter()
            .map(|(p, shape, star)| (p, shape_fits(&spec, shape, star))),
    );
    Err(bad(&path, expected).candidates(ranked(&r.ptr, &paths, "path")))
}

/// Tells if a value of `shape` fits the argument `spec`. The value of a `*` pointer goes into
/// the items of a list argument.
fn shape_fits(spec: &ArgSpec, shape: OutputShape, star: bool) -> bool {
    if !star {
        return fits(shape, &spec.kind);
    }
    let item = match spec.kind {
        ArgKind::AddrList(_) => Some(ArgKind::Addr),
        ArgKind::List(item, _) => Some(item.kind),
        ArgKind::Json => Some(ArgKind::Json),
        _ => None,
    };
    item.is_some_and(|k| fits(shape, &k))
}

/// Adds the paths of the output shape `shape` below `prefix` to `out`, with their shapes and
/// `true` for a path with `*`. An array item is `*` when `list` is `true`, else `0`.
fn shape_tree(
    shape: OutputShape,
    prefix: &str,
    list: bool,
    star: bool,
    depth: usize,
    out: &mut Vec<(String, OutputShape, bool)>,
) {
    let shape = match shape {
        OutputShape::Nullable(inner) => *inner,
        other => other,
    };
    if out.len() >= MAX_PATHS {
        return;
    }
    out.push((prefix.to_owned(), shape, star));
    if depth >= MAX_PATH_DEPTH {
        return;
    }
    let next = depth.saturating_add(1);
    match shape {
        OutputShape::Obj(fields) => {
            for f in fields {
                let sub = format!("{prefix}/{}", escape(f.name));
                shape_tree(f.shape, &sub, list, star, next, out);
            }
        }
        OutputShape::List(inner) => {
            let sub = format!("{prefix}/{}", item_token(list));
            shape_tree(*inner, &sub, list, star || list, next, out);
        }
        OutputShape::Text => {
            let sub = format!("{prefix}/text");
            shape_tree(OutputShape::Str, &sub, list, star, next, out);
        }
        _ => {}
    }
}

/// Gives the paths that fit, or all paths when no path fits.
fn pick(paths: impl Iterator<Item = (String, bool)>) -> Vec<String> {
    let all: Vec<(String, bool)> = paths.collect();
    let fit: Vec<String> = all
        .iter()
        .filter(|(_, fit)| *fit)
        .map(|(p, _)| p.clone())
        .collect();
    if fit.is_empty() {
        all.into_iter().map(|(p, _)| p).collect()
    } else {
        fit
    }
}

/// Gives the pointer token of an object key.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Gives the pointer token of an array item: `*` for a list argument, else `0`.
const fn item_token(list: bool) -> &'static str {
    if list { "*" } else { "0" }
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

/// Gives the candidate paths of the values of `value` below `prefix`. An array gives the
/// paths of its first item, with `*` when `list` is `true`, else `0`.
fn value_paths(value: &Value, prefix: &str, list: bool, depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_PATHS {
        return;
    }
    let next = depth.saturating_add(1);
    match value {
        Value::Object(object) if depth < MAX_PATH_DEPTH => {
            for (key, member) in object.iter() {
                let path = format!("{prefix}/{}", escape(key));
                out.push(path.clone());
                value_paths(member, &path, list, next, out);
            }
        }
        Value::Array(items) if depth < MAX_PATH_DEPTH => {
            if let Some(first) = items.first() {
                let path = format!("{prefix}/{}", item_token(list));
                value_paths(first, &path, list, next, out);
            }
        }
        _ => {}
    }
}

/// Gives the candidate paths of the data of the envelope `source` for reference `r`.
fn data_paths(r: &Reference, source: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(data) = source.get("data") {
        value_paths(data, "/data", r.cap().is_some(), 0, &mut out);
    }
    out.truncate(MAX_PATHS);
    out
}

/// Gives the value of `source` at the candidate path `path`, or `None` for no value.
fn value_at(source: &Value, path: &str) -> Option<Value> {
    let pointer = pointer::parse(path).ok()?;
    if pointer.has_star() {
        let selection = pointer::select(source, &pointer);
        Some(Value::Array(
            selection.values.into_iter().cloned().collect(),
        ))
    } else {
        pointer::get(source, &pointer).cloned()
    }
}

/// Gives the candidate paths of the data of `source` for the argument `spec` of reference
/// `r`: the paths whose value fits. When no value fits, it gives all paths.
fn fit_paths(r: &Reference, spec: &ArgSpec, source: &Value) -> Vec<String> {
    pick(data_paths(r, source).into_iter().map(|p| {
        let fit = value_at(source, &p).is_some_and(|v| check_value(spec, &v).is_ok());
        (p, fit)
    }))
}

/// Gives the value of reference `r` of step `step` in the envelope `source`.
///
/// The value of a `*` pointer has no duplicate.
///
/// # Errors
///
/// Returns `BAD_REFERENCE` for a truncated source page without `partial`, a missing path, or
/// a value that does not fit the argument. The candidates are the paths of the source data.
/// For a value that does not fit, the candidates are the paths whose values fit.
/// Returns `PLUCK_TOO_LONG` with `details: { count, cap }` when a `*` pointer gives more
/// values than the cap of the target list.
pub fn resolve(r: &Reference, source: &Value, step: usize) -> Result<Value, ToolError> {
    let path = r.path(step);
    let truncated = source.pointer("/page/truncated") == Some(&Value::Bool(true));
    let missing = |given: &str| {
        bad(&path, "a path of the data of the source step").candidates(ranked(
            given,
            &data_paths(r, source),
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
    check(r, &value, step).map_err(|e| match r.spec {
        Some(spec) => e.candidates(ranked(&r.ptr, &fit_paths(r, &spec, source), "path")),
        None => e,
    })?;
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
