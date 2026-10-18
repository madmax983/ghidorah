//! The output shapes of a step envelope (design Section 11.3): the shape at a pointer, the
//! fit of a shape to an argument kind and the sample values of the argument check.

use ghidorah_base::IdKind;
use ghidorah_json::Value;
use ghidorah_json::pointer::{Pointer, Segment};

use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ToolSpec};

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
pub(super) fn fits(shape: OutputShape, kind: &ArgKind) -> bool {
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
