//! The value walker of the argument parser.
//!
//! The walker checks one object level at a time. Each error carries the JSON pointer of the
//! bad value. A repair call starts from the base: the raw arguments with canonical names and
//! with each unknown key renamed or removed.

use std::collections::BTreeSet;

use ghidorah_base::{ErrorCode, Fuel, Id, WarningCode, addr_expr, did_you_mean};
use ghidorah_json::{Number, Object, Value};

use super::{Coerce, Format};
use crate::envelope::Warning;
use crate::errors::{Candidate, ToolError, cut};
use crate::hints::{Call, WHY_CLAMP, WHY_HEX, WHY_NAMES};
use crate::spec::{ArgKind, ArgSpec};

/// The fuel of one did-you-mean scan.
const DYM_FUEL: u64 = 1_000_000;

/// The largest distance of an unknown key to the name that a repair gives it.
const RENAME_DISTANCE: usize = 2;

/// One step of an argument path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Part {
    /// An object member.
    Key(String),
    /// An array item.
    Index(usize),
}

/// Gives the JSON pointer text of a path.
pub(super) fn pointer(path: &[Part]) -> String {
    let mut out = String::new();
    for part in path {
        out.push('/');
        match part {
            Part::Key(key) => out.push_str(&key.replace('~', "~0").replace('/', "~1")),
            Part::Index(i) => out.push_str(&i.to_string()),
        }
    }
    out
}

/// Gives the field text of a path for the message: the pointer without its first `/`.
fn field(path: &[Part]) -> String {
    let text = pointer(path);
    text.strip_prefix('/').unwrap_or(&text).to_owned()
}

/// Gives the kind name of an argument kind: the JSON type that the schema expects.
pub(super) const fn kind_name(kind: &ArgKind) -> &'static str {
    match kind {
        ArgKind::Addr => "address",
        ArgKind::AddrList(_) | ArgKind::List(..) => "array",
        ArgKind::Id(_) | ArgKind::Str(_) | ArgKind::Enum(_) => "string",
        ArgKind::Int { .. } => "integer",
        ArgKind::Bool => "boolean",
        ArgKind::Obj(_) => "object",
        ArgKind::Json => "any",
    }
}

/// Gives the text of `details.expected` for an argument kind.
pub(super) fn expected(kind: &ArgKind) -> String {
    match kind {
        ArgKind::Addr => {
            "an address: a 0x hex string, a name, an ID or an integer below 2^53".to_owned()
        }
        ArgKind::AddrList(max) => format!("an array of at most {max} addresses"),
        ArgKind::Id(kinds) => {
            let prefixes: Vec<&str> = kinds.iter().map(|k| k.prefix()).collect();
            format!("an ID with the prefix {}", prefixes.join(" or "))
        }
        ArgKind::Int { min, max } => format!("an integer from {min} to {max}"),
        ArgKind::Str(max) => format!("a string of at most {max} characters"),
        ArgKind::Enum(values) => format!("one of: {}", values.join(", ")),
        ArgKind::Bool => "true or false".to_owned(),
        ArgKind::Obj(_) => "an object".to_owned(),
        ArgKind::List(_, max) => format!("an array of at most {max} items"),
        ArgKind::Json => "any JSON value".to_owned(),
    }
}

/// Gives the names of `names` near `key`, nearest first.
fn near<'n>(key: &str, names: &[&'n str]) -> Vec<(usize, &'n str)> {
    let mut fuel = Fuel::new(DYM_FUEL);
    did_you_mean(key, names.iter().copied(), &mut fuel)
        .into_iter()
        .filter_map(|s| {
            names
                .iter()
                .find(|n| **n == s.name)
                .map(|n| (s.distance, *n))
        })
        .collect()
}

/// Finds the spec of `key` in `specs` and `extra`. An alias counts only with `aliases` and a
/// free canonical name. The flag tells if the key is an alias.
fn find<'s>(
    specs: &'s [ArgSpec],
    extra: &'s [ArgSpec],
    key: &str,
    aliases: bool,
    taken: &BTreeSet<&str>,
) -> Option<(&'s ArgSpec, bool)> {
    if let Some(spec) = specs.iter().chain(extra).find(|s| s.name == key) {
        return Some((spec, false));
    }
    specs
        .iter()
        .find(|s| aliases && s.aliases.contains(&key) && !taken.contains(s.name))
        .map(|spec| (spec, true))
}

/// Gives the names that `object` uses directly, so an alias cannot take a used name.
fn direct<'o>(specs: &[ArgSpec], extra: &[ArgSpec], object: &'o Object) -> BTreeSet<&'o str> {
    object
        .iter()
        .map(|(key, _)| key)
        .filter(|key| specs.iter().chain(extra).any(|s| s.name == *key))
        .collect()
}

/// Gives the repair base of one object level: canonical names, and each unknown key renamed
/// to its one near name or removed.
pub(super) fn fix_object(
    specs: &[ArgSpec],
    extra: &[ArgSpec],
    object: &Object,
    aliases: bool,
) -> Object {
    let mut taken = direct(specs, extra, object);
    let names: Vec<&str> = specs.iter().chain(extra).map(|s| s.name).collect();
    let mut out = Object::new();
    for (key, value) in object.iter() {
        let spec = match find(specs, extra, key, aliases, &taken) {
            Some((spec, _)) if !out.contains_key(spec.name) => Some(spec),
            Some(_) => None,
            None => {
                let near: Vec<&str> = near(key, &names)
                    .into_iter()
                    .filter(|(d, _)| *d <= RENAME_DISTANCE)
                    .map(|(_, n)| n)
                    .collect();
                match near.as_slice() {
                    [one] if !taken.contains(one) && !out.contains_key(one) => {
                        specs.iter().chain(extra).find(|s| s.name == *one)
                    }
                    _ => None,
                }
            }
        };
        if let Some(spec) = spec {
            taken.insert(spec.name);
            out.push(spec.name, fix_value(spec, value, aliases));
        }
    }
    out
}

fn fix_value(spec: &ArgSpec, value: &Value, aliases: bool) -> Value {
    match (spec.kind, value) {
        (ArgKind::Obj(members), Value::Object(object)) => {
            Value::Object(fix_object(members, &[], object, aliases))
        }
        (ArgKind::List(item, _), Value::Array(items)) => {
            Value::Array(items.iter().map(|v| fix_value(item, v, aliases)).collect())
        }
        _ => value.clone(),
    }
}

/// Sets the value at `path` in `root`. A missing path leaves `root` as it is.
fn set_at(root: &mut Value, path: &[Part], new: Value) {
    let Some((last, parents)) = path.split_last() else {
        *root = new;
        return;
    };
    let mut at = root;
    for part in parents {
        let next = match (part, at) {
            (Part::Key(key), Value::Object(object)) => object.get_mut(key),
            (Part::Index(i), Value::Array(items)) => items.get_mut(*i),
            _ => None,
        };
        let Some(next) = next else { return };
        at = next;
    }
    let slot = match (last, at) {
        (Part::Key(key), Value::Object(object)) => object.get_mut(key),
        (Part::Index(i), Value::Array(items)) => items.get_mut(*i),
        _ => None,
    };
    if let Some(slot) = slot {
        *slot = new;
    }
}

/// The values of one object level in input order: `(spec, value, given)`.
pub(super) type Level<'s> = Vec<(&'s ArgSpec, Value, bool)>;

/// The walker of one parse.
pub(super) struct Walk<'a> {
    /// The tool name of the repair calls.
    pub tool: &'a str,
    /// The base of the repair calls.
    pub base: Value,
    /// The lenient coercion of the host.
    pub coerce: Option<Coerce<'a>>,
    /// `true` when aliases count.
    pub aliases: bool,
    /// The output format: `detailed` adds coercion details.
    pub format: Format,
    /// The `W_COERCED` warnings.
    pub warnings: Vec<Warning>,
}

impl Walk<'_> {
    fn invalid(path: &[Part], expected: String) -> ToolError {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", &field(path))
            .path(&pointer(path))
            .detail("expected", Value::from(expected))
    }

    fn clamp(&self, path: &[Part], value: Value) -> ToolError {
        let mut args = self.base.clone();
        set_at(&mut args, path, value);
        ToolError::new(ErrorCode::LimitExceeded)
            .var("field", &field(path))
            .path(&pointer(path))
            .next(Call::new(self.tool, args, WHY_CLAMP))
    }

    fn address(&self, path: &[Part], repair: Option<String>) -> ToolError {
        let error = ToolError::new(ErrorCode::AddressInvalid)
            .var("field", &field(path))
            .path(&pointer(path));
        match repair {
            Some(text) => {
                let mut args = self.base.clone();
                set_at(&mut args, path, Value::from(text));
                error.next(Call::new(self.tool, args, WHY_HEX))
            }
            None => error,
        }
    }

    /// Adds a `W_COERCED` warning. `pair` names the details: the names of an alias or the
    /// types of a coercion.
    fn coerced(&mut self, field: String, pair: [(&str, &str); 2]) {
        let mut warning = Warning::new(WarningCode::Coerced);
        warning.field = Some(field);
        if self.format == Format::Detailed {
            warning.details = Some(Object::from_iter(pair.map(|(k, v)| (k, Value::from(v)))));
        }
        self.warnings.push(warning);
    }

    /// Checks one object level. `extra` holds the global arguments of the top level.
    ///
    /// The result holds the given values in input order, then the defaults.
    pub(super) fn level<'s>(
        &mut self,
        specs: &'s [ArgSpec],
        extra: &'s [ArgSpec],
        object: &Object,
        path: &mut Vec<Part>,
    ) -> Result<Level<'s>, ToolError> {
        if let Some(key) = object.first_duplicate() {
            path.push(Part::Key(key.to_owned()));
            return Err(Self::invalid(path, "a key that appears once".to_owned()));
        }
        let mut taken = direct(specs, extra, object);
        let mut found = Vec::new();
        for (key, value) in object.iter() {
            let Some((spec, alias)) = find(specs, extra, key, self.aliases, &taken) else {
                path.push(Part::Key(key.to_owned()));
                let names: Vec<&str> = specs.iter().chain(extra).map(|s| s.name).collect();
                let candidates = near(key, &names)
                    .into_iter()
                    .map(|(_, n)| Candidate::text(n, "argument"))
                    .collect();
                return Err(ToolError::new(ErrorCode::UnknownArgument)
                    .var("field", &cut(&field(path), 256))
                    .path(&pointer(path))
                    .candidates(candidates)
                    .next(Call::new(self.tool, self.base.clone(), WHY_NAMES)));
            };
            taken.insert(spec.name);
            found.push((spec, alias, key, value));
        }
        let mut out = Vec::new();
        for (spec, alias, key, value) in found {
            if alias {
                path.push(Part::Key(key.to_owned()));
                let at = pointer(path);
                path.pop();
                self.coerced(at, [("from_name", key), ("to_name", spec.name)]);
            }
            path.push(Part::Key(spec.name.to_owned()));
            let checked = self.value(spec, value, path)?;
            path.pop();
            out.push((spec, checked, true));
        }
        for spec in specs {
            if out.iter().any(|(s, _, _)| s.name == spec.name) {
                continue;
            }
            if spec.required {
                path.push(Part::Key(spec.name.to_owned()));
                return Err(ToolError::new(ErrorCode::MissingArgument)
                    .var("field", &field(path))
                    .path(&pointer(path)));
            }
            let default = spec
                .default
                .and_then(|text| ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).ok());
            if let Some(value) = default {
                out.push((spec, value, false));
            }
        }
        Ok(out)
    }

    /// Checks one value, with the host coercion for a value of the wrong type.
    pub(super) fn value(
        &mut self,
        spec: &ArgSpec,
        value: &Value,
        path: &mut Vec<Part>,
    ) -> Result<Value, ToolError> {
        match self.kind(spec, value, path) {
            Err(e)
                if e.code == ErrorCode::InvalidArgument && e.field_path == Some(pointer(path)) =>
            {
                let coerced = self.coerce.and_then(|coerce| coerce(&spec.kind, value));
                if let Some(new) = coerced
                    && let Ok(ok) = self.kind(spec, &new, path)
                {
                    let types = [
                        ("from_type", value.kind()),
                        ("to_type", kind_name(&spec.kind)),
                    ];
                    self.coerced(pointer(path), types);
                    return Ok(ok);
                }
                Err(e)
            }
            other => other,
        }
    }

    fn kind(
        &mut self,
        spec: &ArgSpec,
        value: &Value,
        path: &mut Vec<Part>,
    ) -> Result<Value, ToolError> {
        let ok = Ok(value.clone());
        match (spec.kind, value) {
            (ArgKind::Addr, _) => self.addr(value, path),
            (ArgKind::AddrList(max), Value::Array(items)) => {
                if items.len() > max {
                    let cut = items.iter().take(max).cloned().collect();
                    return Err(self.clamp(path, Value::Array(cut)));
                }
                for (i, item) in items.iter().enumerate() {
                    path.push(Part::Index(i));
                    self.addr(item, path)?;
                    path.pop();
                }
                ok
            }
            (ArgKind::Id(kinds), Value::String(text))
                if Id::parse(text).is_ok_and(|id| kinds.contains(&id.kind())) =>
            {
                ok
            }
            (ArgKind::Int { min, max }, Value::Number(n)) if n.is_integer() => match n.as_i64() {
                Some(v) if v < min => Err(Self::invalid(path, expected(&spec.kind))),
                Some(v) if v <= max => ok,
                Some(_) => Err(self.clamp(path, number(max))),
                None if n.as_u64().is_some() => Err(self.clamp(path, number(max))),
                None => Err(Self::invalid(path, expected(&spec.kind))),
            },
            (ArgKind::Str(max), Value::String(text)) => {
                if text.chars().count() > max {
                    Err(self.clamp(path, Value::from(cut(text, max))))
                } else {
                    ok
                }
            }
            (ArgKind::Enum(values), Value::String(text)) if values.contains(&text.as_str()) => ok,
            (ArgKind::Enum(values), Value::String(text)) => {
                let candidates = near(text, values)
                    .into_iter()
                    .map(|(_, n)| Candidate::text(n, "value"))
                    .collect();
                Err(Self::invalid(path, expected(&spec.kind)).candidates(candidates))
            }
            (ArgKind::Bool, Value::Bool(_)) | (ArgKind::Json, _) => ok,
            (ArgKind::Obj(members), Value::Object(object)) => {
                let level = self.level(members, &[], object, path)?;
                Ok(Value::Object(
                    level.into_iter().map(|(s, v, _)| (s.name, v)).collect(),
                ))
            }
            (ArgKind::List(item, max), Value::Array(items)) => {
                if items.len() > max {
                    let cut = items.iter().take(max).cloned().collect();
                    return Err(self.clamp(path, Value::Array(cut)));
                }
                let mut out = Vec::with_capacity(items.len());
                for (i, v) in items.iter().enumerate() {
                    path.push(Part::Index(i));
                    out.push(self.value(item, v, path)?);
                    path.pop();
                }
                Ok(Value::Array(out))
            }
            _ => Err(Self::invalid(path, expected(&spec.kind))),
        }
    }

    fn addr(&self, value: &Value, path: &[Part]) -> Result<Value, ToolError> {
        match value {
            Value::Number(n) => {
                let parsed = if n.is_integer() { n.as_u64() } else { None };
                match parsed.map(addr_expr::from_integer) {
                    Some(Ok(_)) => Ok(value.clone()),
                    Some(Err(e)) => Err(self.address(path, e.repair_text())),
                    None => Err(self.address(path, None)),
                }
            }
            Value::String(text) => match addr_expr::parse(text) {
                Ok(_) => Ok(value.clone()),
                Err(e) => Err(self.address(path, e.repair_text())),
            },
            _ => Err(Self::invalid(path, expected(&ArgKind::Addr))),
        }
    }
}

/// Gives a JSON integer of an `i64`.
fn number(value: i64) -> Value {
    Number::parse(&value.to_string()).map_or(Value::Null, Value::Number)
}
