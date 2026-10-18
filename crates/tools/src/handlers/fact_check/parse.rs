//! The arguments of a claim: one parser per column kind of the relation catalog.
//!
//! | Kind | Input | Atom value |
//! |---|---|---|
//! | `fn` | an address input of the function family | the function |
//! | `fn`, `imp`, `sys` | an `imp:` ID, a stub, an import name, a `sys:` ID, else a function | the endpoint |
//! | `imp` | an `imp:` ID, an import name or the stub of an import | the import |
//! | `sys` | a `sys:` ID, a syscall name or a number | the syscall number |
//! | `addr` | an address input of the address family | the address |
//! | `int` | a JSON integer or decimal digits | the integer |
//! | `glob` | a glob pattern | the pattern |
//! | `kind` | a reference class or a reference type name | the class |
//! | `value` | a JSON integer, `0x` hex, decimal digits or an address input | the number |
//!
//! Each error has the field path of its argument, for example `/claims/2/args/1`.

use ghidorah_analysis::facts::relations::{MAX_DEPTH, MAX_INDEX};
use ghidorah_analysis::facts::{Atom, Endpoint, RefClass, RelSpec, Relation};
use ghidorah_base::{Address, ErrorCode, FuncId, Glob, Id, ImportId, SyscallId, hex};
use ghidorah_db::Program;
use ghidorah_json::Value;

use crate::errors::ToolError;
use crate::handlers::func_sections as fs;
use crate::resolve::{self, Family, Named, Target};

/// Gives the field name of the message: the path without its first `/`.
fn field(path: &str) -> &str {
    path.strip_prefix('/').unwrap_or(path)
}

/// Gives `INVALID_ARGUMENT` at `path` with the text of `details.expected`.
fn invalid(path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field(path))
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives `NOT_FOUND` at `path` for an entity of the kind `kind`.
fn not_found(path: &str, kind: &str) -> ToolError {
    ToolError::new(ErrorCode::NotFound)
        .var("kind", kind)
        .path(path)
        .detail("kind", Value::from(kind))
}

/// Gives the import whose stub or EXTERNAL address is `addr`.
fn import_at(p: &Program, addr: Address) -> Option<ImportId> {
    p.imports()
        .values()
        .find(|row| row.ext == addr || row.stub == Some(addr))
        .map(|row| row.id.clone())
}

/// Gives the function of the input `v`.
fn func(p: &Program, v: &Value, path: &str) -> Result<FuncId, ToolError> {
    let (f, _) = resolve::function(p, v, &fs::site(path))?;
    if p.func(f).is_none() {
        return Err(not_found(path, "function"));
    }
    Ok(f)
}

/// Gives the syscall number of the ID `id`.
fn syscall_of(id: &SyscallId, path: &str) -> Result<u16, ToolError> {
    if let Some(n) = id.number() {
        return Ok(n);
    }
    let name = id.name().unwrap_or_default();
    ghidorah_types::syscalls::x86_64()
        .ok()
        .and_then(|t| t.number(name))
        .ok_or_else(|| not_found(path, "syscall"))
}

/// Gives the syscall number of the input `v`: a `sys:` ID, a syscall name or a number.
fn syscall(v: &Value, path: &str) -> Result<u16, ToolError> {
    const EXPECTED: &str = "a syscall: a sys: ID, a syscall name or a number";
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).map_err(|_| invalid(path, EXPECTED));
    }
    let text = v.as_str().ok_or_else(|| invalid(path, EXPECTED))?;
    let id = match Id::parse(text) {
        Ok(Id::Syscall(id)) => id,
        Ok(_) => return Err(invalid(path, EXPECTED)),
        Err(_) => match text.parse::<u16>() {
            Ok(n) => SyscallId::by_number(n),
            Err(_) => SyscallId::by_name(text).map_err(|_| invalid(path, EXPECTED))?,
        },
    };
    syscall_of(&id, path)
}

/// Gives the endpoint of the input `v`. `sys` tells if a syscall is a valid endpoint.
fn endpoint(p: &Program, v: &Value, path: &str, sys: bool) -> Result<Endpoint, ToolError> {
    let site = fs::site(path);
    let resolved = resolve::resolve(p, v, &site)?;
    match &resolved.named {
        Named::Import(i) => return Ok(Endpoint::Import(i.clone())),
        Named::Syscall(s) if sys => return syscall_of(s, path).map(Endpoint::Syscall),
        Named::Syscall(_) => return Err(invalid(path, "a function or an import")),
        Named::Addr(a) | Named::External(a) => {
            if let Some(i) = import_at(p, *a) {
                return Ok(Endpoint::Import(i));
            }
        }
        _ => {}
    }
    match resolve::target(p, &resolved, Family::Function).map_err(|e| with_path(e, path))? {
        Target::Func(f) if p.func(f).is_some() => Ok(Endpoint::Func(f)),
        Target::Func(_) => Err(not_found(path, "function")),
        _ => Err(invalid(path, "a function, an import or a syscall")),
    }
}

/// Adds the field path `path` to an error that has none.
fn with_path(mut error: ToolError, path: &str) -> ToolError {
    if error.field_path.is_none() {
        error.field_path = Some(path.to_owned());
    }
    error
}

/// Gives the import of the input `v`.
fn import(p: &Program, v: &Value, path: &str) -> Result<ImportId, ToolError> {
    match endpoint(p, v, path, false)? {
        Endpoint::Import(i) => Ok(i),
        _ => Err(invalid(
            path,
            "an import: an imp: ID, an import name or a stub",
        )),
    }
}

/// Gives the address of the input `v`.
fn addr(p: &Program, v: &Value, path: &str) -> Result<Address, ToolError> {
    resolve::address(p, v, &fs::site(path)).map(|(a, _)| a)
}

/// Gives the integer of the input `v` in `min..=max`.
fn int(v: &Value, path: &str, min: u8, max: u8) -> Result<u8, ToolError> {
    let expected = format!("an integer from {min} to {max}");
    let n = v
        .as_u64()
        .or_else(|| v.as_str().and_then(|t| t.parse::<u64>().ok()))
        .ok_or_else(|| invalid(path, &expected))?;
    u8::try_from(n)
        .ok()
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| invalid(path, &expected))
}

/// Gives the glob of the input `v`.
fn glob(v: &Value, path: &str) -> Result<Glob, ToolError> {
    v.as_str()
        .and_then(|t| Glob::new(t).ok())
        .ok_or_else(|| invalid(path, "a glob pattern of at most 1,024 characters"))
}

/// Gives the reference class of the input `v`.
fn kind(v: &Value, path: &str) -> Result<RefClass, ToolError> {
    v.as_str().and_then(RefClass::parse).ok_or_else(|| {
        invalid(
            path,
            "a reference class (call, jump, read or write) or a reference type name",
        )
    })
}

/// Gives the number of the input `v`: an integer, `0x` hex, decimal digits or an address.
fn value(p: &Program, v: &Value, path: &str) -> Result<u64, ToolError> {
    const EXPECTED: &str = "an integer, 0x hex text or an address";
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(n) = v.as_i64() {
        return Ok(n.cast_unsigned());
    }
    let text = v.as_str().ok_or_else(|| invalid(path, EXPECTED))?;
    if let Some(n) = hex::parse_u64(text) {
        return Ok(n);
    }
    if let Ok(n) = text.parse::<u64>() {
        return Ok(n);
    }
    if let Ok(n) = text.parse::<i64>() {
        return Ok(n.cast_unsigned());
    }
    let resolved = resolve::resolve(p, v, &fs::site(path))?;
    let a = resolve::value_of(p, &resolved).map_err(|e| with_path(e, path))?;
    if a.is_ram() {
        Ok(a.off)
    } else {
        Err(invalid(path, EXPECTED))
    }
}

/// Gives the text of `details.expected` for the argument count of a relation.
fn arity(spec: &RelSpec) -> String {
    let names: Vec<&str> = spec.columns.iter().map(|c| c.name).collect();
    let optional = spec.columns.len() - spec.required();
    if optional == 0 {
        format!("{} arguments: {}", spec.columns.len(), names.join(", "))
    } else {
        format!(
            "{} to {} arguments: {}",
            spec.required(),
            spec.columns.len(),
            names.join(", ")
        )
    }
}

/// Gives the atom of the claim `claim` at the path `path`, for example `/claims/0`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for an unknown relation, a wrong argument count or an argument of
/// the wrong kind. Returns the resolver errors of an address input, for example `NOT_FOUND`.
pub fn atom(p: &Program, claim: &Value, path: &str) -> Result<Atom, ToolError> {
    let rel = claim
        .get("rel")
        .and_then(Value::as_str)
        .and_then(Relation::parse)
        .ok_or_else(|| invalid(&format!("{path}/rel"), "a relation of the catalog"))?;
    let args = claim
        .get("args")
        .and_then(Value::as_array)
        .unwrap_or_default();
    let spec = rel.spec();
    if args.len() < spec.required() || args.len() > spec.columns.len() {
        return Err(invalid(&format!("{path}/args"), &arity(spec)));
    }
    let at = |k: usize| format!("{path}/args/{k}");
    let arg = |k: usize| args.get(k).unwrap_or(&Value::Null);
    Ok(match rel {
        Relation::Calls => Atom::Calls {
            f: func(p, arg(0), &at(0))?,
            g: endpoint(p, arg(1), &at(1), true)?,
        },
        Relation::Reaches => Atom::Reaches {
            f: func(p, arg(0), &at(0))?,
            g: endpoint(p, arg(1), &at(1), false)?,
            depth: match args.get(2) {
                Some(v) => int(v, &at(2), 1, MAX_DEPTH)?,
                None => MAX_DEPTH,
            },
        },
        Relation::UsesImport => Atom::UsesImport {
            f: func(p, arg(0), &at(0))?,
            import: import(p, arg(1), &at(1))?,
        },
        Relation::RefsString => Atom::RefsString {
            f: func(p, arg(0), &at(0))?,
            glob: glob(arg(1), &at(1))?,
        },
        Relation::RefsAddr => Atom::RefsAddr {
            f: func(p, arg(0), &at(0))?,
            addr: addr(p, arg(1), &at(1))?,
        },
        Relation::Xref => Atom::Xref {
            from: addr(p, arg(0), &at(0))?,
            to: addr(p, arg(1), &at(1))?,
            kind: args.get(2).map(|v| kind(v, &at(2))).transpose()?,
        },
        Relation::ConstArg => Atom::ConstArg {
            callee: endpoint(p, arg(0), &at(0), true)?,
            index: int(arg(1), &at(1), 0, MAX_INDEX)?,
            value: value(p, arg(2), &at(2))?,
        },
        Relation::HasSyscall => Atom::HasSyscall {
            f: func(p, arg(0), &at(0))?,
            number: syscall(arg(1), &at(1))?,
        },
        Relation::Noreturn => Atom::Noreturn {
            f: func(p, arg(0), &at(0))?,
        },
        Relation::InFunc => Atom::InFunc {
            addr: addr(p, arg(0), &at(0))?,
            f: func(p, arg(1), &at(1))?,
        },
    })
}
