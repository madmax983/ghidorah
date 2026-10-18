//! `type_edit`: apply a C type or a prototype (design Sections 9.5 and 10.4, tool 20).
//!
//! | `target` | Argument | Fact | Band |
//! |---|---|---|---|
//! | a function: `fn:`, an entry or a name | `signature` | `SetSignature` | 800 |
//! | a variable: `var:` | `type` | `SetVarFact` with the type | - |
//! | another address | `type` | `SetDataDef` with the size of the type | 100 |
//!
//! The C text parses in `sig` or `type` mode (design Section 9.2) into the type store of the
//! program. The journal line keeps the text, so a reopen gives the same types. A text that
//! does not parse gives `C_PARSE_ERROR` with `details.errors`. The name in a prototype does
//! not rename the function.
//!
//! The result is `{ applied: { target, old, new }, rev, analysis? }`. `old` and `new` are C
//! texts, and `old` is `null` when no fact was there. A signature re-runs only the bands 800
//! and above, so the other analysis facts stay (AC-210). A data definition re-runs from band
//! 100. `dry_run: true` gives the planned edits and changes nothing.

use ghidorah_base::{Address, ErrorCode, FuncId, Id, VarId};
use ghidorah_db::{DataDef, Edit, EditError, Invalid, Program, Tx, VarField};
use ghidorah_json::{Object, Value};
use ghidorah_types::{TypeId, layout};

use super::func_edit::edit::{self, edit_error, not_found};
use super::type_get::parse_error;
use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::resolve::{self, Site};
use crate::session::Session;
use crate::spec::{
    Annotations, ArgKind, ArgSpec, Example, FuelSpec, Group, GroupRule, Profile, Role, ToolSpec,
};

/// The longest C text.
pub const MAX_C: usize = 4_000;

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The function, the variable or the data: an address, a name, a fn: ID or a var: ID.",
    )
    .required(),
    ArgSpec::new(
        "type",
        Role::Param,
        ArgKind::Str(MAX_C),
        "The C type text of a variable or of the data at an address, for example char [16].",
    ),
    ArgSpec::new(
        "signature",
        Role::Param,
        ArgKind::Str(MAX_C),
        "One C prototype of a function, for example int check(const char *input).",
    ),
];

const APPLIED: &[Field] = &[
    Field::req("target", OutputShape::Str),
    Field::req("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("new", OutputShape::Str),
];

const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
];

const FIELDS: &[Field] = &[
    Field::req("applied", OutputShape::Obj(APPLIED)),
    Field::req("rev", OutputShape::Int),
    Field::opt("analysis", OutputShape::Obj(ANALYSIS)),
];

/// `type_edit`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Apply a C type",
    summary: "Apply a C type or a prototype to an address, a function or a variable.",
    description: "Apply a C type or a prototype to an address, a function or a variable. \
                  Send signature with one C prototype for a function. \
                  Send type with C type text for a var: ID or for the data at an address. \
                  Text that does not parse gives C_PARSE_ERROR.",
    args: ARGS,
    groups: &[Group {
        members: &["type", "signature"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    analysis_affecting: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: r#"{"target":"fn:0x11e0","signature":"int check_password(const char *input)"}"#,
            golden: "tests/golden/tools/type_edit.1.json",
        },
        Example {
            args: r#"{"target":"0x2004","type":"char [26]"}"#,
            golden: "tests/golden/tools/type_edit.2.json",
        },
        Example {
            args: r#"{"target":"var:0x11e0/param:0","type":"const char *","dry_run":true}"#,
            golden: "tests/golden/tools/type_edit.3.json",
        },
    ],
    force: true,
    fuel: Some(FuelSpec {
        default: super::func_edit::DEFAULT_STEPS,
        cap: super::func_edit::MAX_STEPS,
    }),
    ..ToolSpec::base("type_edit", run)
};

/// What a call applies its C text to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// The signature of a function.
    Func(FuncId),
    /// The type of a variable.
    Var(VarId),
    /// A data definition at an address.
    Data(Address),
}

impl Target {
    /// Gives the ID text: a `fn:` ID, a `var:` ID or an address.
    fn id(&self) -> String {
        match self {
            Self::Func(f) => f.to_string(),
            Self::Var(v) => v.to_string(),
            Self::Data(a) => a.to_string(),
        }
    }

    /// Gives the C text of the current fact, or `None`.
    fn old(&self, p: &Program) -> Option<String> {
        let ty = match self {
            Self::Func(f) => p.func(*f).and_then(|v| v.sig).map(|s| s.value),
            Self::Var(v) => p.var(v).ty.map(|t| t.value),
            Self::Data(a) => p.data_def(a.off).map(|d| d.value.ty),
        }?;
        p.types().store().c_text(ty).ok()
    }
}

/// Gives `INVALID_ARGUMENT` for the argument `field` with what it expects.
fn invalid(field: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .path(&format!("/{field}"))
        .detail("expected", Value::from(expected))
}

/// Gives the target of the call: a function for `signature`, a variable or an address for
/// `type`.
fn target(p: &Program, args: &Args, signature: bool) -> Result<Target, ToolError> {
    let value = args
        .get("target")
        .ok_or_else(|| ToolError::new(ErrorCode::MissingArgument).var("field", "target"))?;
    let site = Site {
        path: "/target",
        repair: None,
    };
    if let Some(Ok(Id::Var(var))) = value
        .as_str()
        .filter(|t| t.starts_with("var:"))
        .map(Id::parse)
    {
        if signature {
            return Err(invalid(
                "signature",
                "a function target: send type for a variable",
            ));
        }
        if p.func(var.func).is_none() {
            return Err(not_found("function", &var.func.to_string()));
        }
        return Ok(Target::Var(var));
    }
    let resolved = resolve::resolve(p, value, &site)?;
    let func_id = matches!(resolved.named, resolve::Named::Func(_));
    if signature {
        let (func, _) = resolve::function(p, value, &site)?;
        if p.func(func).is_none() {
            return Err(not_found("function", &func.to_string()));
        }
        return Ok(Target::Func(func));
    }
    if func_id {
        return Err(invalid(
            "type",
            "an address or a var: ID: send signature for a function",
        ));
    }
    let (at, _) = resolve::address(p, value, &site)?;
    if !at.is_ram() || p.code_unit(at.off).is_some() || p.owner_of(at).is_some() {
        return Err(invalid(
            "target",
            "an address of data, outside code and functions",
        ));
    }
    Ok(Target::Data(at))
}

/// Gives the edit error of a data definition: an overlap names the target.
fn data_error(error: &EditError, args: &Args) -> ToolError {
    match error {
        EditError::Invalid(Invalid::Overlap { .. }) => {
            invalid("target", "an address with no other data definition")
        }
        other => edit_error(other, args),
    }
}

/// Parses `text` for `target` in `tx` and applies the fact. Gives the C text of the new type.
fn apply(tx: &mut Tx<'_>, args: &Args, target: &Target, text: &str) -> Result<String, ToolError> {
    let (ty, e): (TypeId, Edit) = match target {
        Target::Func(id) => {
            let parsed = tx
                .parse_sig(text)
                .map_err(|e| parse_error(&e, "/signature"))?;
            let sig = Some(tx.fact(parsed.ty));
            (parsed.ty, Edit::SetSignature { id: *id, sig })
        }
        Target::Var(var) => {
            let ty = tx.parse_type(text).map_err(|e| parse_error(&e, "/type"))?;
            let field = VarField::Type(Some(tx.fact(ty)));
            (
                ty,
                Edit::SetVarFact {
                    var: var.clone(),
                    field,
                },
            )
        }
        Target::Data(at) => {
            let ty = tx.parse_type(text).map_err(|e| parse_error(&e, "/type"))?;
            let types = tx.program().types();
            let len = layout::sysv(types.store(), ty, types.model())
                .ok()
                .and_then(|l| u32::try_from(l.size).ok())
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("type", "a C type with a known size"))?;
            let def = Some(tx.fact(DataDef { ty, len }));
            (ty, Edit::SetDataDef { at: *at, def })
        }
    };
    let data = matches!(target, Target::Data(_));
    tx.apply(e).map_err(|err| {
        if data {
            data_error(&err, args)
        } else {
            edit_error(&err, args)
        }
    })?;
    Ok(tx.program().types().store().c_text(ty).unwrap_or_default())
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let signature = args.str("signature");
    let text = signature
        .or_else(|| args.str("type"))
        .unwrap_or_default()
        .to_owned();
    let target = target(p, args, signature.is_some())?;
    let old = target.old(p);
    let focus = match &target {
        Target::Func(f) => Some(*f),
        Target::Var(_) | Target::Data(_) => None,
    };
    let out = edit::run(session, args, ctx, focus, |tx| {
        apply(tx, args, &target, &text)
    })?;
    let mut applied = Object::new();
    applied.push("target", Value::from(target.id()));
    applied.push("old", old.map_or(Value::Null, Value::from));
    applied.push("new", Value::from(out.value));
    let mut result = Object::new();
    result.push("applied", Value::Object(applied));
    result.push("rev", Value::from(out.rev));
    if out.report.is_some() {
        result.push("analysis", edit::analysis(out.report, ctx));
    }
    Ok(Payload::Object(result))
}
