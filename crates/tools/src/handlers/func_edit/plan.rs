//! The plan of one `func_edit` call: the checked inputs of the action and its edits.
//!
//! The plan step reads the program only. It resolves each address and checks the site:
//!
//! | Input | Check |
//! |---|---|
//! | `target` of `create` | an instruction start in an executable region. No other function owns it. |
//! | `target` of `delete` | a function record of an agent or a user |
//! | `target` of `set_noreturn` | a function |
//! | `at` of `set_jumptable` | an indirect jump |
//! | `at` of `set_call_targets` | an indirect call or jump |
//! | `at` of `set_flow` | an instruction. `call_as_jump` needs a direct call and `jump_as_call` a direct jump. |
//! | `targets` and `flow.to` | instruction starts in executable regions. A `set_call_targets` target can be an import. |
//! | `ref` of `remove_ref` | a reference of an agent or a user |
//!
//! A `create` inside the body of a function gives `BODY_OVERLAP`, and its candidate names the
//! owner. This holds for the entry of a discovered function too. Only the entry of an agent
//! function stays a valid target, so a second `create` of it is a no-op.

use ghidorah_base::{Address, ErrorCode, FuncId, JumpTableId};
use ghidorah_db::{
    CodeUnit, Edit, FlowKind, FlowOverride, FuncRecord, Function, JtMethod, JumpTable, Program,
    Ref, RefKey, RefType, StartReason, SymKind, Tx,
};
use ghidorah_json::Value;

use super::edit::{edit_error, not_found};
use crate::args::Args;
use crate::errors::{Candidate, ToolError};
use crate::resolve::{self, Named, Site};

/// The checked action of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// A new agent function, with an optional name.
    Create {
        /// The entry.
        entry: Address,
        /// The name.
        name: Option<String>,
    },
    /// The delete of an agent function.
    Delete(FuncId),
    /// A noreturn flag.
    Noreturn(FuncId, bool),
    /// The case targets of an indirect jump.
    JumpTable(Address, Vec<Address>),
    /// A flow override, or `None` to remove it.
    Flow(Address, Option<FlowOverride>),
    /// The targets of an indirect call or jump.
    CallTargets(Address, Vec<Address>),
    /// An agent reference.
    AddRef(RefKey),
    /// The removal of an agent reference.
    RemoveRef(RefKey),
}

/// Gives `INVALID_ARGUMENT` for the argument `field` at `path` with what it expects.
fn invalid(field: &str, path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives `MISSING_ARGUMENT` for the argument `field` at `path`.
fn missing(field: &str, path: &str) -> ToolError {
    ToolError::new(ErrorCode::MissingArgument)
        .var("field", field)
        .path(path)
}

/// Resolves the address input `value` at `path`.
fn address(p: &Program, value: Option<&Value>, path: &str) -> Result<Address, ToolError> {
    let field = path.trim_start_matches('/').replace('/', ".");
    let value = value.ok_or_else(|| missing(&field, path))?;
    let site = Site { path, repair: None };
    resolve::address(p, value, &site).map(|(a, _)| a)
}

/// Resolves the function input `value` at `path`.
fn function(p: &Program, value: Option<&Value>, path: &str) -> Result<FuncId, ToolError> {
    let value = value.ok_or_else(|| missing("target", path))?;
    let site = Site { path, repair: None };
    resolve::function(p, value, &site).map(|(f, _)| f)
}

/// Gives the flow kind of the instruction at `at`, or `None` with no instruction there.
fn flow_at(p: &Program, at: Address) -> Option<FlowKind> {
    if !at.is_ram() {
        return None;
    }
    p.code_unit(at.off).map(|u| match u {
        CodeUnit::Insn { flow, .. } => *flow,
    })
}

/// Checks that `at` is an instruction start in an executable region.
fn code_target(p: &Program, at: Address, field: &str, path: &str) -> Result<Address, ToolError> {
    if at.is_ram() && p.is_code_target(at) {
        Ok(at)
    } else {
        Err(invalid(
            field,
            path,
            "an instruction start in an executable region",
        ))
    }
}

/// Checks that no function owns the new entry `entry`. The entry of an agent function is the
/// one exception: a second `create` of it changes nothing.
fn free_entry(p: &Program, entry: Address) -> Result<Address, ToolError> {
    let Some(owner) = p.owner_of(entry) else {
        return Ok(entry);
    };
    let again = owner.0 == entry
        && p.base()
            .funcs()
            .get(owner)
            .is_some_and(|f| f.start_reason == StartReason::Agent);
    if again {
        return Ok(entry);
    }
    let id = owner.to_string();
    let mut candidate = Candidate::text(&id, &format!("function at {}", owner.0));
    candidate.id = Some(id);
    candidate.addr = Some(owner.0.to_string());
    candidate.kind = Some("function".to_owned());
    Err(ToolError::new(ErrorCode::BodyOverlap)
        .path("/target")
        .candidates(vec![candidate]))
}

/// Gives the site `at` when its instruction has a flow of `want`.
fn site(p: &Program, args: &Args, want: &[FlowKind], expected: &str) -> Result<Address, ToolError> {
    let at = address(p, args.get("at"), "/at")?;
    match flow_at(p, at) {
        Some(flow) if want.is_empty() || want.contains(&flow) => Ok(at),
        _ => Err(invalid("at", "/at", expected)),
    }
}

/// Gives the case targets of `targets`. `imports` lets an import name its EXTERNAL address.
fn targets(p: &Program, args: &Args, imports: bool) -> Result<Vec<Address>, ToolError> {
    let list = args.list("targets").unwrap_or_default();
    let mut out = Vec::with_capacity(list.len());
    for (i, value) in list.iter().enumerate() {
        let path = format!("/targets/{i}");
        let site = Site {
            path: &path,
            repair: None,
        };
        let resolved = resolve::resolve(p, value, &site)?;
        if let (true, Named::Import(id)) = (imports, &resolved.named) {
            let row = p
                .imports()
                .get(id)
                .ok_or_else(|| not_found("import", &id.to_string()))?;
            out.push(row.ext);
            continue;
        }
        let at = resolve::address(p, value, &site)?.0;
        out.push(code_target(p, at, "targets", &path)?);
    }
    Ok(out)
}

/// Gives the flow override of `flow` for the instruction at `at`.
fn flow(p: &Program, args: &Args, at: Address) -> Result<Option<FlowOverride>, ToolError> {
    let obj = args.get("flow");
    let kind = obj
        .and_then(|f| f.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let unit = flow_at(p, at);
    match kind {
        "fallthrough" => {
            let to = address(p, obj.and_then(|f| f.get("to")), "/flow/to")?;
            let to = code_target(p, to, "flow.to", "/flow/to")?;
            Ok(Some(FlowOverride::Fallthrough(to)))
        }
        "call_as_jump" if unit == Some(FlowKind::Call) => Ok(Some(FlowOverride::CallAsJump)),
        "jump_as_call" if unit == Some(FlowKind::Jmp) => Ok(Some(FlowOverride::JumpAsCall)),
        "clear" => Ok(None),
        "call_as_jump" => Err(invalid("at", "/at", "a direct call")),
        _ => Err(invalid("at", "/at", "a direct jump")),
    }
}

/// Gives the key of the reference `ref`.
fn ref_key(p: &Program, args: &Args) -> Result<RefKey, ToolError> {
    let obj = args.get("ref");
    let from = address(p, obj.and_then(|r| r.get("from")), "/ref/from")?;
    let to = address(p, obj.and_then(|r| r.get("to")), "/ref/to")?;
    let kind = obj
        .and_then(|r| r.get("kind"))
        .and_then(Value::as_str)
        .and_then(RefType::parse)
        .ok_or_else(|| invalid("ref.kind", "/ref/kind", "a reference type name"))?;
    Ok(RefKey {
        from,
        op_index: 0,
        to,
        kind,
    })
}

impl Plan {
    /// Checks the inputs of the call `args` on `p` and gives the plan.
    ///
    /// # Errors
    ///
    /// Returns the resolver errors, `INVALID_ARGUMENT` for a site of the wrong kind,
    /// `MISSING_ARGUMENT` for `flow.to`, and `NOT_FOUND` for a function or a reference that
    /// the action needs. Returns `BODY_OVERLAP` for a `create` in the body of a function.
    pub fn of(p: &Program, args: &Args) -> Result<Self, ToolError> {
        match args.action().unwrap_or_default() {
            "create" => {
                let at = address(p, args.get("target"), "/target")?;
                let entry = free_entry(p, code_target(p, at, "target", "/target")?)?;
                Ok(Self::Create {
                    entry,
                    name: args.str("name").map(str::to_owned),
                })
            }
            "delete" => {
                let id = function(p, args.get("target"), "/target")?;
                if p.base().funcs().get(id).is_none() {
                    return Err(not_found("agent function", &id.to_string()));
                }
                Ok(Self::Delete(id))
            }
            "set_noreturn" => {
                let id = function(p, args.get("target"), "/target")?;
                if p.func(id).is_none() {
                    return Err(not_found("function", &id.to_string()));
                }
                Ok(Self::Noreturn(id, args.bool("noreturn").unwrap_or(false)))
            }
            "set_jumptable" => {
                let at = site(p, args, &[FlowKind::IJmp], "an indirect jump")?;
                Ok(Self::JumpTable(at, targets(p, args, false)?))
            }
            "set_flow" => {
                let at = site(p, args, &[], "an instruction start")?;
                Ok(Self::Flow(at, flow(p, args, at)?))
            }
            "set_call_targets" => {
                let want = [FlowKind::ICall, FlowKind::IJmp];
                let at = site(p, args, &want, "an indirect call or jump")?;
                Ok(Self::CallTargets(at, targets(p, args, true)?))
            }
            "add_ref" => Ok(Self::AddRef(ref_key(p, args)?)),
            _ => {
                let key = ref_key(p, args)?;
                if p.base().refs().get(&key).is_none() {
                    let text = key
                        .id()
                        .map_or_else(|_| key.from.to_string(), |i| i.to_string());
                    return Err(not_found("agent reference", &text));
                }
                Ok(Self::RemoveRef(key))
            }
        }
    }

    /// Gives the ID text of the fact that the plan changes: a `fn:` ID, the site address or a
    /// `ref:` ID.
    #[must_use]
    pub fn target(&self) -> String {
        match self {
            Self::Create { entry, .. } => FuncId(*entry).to_string(),
            Self::Delete(id) | Self::Noreturn(id, _) => id.to_string(),
            Self::JumpTable(at, _) | Self::Flow(at, _) | Self::CallTargets(at, _) => at.to_string(),
            Self::AddRef(key) | Self::RemoveRef(key) => key
                .id()
                .map_or_else(|_| key.from.to_string(), |id| id.to_string()),
        }
    }

    /// Gives the function whose override conflicts the result reports.
    #[must_use]
    pub fn focus(&self, p: &Program) -> Option<FuncId> {
        match self {
            Self::Create { entry, .. } => Some(FuncId(*entry)),
            Self::Delete(id) | Self::Noreturn(id, _) => Some(*id),
            Self::JumpTable(at, _) | Self::Flow(at, _) | Self::CallTargets(at, _) => {
                p.owner_of(*at)
            }
            Self::AddRef(key) | Self::RemoveRef(key) => p.owner_of(key.from),
        }
    }

    /// Applies the edits of the plan in `tx`.
    ///
    /// # Errors
    ///
    /// Returns the tool error of the first edit that fails.
    pub fn apply(&self, tx: &mut Tx<'_>, args: &Args) -> Result<(), ToolError> {
        let edits = match self {
            Self::Create { entry, name } => {
                let func = Function::new(*entry, StartReason::Agent, 100, tx.origin().source);
                let mut list = vec![Edit::CreateFunction(Box::new(FuncRecord {
                    func,
                    vars: Vec::new(),
                    plate: None,
                }))];
                if let Some(text) = name {
                    list.push(Edit::SetName {
                        addr: *entry,
                        key: None,
                        kind: SymKind::Function,
                        primary: true,
                        name: Some(tx.fact(text.clone())),
                        evidence: Vec::new(),
                    });
                }
                list
            }
            Self::Delete(id) => vec![Edit::DeleteFunction {
                id: *id,
                cascade: true,
            }],
            Self::Noreturn(id, value) => vec![Edit::SetNoreturn {
                id: *id,
                noreturn: Some(tx.fact(*value)),
            }],
            Self::JumpTable(at, list) => {
                let table = JumpTable {
                    base: None,
                    entry_size: 0,
                    count: u16::try_from(list.len()).unwrap_or(u16::MAX),
                    targets: list.clone(),
                    method: JtMethod::Agent,
                    resolved: true,
                };
                vec![Edit::SetJumpTable {
                    id: JumpTableId(*at),
                    table: Some(tx.fact(table)),
                }]
            }
            Self::Flow(at, flow) => vec![Edit::SetFlowOverride {
                at: *at,
                flow: flow.clone().map(|f| tx.fact(f)),
            }],
            Self::CallTargets(at, list) => vec![Edit::SetFlowOverride {
                at: *at,
                flow: Some(tx.fact(FlowOverride::IndirectTargets(list.clone()))),
            }],
            Self::AddRef(key) => vec![Edit::AddRef {
                fact: tx.fact(Ref {
                    key: *key,
                    primary: false,
                }),
            }],
            Self::RemoveRef(key) => vec![Edit::RemoveRef { key: *key }],
        };
        for e in edits {
            tx.apply(e).map_err(|e| edit_error(&e, args))?;
        }
        Ok(())
    }
}
