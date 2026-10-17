//! The items of `xref_list`: one reference with its source function, name, path to an import,
//! context and argument values.

use std::collections::BTreeSet;

use ghidorah_analysis::callargs::{self, ArgValue};
use ghidorah_base::{Address, Caps, Fuel, StringId, SyscallId};
use ghidorah_db::{Program, RefKey, RefType, Types};
use ghidorah_json::{Object, Value};
use ghidorah_x86::Flow;

use super::sites::{Found, classes};
use crate::dispatch::{Item, KeyPart, SortKey};
use crate::handlers::func_sections::{self as fs, Namer};

/// The settings of one call.
pub struct Query {
    /// The reference classes of the `kinds` filter. Empty keeps every class.
    pub classes: BTreeSet<String>,
    /// The number of instructions before each site.
    pub context: usize,
    /// `true` adds the argument values.
    pub args: bool,
    /// The caps of binary text.
    pub caps: Caps,
}

/// Gives the value of one argument (design Section 10.4).
pub fn arg_value(p: &Program, v: &ArgValue, caps: Caps) -> Value {
    match v {
        ArgValue::Int(n) => Value::object([("kind", Value::from("int")), ("v", fs::hex(*n))]),
        ArgValue::Str { addr, text } => {
            let shown = fs::string_text(p, *addr, caps)
                .unwrap_or_else(|| fs::bin_text(text.as_bytes(), caps));
            Value::object([
                ("kind", Value::from("str")),
                ("id", Value::from(StringId(Address::ram(*addr)).to_string())),
                ("text", shown),
            ])
        }
        ArgValue::Func(f) => Value::object([
            ("kind", Value::from("func")),
            ("id", Value::from(f.to_string())),
        ]),
        ArgValue::Addr(a) => Value::object([("kind", Value::from("addr")), ("v", fs::hex(*a))]),
        ArgValue::Unknown => Value::object([("kind", Value::from("unknown"))]),
    }
}

/// Gives the parameter names of the callee at `to`: the Tier-0 prototype of its import or of
/// its name.
fn param_names(p: &Program, to: Address) -> Vec<Option<String>> {
    let import = p
        .imports()
        .values()
        .find(|r| r.stub == Some(to) || r.ext == to)
        .and_then(|r| r.id.name().map(str::to_owned));
    let name = import.or_else(|| p.name(to).filter(|n| !n.is_default()).map(|n| n.text));
    name.and_then(|n| Types::prototype(&n))
        .map(|proto| proto.sig.params.iter().map(|q| q.name.clone()).collect())
        .unwrap_or_default()
}

/// Gives the argument values of the call or jump at `site` to `to`.
fn args_at(p: &Program, site: u64, to: Address, q: &Query, fuel: &mut Fuel) -> Value {
    let Ok(values) = callargs::at(p, site, fuel) else {
        return Value::Array(Vec::new());
    };
    let regs = ghidorah_analysis::cc::conv_of(p).int_args;
    let names = param_names(p, to);
    let list = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mut out = Object::new();
            out.push("index", Value::from(i));
            out.push("reg", Value::from(regs.get(i).copied().unwrap_or_default()));
            if let Some(Some(name)) = names.get(i) {
                out.push("name", Value::from(name.as_str()));
            }
            out.push("value", arg_value(p, v, q.caps));
            Value::Object(out)
        })
        .collect();
    Value::Array(list)
}

/// Gives the display texts of up to `n` instructions before `site` in its function.
fn context(p: &Program, site: u64, n: usize, namer: &Namer) -> Value {
    let Some(owner) = p.owner_of(Address::ram(site)) else {
        return Value::Array(Vec::new());
    };
    let units = fs::body_units(p, owner);
    let at = units.iter().position(|(a, _)| *a == site).unwrap_or(0);
    let list = units
        .get(at.saturating_sub(n)..at)
        .unwrap_or_default()
        .iter()
        .filter_map(|(a, _)| fs::decode(p, *a))
        .map(|insn| {
            fs::row(p, &insn, namer)
                .get("t")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    Value::Array(list)
}

/// Gives the item of one found reference.
pub fn item(p: &Program, f: &Found, q: &Query, namer: &Namer, fuel: &mut Fuel) -> Value {
    let key = f.key;
    let mut out = Object::new();
    out.push("from", fs::addr(key.from));
    if let Some(owner) = p.owner_of(key.from) {
        out.push("from_func", fs::func_ref(p, owner, namer));
    }
    out.push("to", fs::addr(key.to));
    out.push("to_name", Value::from(namer.of(p, key.to)));
    out.push("kind", Value::from(key.kind.name()));
    if let Some(via) = f.via {
        out.push("via", Value::from(via));
    }
    out.push("op_index", Value::from(key.op_index));
    out.push("source", Value::from(f.source));
    let insn = key
        .from
        .is_ram()
        .then(|| fs::decode(p, key.from.off))
        .flatten();
    if let (true, Some(insn)) = (q.context > 0, insn.as_ref()) {
        let row = fs::row(p, insn, namer);
        out.push("insn", row.get("t").cloned().unwrap_or_default());
        out.push("context", context(p, key.from.off, q.context, namer));
    }
    let flow = insn.as_ref().map(ghidorah_x86::Insn::flow);
    let call_like = matches!(
        flow,
        Some(Flow::Call | Flow::ICall | Flow::Jmp | Flow::IJmp)
    );
    if q.args && key.kind.is_flow() && call_like {
        out.push("args", args_at(p, key.from.off, key.to, q, fuel));
    }
    Value::Object(out)
}

/// Gives the sort key of a reference of target `index`.
pub fn ref_key(index: usize, key: &RefKey, code: u64) -> SortKey {
    let space = |a: Address| u64::from(a.space.code());
    SortKey(vec![
        KeyPart::Int(u64::try_from(index).unwrap_or(u64::MAX)),
        KeyPart::Int(space(key.from)),
        KeyPart::Int(key.from.off),
        KeyPart::Int(space(key.to)),
        KeyPart::Int(key.to.off),
        KeyPart::Int(code),
        KeyPart::Int(u64::from(key.op_index.cast_unsigned())),
    ])
}

/// The class of a syscall site in the sort key: after every reference type code.
const SYSCALL_CODE: u64 = 0x100;

/// Gives the items of the references that pass the class filter, one per sort key.
pub fn ref_items(
    p: &Program,
    refs: &[Found],
    q: &Query,
    namer: &Namer,
    fuel: &mut Fuel,
) -> Vec<Item> {
    let mut items = Vec::new();
    let mut keys = BTreeSet::new();
    for f in refs {
        let keep =
            q.classes.is_empty() || classes(p, &f.key).iter().any(|c| q.classes.contains(*c));
        let sort = ref_key(f.target, &f.key, u64::from(f.key.kind.code()));
        if keep && keys.insert(sort.clone()) {
            items.push(Item {
                key: sort,
                value: item(p, f, q, namer, fuel),
            });
        }
    }
    items
}

/// Gives the items of the syscall sites of the `sys:` targets.
pub fn syscall_items(
    p: &Program,
    syscalls: &[(usize, SyscallId)],
    q: &Query,
    namer: &Namer,
    fuel: &mut Fuel,
) -> Vec<Item> {
    if syscalls.is_empty() || !(q.classes.is_empty() || q.classes.contains("syscall")) {
        return Vec::new();
    }
    let sites = ghidorah_analysis::syscalls::sites(p, fuel);
    let mut items = Vec::new();
    for (index, id) in syscalls {
        for site in sites.iter().filter(|s| s.id().as_ref() == Some(id)) {
            let from = Address::ram(site.site);
            let mut out = Object::new();
            out.push("from", fs::addr(from));
            out.push("from_func", fs::func_ref(p, site.func, namer));
            out.push("to", Value::from(id.to_string()));
            out.push("to_name", Value::from(id.name().unwrap_or_default()));
            out.push("kind", Value::from("syscall"));
            out.push("op_index", Value::from(0));
            out.push("source", Value::from("analysis"));
            if q.args {
                let list = site.args.iter().enumerate().map(|(i, v)| {
                    Value::object([
                        ("index", Value::from(i)),
                        ("value", arg_value(p, v, q.caps)),
                    ])
                });
                out.push("args", Value::Array(list.collect()));
            }
            let key = RefKey {
                from,
                op_index: 0,
                to: from,
                kind: RefType::Param,
            };
            items.push(Item {
                key: ref_key(*index, &key, SYSCALL_CODE),
                value: Value::Object(out),
            });
        }
    }
    items
}
