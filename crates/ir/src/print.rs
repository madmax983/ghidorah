//! The IR text and JSON printers (design Sections 6.1 and 10.4, `func_get include ir`).
//!
//! Both printers show the instructions of an [`Arena`] in address order, then the ops
//! outside each instruction (L1 phis and pass ops). The output is deterministic: equal
//! arenas give equal bytes.
//!
//! Text form, one line for each instruction and each op:
//!
//! ```text
//! 0x401000 len=3
//!   op:0x401000:0 v0 = Get.64 rax
//!   op:0x401000:1 v1 = Add.64 v0 0x8
//!   op:0x401000:2 Put.64 rax v1
//! ```
//!
//! An op shows its output value, its opcode with its width, the aux byte (a flag operation,
//! a condition, or `#n` for an input width) and its arguments. A `Syscall` or `Intrinsic`
//! op shows its effect: `name=.. defs=[..] uses=[..] mem=..`. A `Phi` op shows its
//! arguments in brackets. The ops outside each instruction follow a line `extra`.
//!
//! JSON form: `{"insns":[{"addr","len","ops":[op]}],"extra":[op]}`. Each op is
//! `{"id","opc","w","out"?,"sub"?,"args":[..],"effect"?,"phi"?}`. An argument is `v<n>`
//! for a value, `0x..` for a constant and the location name for a location. `sub` is the
//! flag operation name, the condition name or the input width.

use std::fmt::Write as _;

use crate::arena::Arena;
use crate::loc::LocSet;
use crate::op::{Arg, IntrinsicId, MemEffect, Op, Opc};

/// Gives the names of intrinsic instructions. The ISA crate gives the meaning of an
/// [`IntrinsicId`], so it implements this trait.
pub trait IntrinsicNames {
    /// Gives the name of an intrinsic instruction, or `None` for an unknown number.
    fn name(&self, id: IntrinsicId) -> Option<&'static str>;
}

/// The names of no intrinsic instruction. The printers then show `#<number>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoNames;

impl IntrinsicNames for NoNames {
    fn name(&self, _id: IntrinsicId) -> Option<&'static str> {
        None
    }
}

/// Gives the name of an intrinsic number: its name, or `#<number>`.
fn name_of(names: &dyn IntrinsicNames, id: IntrinsicId) -> String {
    names
        .name(id)
        .map_or_else(|| format!("#{}", id.0), str::to_owned)
}

/// Gives the text of a memory effect: `none`, `read:n`, `write:n` or `readwrite:n`.
fn mem_text(mem: MemEffect) -> String {
    match mem {
        MemEffect::None => "none".to_owned(),
        MemEffect::Read { size } => format!("read:{size}"),
        MemEffect::Write { size } => format!("write:{size}"),
        MemEffect::ReadWrite { size } => format!("readwrite:{size}"),
    }
}

/// Gives the location names of a set.
fn loc_names(set: &LocSet) -> Vec<String> {
    set.iter().map(|l| l.to_string()).collect()
}

/// Gives the arguments of an op that the printers show. A `Syscall`, `Intrinsic` or `Phi`
/// op hides its side-table index in argument 0.
fn shown_args(op: &Op) -> impl Iterator<Item = &Arg> {
    let skip = usize::from(matches!(op.opc, Opc::Syscall | Opc::Intrinsic | Opc::Phi));
    op.a.iter().skip(skip).filter(|a| **a != Arg::Nil)
}

/// The aux byte of an op as the printers show it.
enum Sub {
    /// A flag operation or a condition name.
    Name(String),
    /// An input width.
    Width(u8),
}

/// Gives the aux byte of an op, or `None` when it has no meaning.
fn sub_of(op: &Op) -> Option<Sub> {
    match (op.flag_op(), op.cc()) {
        (Some(f), _) => Some(Sub::Name(format!("{f:?}"))),
        (None, Some(cc)) => Some(Sub::Name(cc.name().to_owned())),
        (None, None) if op.sub != 0 => Some(Sub::Width(op.sub)),
        (None, None) => None,
    }
}

/// Gives the text of one op, without the op ID.
#[must_use]
pub fn op_text(arena: &Arena, op: &Op, names: &dyn IntrinsicNames) -> String {
    let mut out = String::new();
    if let Some(v) = op.out {
        let _ = write!(out, "{v} = ");
    }
    let _ = write!(out, "{}.{}", op.opc, op.w);
    match sub_of(op) {
        Some(Sub::Name(n)) => {
            let _ = write!(out, " {n}");
        }
        Some(Sub::Width(w)) => {
            let _ = write!(out, " #{w}");
        }
        None => {}
    }
    if let Some(e) = arena.effect(op) {
        let _ = write!(
            out,
            " name={} defs=[{}] uses=[{}] mem={}",
            name_of(names, e.name),
            loc_names(&e.defs).join(","),
            loc_names(&e.uses).join(","),
            mem_text(e.mem)
        );
    }
    if let Some(list) = arena.phi_args(op) {
        let items: Vec<String> = list.iter().map(ToString::to_string).collect();
        let _ = write!(out, " [{}]", items.join(", "));
    }
    for arg in shown_args(op) {
        let _ = write!(out, " {arg}");
    }
    out
}

/// Gives the ops outside each instruction: the ops after the last instruction op.
fn extra_ops(arena: &Arena) -> &[Op] {
    let end = arena
        .insns()
        .iter()
        .filter_map(|s| s.first.checked_add(s.count))
        .max()
        .and_then(|e| usize::try_from(e).ok())
        .unwrap_or(0);
    arena.ops().get(end..).unwrap_or_default()
}

/// Gives the text form of an arena.
#[must_use]
pub fn text(arena: &Arena, names: &dyn IntrinsicNames) -> String {
    let mut out = String::new();
    for span in arena.insns() {
        let _ = writeln!(out, "{:#x} len={}", span.addr, span.len);
        for op in arena.span_ops(span).unwrap_or_default() {
            let _ = writeln!(out, "  {} {}", op.id, op_text(arena, op, names));
        }
    }
    let extra = extra_ops(arena);
    if !extra.is_empty() {
        out.push_str("extra\n");
        for op in extra {
            let _ = writeln!(out, "  {} {}", op.id, op_text(arena, op, names));
        }
    }
    out
}

/// Writes a JSON string. The printers write only ASCII names, so the escape covers the
/// quote and the backslash.
fn quoted(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

/// Writes a JSON array of strings.
fn string_list(out: &mut String, items: impl IntoIterator<Item = String>) {
    out.push('[');
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        quoted(out, &item);
    }
    out.push(']');
}

/// Writes one op as a JSON object.
fn op_json(out: &mut String, arena: &Arena, op: &Op, names: &dyn IntrinsicNames) {
    out.push_str("{\"id\":");
    quoted(out, &op.id.to_string());
    out.push_str(",\"opc\":");
    quoted(out, op.opc.name());
    let _ = write!(out, ",\"w\":{}", op.w);
    if let Some(v) = op.out {
        out.push_str(",\"out\":");
        quoted(out, &v.to_string());
    }
    match sub_of(op) {
        Some(Sub::Name(n)) => {
            out.push_str(",\"sub\":");
            quoted(out, &n);
        }
        Some(Sub::Width(w)) => {
            let _ = write!(out, ",\"sub\":{w}");
        }
        None => {}
    }
    out.push_str(",\"args\":");
    string_list(out, shown_args(op).map(ToString::to_string));
    if let Some(e) = arena.effect(op) {
        out.push_str(",\"effect\":{\"name\":");
        quoted(out, &name_of(names, e.name));
        out.push_str(",\"defs\":");
        string_list(out, loc_names(&e.defs));
        out.push_str(",\"uses\":");
        string_list(out, loc_names(&e.uses));
        out.push_str(",\"mem\":");
        quoted(out, &mem_text(e.mem));
        out.push('}');
    }
    if let Some(list) = arena.phi_args(op) {
        out.push_str(",\"phi\":");
        string_list(out, list.iter().map(ToString::to_string));
    }
    out.push('}');
}

/// Writes a list of ops as JSON array items.
fn ops_json(out: &mut String, arena: &Arena, ops: &[Op], names: &dyn IntrinsicNames) {
    for (k, op) in ops.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        op_json(out, arena, op, names);
    }
}

/// Gives the JSON form of an arena on one line.
#[must_use]
pub fn json(arena: &Arena, names: &dyn IntrinsicNames) -> String {
    let mut out = String::from("{\"insns\":[");
    for (i, span) in arena.insns().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"addr\":\"{:#x}\",\"len\":{},\"ops\":[",
            span.addr, span.len
        );
        ops_json(
            &mut out,
            arena,
            arena.span_ops(span).unwrap_or_default(),
            names,
        );
        out.push_str("]}");
    }
    out.push_str("],\"extra\":[");
    ops_json(&mut out, arena, extra_ops(arena), names);
    out.push_str("]}");
    out
}
