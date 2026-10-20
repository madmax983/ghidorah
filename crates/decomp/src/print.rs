//! The C printer (design Section 8.3).
//!
//! [`print()`] walks the statement tree of a [`Decomp`] with an explicit stack and gives one
//! [`Line`] for each line of text. Each line holds the ops that it shows, so the line map
//! ([`crate::linemap`]) can map it to its instructions.
//!
//! | Tree | Text |
//! |---|---|
//! | `Block(n)` | one line for each statement of `n` |
//! | `If` | `if (c) {`, the branch, `} else {`, the other branch, `}` |
//! | `Loop` | `while (c) {`, `for (init; c; step) {`, `do {` .. `} while (c);` or `while (true) {` |
//! | `Switch` | `switch (x) {`, `case i:` lines, each arm with `break;` |
//! | `Goto(n)`, `Label(n)` | `goto L_<addr>;` and `L_<addr>:` |
//! | `Break`, `Continue` | `break;` and `continue;` |
//!
//! Rules of the text:
//!
//! - Expressions use precedence climbing with the numbers of [`crate::precedence`].
//! - A negated condition flips its compare operator: `!(a < b)` prints as `a >= b`.
//! - A cast shows only where a width changes or an operand needs a signed type.
//! - A `while` loop prints as `for` only when its init, condition and step on one variable
//!   are adjacent, and no `continue` goes to its head.
//! - A string literal prints inline as escaped C text. A name from the binary prints with
//!   the escapes of `BinText`.
//! - Call names come from symbols, stub names and `sys:` IDs. The argument count comes from
//!   the signature or the Tier-0 prototype of the callee, then from the parameter recovery.
//! - Default variable names: `param_N`, `local_<hex>` for a stack slot and `v<N>` for a
//!   register value. An agent name wins.
//! - Comments: a PLATE comment comes before the function, a PRE comment before the first line
//!   of its address, a POST comment after the last line of its address and an EOL comment at
//!   the end of the first line of its address.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{FuncId, VarId};
use ghidorah_db::{CodeUnit, CommentKind, Program};
use ghidorah_ir::{IntrinsicNames, Node, OpId};
use ghidorah_types::cc::SYSV_X86_64;
use ghidorah_types::{CallConv, DataModel, TypeId, TypeStore};

use crate::expr::{Stmt, VarIdx};
use crate::lattice::{self, Stores, Ty};
use crate::view::{Env, NoEnv, View};
use crate::{Decomp, Warning};

mod calls;
mod comments;
mod env;
mod expr;
mod names;
mod walk;

/// The signature of a callee or of the function: its parameter types and its return type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    /// The parameter types in order.
    pub params: Vec<Ty>,
    /// The parameter names of the signature, in order.
    pub names: Vec<Option<String>>,
    /// The return type. `void` gives `None`.
    pub ret: Option<Ty>,
    /// The function takes a variable argument list.
    pub variadic: bool,
}

/// The facts outside the view that the printer reads. Each method has a default that knows
/// no fact.
pub trait PrintEnv: Env {
    /// Gives the name fact of a variable: the name and the source name, for example `agent`.
    fn var_name(&self, id: &VarId) -> Option<(String, &'static str)> {
        let _ = id;
        None
    }

    /// Gives the type fact of a variable. The type is in the program store.
    fn var_type(&self, id: &VarId) -> Option<TypeId> {
        let _ = id;
        None
    }

    /// Gives the comments in the body of the function at `entry`: the address, the kind and
    /// the text, in address order, then in kind order.
    fn comments(&self, entry: u64) -> Vec<(u64, CommentKind, String)> {
        let _ = entry;
        Vec::new()
    }

    /// Gives the signature of the function at `addr`: an agent signature first, then the
    /// Tier-0 prototype of its name.
    fn signature(&self, addr: u64) -> Option<Signature> {
        let _ = addr;
        None
    }

    /// Gives the bytes of the string literal at `addr`, without the terminator.
    fn string_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        let _ = addr;
        None
    }

    /// Gives the type store and the data model of the program.
    fn types(&self) -> Option<(&TypeStore, &DataModel)> {
        None
    }

    /// Gives the targets of the indirect call at `site`, in address order.
    fn call_targets(&self, site: u64) -> Vec<u64> {
        let _ = site;
        Vec::new()
    }

    /// Gives the name of the system call with the number `nr`.
    fn syscall_name(&self, nr: u64) -> Option<&'static str> {
        let _ = nr;
        None
    }

    /// Gives the calling convention of the binary.
    fn conv(&self) -> &'static CallConv {
        &SYSV_X86_64
    }
}

impl PrintEnv for NoEnv {}

/// The kind of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LineKind {
    /// The function line: the return type, the name and the parameters.
    Head,
    /// A line that opens a block: `{`, `if (c) {`, `while (c) {`, `switch (x) {`, `case i:`.
    Open,
    /// A line that closes a block: `}`, `} else {` or `} while (c);`.
    Close,
    /// A statement.
    Stmt,
    /// A label: `L_<addr>:`.
    Label,
    /// A `goto` of the structure.
    Goto,
    /// A `break;` or a `continue;`.
    Jump,
    /// A comment line: PLATE, PRE, POST, or an EOL comment with no line of its own.
    Comment,
}

/// The target of a call row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallTarget {
    /// The address of a function or of a stub.
    Addr(u64),
    /// A system call: its `sys:` ID text.
    Syscall(String),
}

/// One call of a line: the target and the printed name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallRow {
    /// The target.
    pub target: CallTarget,
    /// The name in the text.
    pub name: String,
}

/// One line of text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Line {
    /// The text with its indentation.
    pub text: String,
    /// The kind.
    pub kind: LineKind,
    /// The nesting depth: 0 for the function line.
    pub depth: u16,
    /// The ops that the line shows, in op order.
    pub ops: Vec<OpId>,
    /// The address range of the line: the start and the size in bytes. It covers each
    /// instruction of the ops, and the address of a comment line.
    pub span: Option<(u64, u64)>,
    /// The comment kind of a comment line, or of a line with an EOL comment.
    pub comment: Option<CommentKind>,
    /// The calls of the line in text order.
    pub calls: Vec<CallRow>,
    /// The addresses of the string literals of the line in text order.
    pub strings: Vec<u64>,
}

/// One variable of the output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarRow {
    /// The storage-based identity.
    pub id: VarId,
    /// The name in the text.
    pub name: String,
    /// The C type text.
    pub ty: String,
    /// The source of the name: `default` or the source of the name fact.
    pub source: &'static str,
}

/// The result of [`print()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Printed {
    /// The lines in text order.
    pub lines: Vec<Line>,
    /// The variables that the text names, in view order.
    pub vars: Vec<VarRow>,
    /// The warnings of the printer, for example `W_INDIRECT_CALL_UNRESOLVED`.
    pub warnings: Vec<Warning>,
}

/// The parts of one line under construction: its ops, calls and strings.
#[derive(Debug, Default)]
pub(crate) struct Buf {
    ops: BTreeSet<OpId>,
    calls: Vec<CallRow>,
    strings: Vec<u64>,
}

impl Buf {
    /// Adds one op.
    fn op(&mut self, at: OpId) {
        self.ops.insert(at);
    }
}

/// The argument count of a callee: the named parameters and the varargs flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Arity {
    named: usize,
    variadic: bool,
}

/// The state of one print.
pub(crate) struct Printer<'a> {
    d: &'a Decomp,
    env: &'a dyn PrintEnv,
    names: &'a dyn IntrinsicNames,
    stores: Stores<'a>,
    types: Vec<Option<Ty>>,
    vnames: Vec<(String, &'static str)>,
    used: BTreeSet<VarIdx>,
    refs: BTreeMap<VarIdx, u32>,
    call_defs: Vec<(usize, VarIdx)>,
    skip: BTreeSet<(Node, usize)>,
    clobbers: BTreeSet<VarIdx>,
    arity: BTreeMap<u64, Option<Arity>>,
    void_ret: bool,
    rets: Vec<u8>,
    lines: Vec<Line>,
    warnings: Vec<Warning>,
}

/// Gives the text of `depth` levels of indentation.
fn indent(depth: u16) -> String {
    "    ".repeat(usize::from(depth))
}

/// Gives the default type text of a value with `w` bits.
pub(crate) fn width_type(w: u8) -> String {
    if w == 1 {
        "bool".to_owned()
    } else {
        format!("uint{w}_t")
    }
}

impl<'a> Printer<'a> {
    /// Makes the printer of `d`.
    fn new(d: &'a Decomp, env: &'a dyn PrintEnv, names: &'a dyn IntrinsicNames) -> Self {
        let stores = Stores {
            program: env.types(),
            tier0: ghidorah_types::proto::builtin().ok(),
        };
        let types = lattice::infer(&d.view, env, &stores);
        let vnames = names::var_names(&d.view, env);
        let clobbers = names::clobbers(&d.view);
        let void_ret = env.signature(d.view.entry).is_some_and(|s| s.ret.is_none());
        Self {
            d,
            env,
            names,
            stores,
            types,
            vnames,
            used: BTreeSet::new(),
            refs: BTreeMap::new(),
            call_defs: Vec::new(),
            skip: BTreeSet::new(),
            clobbers,
            arity: BTreeMap::new(),
            void_ret,
            rets: Vec::new(),
            lines: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Gives the view.
    const fn view(&self) -> &'a View {
        &self.d.view
    }

    /// Adds one line with the parts of `buf`.
    fn push(&mut self, text: &str, kind: LineKind, depth: u16, buf: Buf) {
        let pad = if kind == LineKind::Label {
            depth.saturating_sub(1)
        } else {
            depth
        };
        let ops: Vec<OpId> = buf.ops.into_iter().collect();
        let span = self.span(&ops);
        self.lines.push(Line {
            text: format!("{}{text}", indent(pad)),
            kind,
            depth,
            ops,
            span,
            comment: None,
            calls: buf.calls,
            strings: buf.strings,
        });
    }

    /// Gives the address range of the instructions of `ops`: the first address and the size.
    /// The size counts from the first address, so an instruction at `u64::MAX` keeps its byte.
    fn span(&self, ops: &[OpId]) -> Option<(u64, u64)> {
        let start = ops.iter().map(|o| o.addr).min()?;
        let size = ops
            .iter()
            .map(|o| {
                let len = self.view().insn_len(o.addr).map_or(1, u64::from);
                o.addr
                    .checked_sub(start)
                    .and_then(|off| off.checked_add(len))
                    .unwrap_or(u64::MAX)
            })
            .max()?;
        Some((start, size))
    }

    /// Prints the statements of one node.
    fn block(&mut self, n: Node, depth: u16) {
        let Some(nv) = self.view().node(n) else {
            return;
        };
        for (i, s) in nv.stmts.iter().enumerate() {
            if self.skip.contains(&(n, i)) {
                continue;
            }
            let mut buf = Buf::default();
            let text = self.stmt(s, &mut buf);
            let def = match s {
                Stmt::Call(c) if !c.tail => calls::call_ret(c),
                Stmt::Assign {
                    var,
                    value: crate::expr::Expr::Call(_),
                    ..
                } => Some(*var),
                _ => None,
            };
            if let Some(v) = def {
                self.call_defs.push((self.lines.len(), v));
            }
            self.push(&text, LineKind::Stmt, depth, buf);
        }
    }

    /// Drops the `v = ` part of each call line whose result no other text names.
    fn drop_dead_results(&mut self) {
        for (i, v) in std::mem::take(&mut self.call_defs) {
            if self.refs.get(&v).copied().unwrap_or(0) != 1 {
                continue;
            }
            let Some(name) = self.vnames.get(v.index()).map(|n| format!("{} = ", n.0)) else {
                continue;
            };
            if let Some(line) = self.lines.get_mut(i) {
                let pad = indent(line.depth);
                if let Some(rest) = line.text.strip_prefix(&format!("{pad}{name}")) {
                    line.text = format!("{pad}{rest}");
                    self.used.remove(&v);
                }
            }
        }
    }
}

/// Prints the tree of `decomp` as C text. `name` is the name of the function.
#[must_use]
pub fn print(
    decomp: &Decomp,
    env: &dyn PrintEnv,
    names: &dyn IntrinsicNames,
    name: &str,
) -> Printed {
    let mut p = Printer::new(decomp, env, names);
    p.walk();
    p.drop_dead_results();
    let body = std::mem::take(&mut p.lines);
    let head = p.head(name);
    p.push(&head, LineKind::Head, 0, Buf::default());
    p.push("{", LineKind::Open, 0, Buf::default());
    p.lines.extend(body);
    p.push("}", LineKind::Close, 0, Buf::default());
    let lines = comments::insert(
        std::mem::take(&mut p.lines),
        &env.comments(decomp.view.entry),
        &decomp.view,
    );
    Printed {
        lines,
        vars: p.var_rows(),
        warnings: std::mem::take(&mut p.warnings),
    }
}

/// Gives the code units of the body of `func`: the address and the length of each
/// instruction, in address order.
#[must_use]
pub fn body_units(program: &Program, func: FuncId) -> Vec<(u64, u8)> {
    let mut out: BTreeMap<u64, u8> = BTreeMap::new();
    let Some(view) = program.func(func) else {
        return Vec::new();
    };
    for layer in [program.base(), program.analysis()] {
        for r in view.func.body.ranges() {
            for (at, unit) in layer.listing().units_in(*r) {
                let CodeUnit::Insn { len, .. } = unit;
                out.entry(at).or_insert(*len);
            }
        }
    }
    out.into_iter().collect()
}

/// Gives the addresses of the jumps that end a block of `view`.
#[must_use]
pub fn flow_addrs(view: &View) -> BTreeSet<u64> {
    view.nodes
        .iter()
        .filter_map(|n| n.term)
        .map(|t| t.addr)
        .chain(
            view.nodes
                .iter()
                .flat_map(|n| &n.stmts)
                .filter_map(|s| match s {
                    Stmt::Goto { at, .. } => Some(at.addr),
                    _ => None,
                }),
        )
        .collect()
}
