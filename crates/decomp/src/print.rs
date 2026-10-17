//! The C printer (design Section 8.3).
//!
//! [`print`] walks the statement tree of a [`Decomp`] with an explicit stack and gives one
//! [`Line`] for each line of text. Each line holds the ops that it shows, so the line map
//! ([`crate::linemap`]) can map it to its instructions.
//!
//! | Tree | Text |
//! |---|---|
//! | `Block(n)` | one line for each statement of `n` |
//! | `If` | `if (c) {`, the branch, `} else {`, the other branch, `}` |
//! | `Loop` | `while (c) {`, `do {` .. `} while (c);` or `for (;;) {` |
//! | `Switch` | `switch (x) {`, `case i:` lines, each arm with `break;` |
//! | `Goto(n)`, `Label(n)` | `goto L_<addr>;` and `L_<addr>:` |
//! | `Break`, `Continue` | `break;` and `continue;` |
//!
//! Rules of the text:
//!
//! - Expressions use precedence climbing with the numbers of [`crate::precedence`].
//! - A negated condition flips its compare operator: `!(a < b)` prints as `a >= b`.
//! - A cast shows only where a width changes or an operand needs a signed type.
//! - A string literal prints inline as escaped C text. A name from the binary prints with
//!   the escapes of `BinText`.
//! - Call names come from symbols, stub names and `sys:` IDs. The argument count comes from
//!   the signature or the Tier-0 prototype of the callee, then from the parameter recovery.
//! - Default variable names: `param_N`, `local_<hex>` for a stack slot and `v<N>` for a
//!   register value. An agent name wins.
//! - Comments: a PLATE comment comes before the function, a PRE comment before the first line
//!   of its address, a POST comment after the last line of its address and an EOL comment at
//!   the end of the first line of its address.

use std::collections::BTreeSet;

use ghidorah_base::{FuncId, VarId};
use ghidorah_db::{CommentKind, Program};
use ghidorah_ir::{IntrinsicNames, OpId};
use ghidorah_types::{DataModel, TypeId, TypeStore};

use crate::lattice::Ty;
use crate::view::{Env, NoEnv, View};
use crate::{Decomp, Warning};

mod env;

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

    /// Gives the recovered count of integer parameters of the function at `addr`.
    fn param_count(&self, addr: u64) -> Option<u8> {
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

/// The result of [`print`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Printed {
    /// The lines in text order.
    pub lines: Vec<Line>,
    /// The variables that the text names, in view order.
    pub vars: Vec<VarRow>,
    /// The warnings of the printer, for example `W_INDIRECT_CALL_UNRESOLVED`.
    pub warnings: Vec<Warning>,
}

/// Prints the tree of `decomp` as C text. `name` is the name of the function.
#[must_use]
pub fn print(
    decomp: &Decomp,
    env: &dyn PrintEnv,
    names: &dyn IntrinsicNames,
    name: &str,
) -> Printed {
    let _ = (decomp, env, names, name);
    Printed {
        lines: Vec::new(),
        vars: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Gives the code units of the body of `func`: the address and the length of each
/// instruction, in address order.
#[must_use]
pub fn body_units(program: &Program, func: FuncId) -> Vec<(u64, u8)> {
    let _ = (program, func);
    Vec::new()
}

/// Gives the addresses of the jumps that end a block of `view`.
#[must_use]
pub fn flow_addrs(view: &View) -> BTreeSet<u64> {
    let _ = view;
    BTreeSet::new()
}
