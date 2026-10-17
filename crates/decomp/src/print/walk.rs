//! The walk of the statement tree: blocks, conditions, `if`, loops, switches and jumps.
//!
//! The walk uses an explicit stack of tasks, so a deep tree does not overflow the thread
//! stack.

use ghidorah_ir::Node;

use super::{Buf, LineKind, Printer, expr};
use crate::expr::Stmt;
use crate::tree::{Arm, Cond, LoopKind, Tree};
use crate::view::View;

/// One task of the tree walk.
#[derive(Clone, Copy)]
enum Task<'t> {
    /// Print a tree at a depth.
    Tree(&'t Tree, u16),
    /// Print `} else {` at a depth.
    Else(u16),
    /// Print `} else if (c) {` for an `If` tree, then its branches.
    ElseIf(&'t Tree, u16),
    /// Print `}` at a depth.
    Close(u16),
    /// Print `} while (c);` at a depth.
    DoEnd(&'t Cond, u16),
    /// Print the case labels and the body of one switch arm.
    Arm(&'t Arm, u16),
    /// Print `break;` at a depth.
    Break(u16),
    /// Print a `while` loop as `for (init; c; step) {` at a depth.
    For(&'t Tree, &'t Stmt, &'t Stmt, u16),
}

/// The parts of a `for` loop: the init and step statements and their places in the nodes.
struct ForParts<'t> {
    init: &'t Stmt,
    step: &'t Stmt,
    at: [(Node, usize); 2],
}

/// Gives the label of a shape node: `L_<addr>`.
fn label(view: &View, n: Node) -> String {
    format!("L_{:x}", view.shape.addr(n))
}

/// Tells if the run ends at the end of a tree: a stop node, a jump or a `break`.
fn ends(view: &View, t: &Tree) -> bool {
    let mut cur = t;
    loop {
        match cur {
            Tree::Seq(items) => match items.last() {
                Some(last) => cur = last,
                None => return false,
            },
            Tree::Block(n) => return view.shape.exit(*n).is_stop(),
            Tree::Goto(_) | Tree::Break(_) | Tree::Continue(_) => return true,
            _ => return false,
        }
    }
}

/// Adds the tasks of the branches of an `if` in reverse order: the branch `then`, then the
/// `else` part or an `else if`, then `}`.
fn branches<'t>(then: &'t Tree, els: Option<&'t Tree>, depth: u16, work: &mut Vec<Task<'t>>) {
    let inner = depth.saturating_add(1);
    if let Some(e) = els {
        if let Some(chain) = else_if(e) {
            work.push(Task::ElseIf(chain, depth));
        } else {
            work.push(Task::Close(depth));
            work.push(Task::Tree(e, inner));
            work.push(Task::Else(depth));
        }
    } else {
        work.push(Task::Close(depth));
    }
    work.push(Task::Tree(then, inner));
}

/// Gives the one `If` of an else branch, for an `else if` chain.
fn else_if(t: &Tree) -> Option<&Tree> {
    match t {
        Tree::If { .. } => Some(t),
        Tree::Seq(items) if items.len() == 1 => items.first().and_then(else_if),
        _ => None,
    }
}

impl<'a> Printer<'a> {
    /// Gives the init and the step of a `for` loop: `block` ends with `v = init`, `lp` is a
    /// `while` loop whose pure condition reads `v`, and its body ends with `v = step(v)`. A
    /// `continue` to the loop head keeps the `while` form, because a `for` would run the
    /// step first.
    fn for_parts(&self, block: &'a Tree, lp: &'a Tree) -> Option<ForParts<'a>> {
        let view = self.view();
        let Tree::Block(a) = block else {
            return None;
        };
        let Tree::Loop {
            kind: LoopKind::While,
            cond:
                Some(Cond::Leaf {
                    node: test,
                    exec: false,
                    ..
                }),
            body,
            head,
            ..
        } = lp
        else {
            return None;
        };
        let firsts = &view.node(*a)?.stmts;
        let init = firsts.last()?;
        let Stmt::Assign { var, .. } = init else {
            return None;
        };
        let pure = view.shape.node(*test).is_some_and(|s| s.pure);
        let reads = view
            .node(*test)?
            .cond
            .as_ref()
            .is_some_and(|c| c.vars().contains(var));
        if !pure || !reads {
            return None;
        }
        let last = match body.as_ref() {
            Tree::Seq(items) => items.last()?,
            other => other,
        };
        let Tree::Block(z) = last else {
            return None;
        };
        let lasts = &view.node(*z)?.stmts;
        let step = lasts.last()?;
        let Stmt::Assign {
            var: stepped,
            value,
            ..
        } = step
        else {
            return None;
        };
        let continues = body
            .preorder()
            .into_iter()
            .any(|t| matches!(t, Tree::Continue(n) if n == head));
        (stepped == var && value.vars().contains(var) && !continues).then(|| ForParts {
            init,
            step,
            at: [
                (*a, firsts.len().saturating_sub(1)),
                (*z, lasts.len().saturating_sub(1)),
            ],
        })
    }

    /// Gives the text of a condition and adds its parts to `buf`.
    fn cond(&mut self, c: &Cond, buf: &mut Buf) -> (String, u8) {
        use crate::precedence::{LOG_AND, LOG_OR};
        match c {
            Cond::Leaf { node, neg, exec } => self.leaf(*node, *neg, *exec, buf),
            Cond::And(first, second) | Cond::Or(first, second) => {
                let (text, prec) = if matches!(c, Cond::And(..)) {
                    ("&&", LOG_AND)
                } else {
                    ("||", LOG_OR)
                };
                let (left, left_prec) = self.cond(first, buf);
                let (right, right_prec) = self.cond(second, buf);
                (
                    format!(
                        "{} {text} {}",
                        expr::wrap(&left, left_prec, prec, false),
                        expr::wrap(&right, right_prec, prec, true)
                    ),
                    prec,
                )
            }
        }
    }

    /// Gives the text of one condition leaf: the branch condition of `n`, with the statements
    /// of the node first when `exec` is set.
    fn leaf(&mut self, n: Node, neg: bool, exec: bool, buf: &mut Buf) -> (String, u8) {
        let Some(nv) = self.view().node(n) else {
            return ("true".to_owned(), crate::precedence::ATOM);
        };
        if let Some(t) = nv.term {
            buf.op(t);
        }
        let (mut text, mut prec) = match &nv.cond {
            Some(e) if neg => self.negated(e, buf),
            Some(e) => self.expr(e, buf),
            None => ("true".to_owned(), crate::precedence::ATOM),
        };
        if exec && !nv.stmts.is_empty() {
            let mut parts: Vec<String> = Vec::new();
            for s in &nv.stmts {
                let t = self.stmt(s, buf);
                parts.push(t.trim_end_matches(';').to_owned());
            }
            parts.push(text);
            text = format!("({})", parts.join(", "));
            prec = crate::precedence::ATOM;
        }
        (text, prec)
    }

    /// Prints `kw (c) {` for a condition.
    fn open_cond(&mut self, kw: &str, c: &Cond, depth: u16) {
        let mut buf = Buf::default();
        let (text, _) = self.cond(c, &mut buf);
        self.push(&format!("{kw} ({text}) {{"), LineKind::Open, depth, buf);
    }

    /// Prints one tree and adds the tasks of its parts.
    fn tree(&mut self, t: &'a Tree, depth: u16, work: &mut Vec<Task<'a>>) {
        let inner = depth.saturating_add(1);
        match t {
            Tree::Block(n) => self.block(*n, depth),
            Tree::Seq(items) => {
                let mut tasks = Vec::with_capacity(items.len());
                let mut i = 0usize;
                while let Some(cur) = items.get(i) {
                    let next = items.get(i.saturating_add(1));
                    if let Some(lp) = next
                        && let Some(parts) = self.for_parts(cur, lp)
                    {
                        self.skip.extend(parts.at);
                        tasks.push(Task::Tree(cur, depth));
                        tasks.push(Task::For(lp, parts.init, parts.step, depth));
                        i = i.saturating_add(2);
                        continue;
                    }
                    tasks.push(Task::Tree(cur, depth));
                    i = i.saturating_add(1);
                }
                work.extend(tasks.into_iter().rev());
            }
            Tree::If { cond, then, els } => {
                let empty = matches!(then.as_ref(), Tree::Seq(v) if v.is_empty());
                match els {
                    Some(e) if empty => {
                        let flipped = cond.clone().negate();
                        self.open_cond("if", &flipped, depth);
                        work.push(Task::Close(depth));
                        work.push(Task::Tree(e, inner));
                    }
                    _ => {
                        self.open_cond("if", cond, depth);
                        branches(then, els.as_deref(), depth, work);
                    }
                }
            }
            Tree::Loop {
                kind, cond, body, ..
            } => match (kind, cond) {
                (LoopKind::While, Some(c)) => {
                    self.open_cond("while", c, depth);
                    work.push(Task::Close(depth));
                    work.push(Task::Tree(body, inner));
                }
                (LoopKind::DoWhile, Some(c)) => {
                    self.push("do {", LineKind::Open, depth, Buf::default());
                    work.push(Task::DoEnd(c, depth));
                    work.push(Task::Tree(body, inner));
                }
                _ => {
                    self.push("while (true) {", LineKind::Open, depth, Buf::default());
                    work.push(Task::Close(depth));
                    work.push(Task::Tree(body, inner));
                }
            },
            Tree::Switch { on, arms, .. } => {
                let mut buf = Buf::default();
                let target = match self.view().node(*on) {
                    Some(nv) => {
                        if let Some(t) = nv.term {
                            buf.op(t);
                        }
                        match &nv.target {
                            Some(e) => self.expr(e, &mut buf).0,
                            None => "0".to_owned(),
                        }
                    }
                    None => "0".to_owned(),
                };
                self.push(&format!("switch ({target}) {{"), LineKind::Open, depth, buf);
                work.push(Task::Close(depth));
                work.extend(arms.iter().rev().map(|a| Task::Arm(a, depth)));
            }
            Tree::Goto(n) => {
                let text = format!("goto {};", label(self.view(), *n));
                self.push(&text, LineKind::Goto, depth, Buf::default());
            }
            Tree::Label(n) => {
                let text = format!("{}:", label(self.view(), *n));
                self.push(&text, LineKind::Label, depth, Buf::default());
            }
            Tree::Break(_) => self.push("break;", LineKind::Jump, depth, Buf::default()),
            Tree::Continue(_) => self.push("continue;", LineKind::Jump, depth, Buf::default()),
        }
    }

    /// Runs one task of the walk.
    fn task(&mut self, task: Task<'a>, work: &mut Vec<Task<'a>>) {
        match task {
            Task::Tree(t, depth) => self.tree(t, depth, work),
            Task::Else(depth) => self.push("} else {", LineKind::Close, depth, Buf::default()),
            Task::ElseIf(t, depth) => {
                if let Tree::If { cond, then, els } = t {
                    let mut buf = Buf::default();
                    let (text, _) = self.cond(cond, &mut buf);
                    self.push(
                        &format!("}} else if ({text}) {{"),
                        LineKind::Close,
                        depth,
                        buf,
                    );
                    branches(then, els.as_deref(), depth, work);
                }
            }
            Task::Close(depth) => self.push("}", LineKind::Close, depth, Buf::default()),
            Task::DoEnd(c, depth) => {
                let mut buf = Buf::default();
                let (text, _) = self.cond(c, &mut buf);
                self.push(&format!("}} while ({text});"), LineKind::Close, depth, buf);
            }
            Task::Arm(arm, depth) => {
                for case in &arm.cases {
                    self.push(
                        &format!("case {case}:"),
                        LineKind::Open,
                        depth,
                        Buf::default(),
                    );
                }
                let inner = depth.saturating_add(1);
                if !ends(self.view(), &arm.body) {
                    work.push(Task::Break(inner));
                }
                work.push(Task::Tree(&arm.body, inner));
            }
            Task::Break(depth) => self.push("break;", LineKind::Jump, depth, Buf::default()),
            Task::For(lp, init, step, depth) => {
                if let Tree::Loop {
                    cond: Some(c),
                    body,
                    ..
                } = lp
                {
                    let mut buf = Buf::default();
                    let start = self.stmt(init, &mut buf);
                    let (cond_text, _) = self.cond(c, &mut buf);
                    let next = self.stmt(step, &mut buf);
                    let text = format!(
                        "for ({}; {cond_text}; {}) {{",
                        start.trim_end_matches(';'),
                        next.trim_end_matches(';')
                    );
                    self.push(&text, LineKind::Open, depth, buf);
                    work.push(Task::Close(depth));
                    work.push(Task::Tree(body, depth.saturating_add(1)));
                }
            }
        }
    }

    /// Prints the tree of the decompile with an explicit stack.
    pub(super) fn walk(&mut self) {
        let mut work: Vec<Task<'a>> = vec![Task::Tree(&self.d.tree, 1)];
        while let Some(task) = work.pop() {
            self.task(task, &mut work);
        }
    }
}
