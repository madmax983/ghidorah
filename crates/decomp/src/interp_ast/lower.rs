//! The lowering of a tree to a list of steps with jumps.
//!
//! | Tree | Steps |
//! |---|---|
//! | `Block(n)` | `Exec(n)`, then `Halt` when `n` has the exit `Stop` |
//! | `If` | the condition tests, the branches and a jump to the end |
//! | `Loop` | a head label, the tests of a `while` or `do .. while`, the body and a jump back |
//! | `Switch` | `Dispatch` with one target for each case |
//! | `Goto(n)`, `Label(n)` | a jump to the label of `n` |
//!
//! A condition lowers to one `Test` step for each leaf, with the short-circuit jumps of
//! `&&` and `||`. The work list replaces recursion.

use std::collections::BTreeMap;

use ghidorah_ir::Node;

use crate::shape::{Exit, Shape};
use crate::tree::{Cond, LoopKind, Tree};

/// One step of lowered code. A target is an index in [`Code::steps`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Runs the statements of a node.
    Exec(Node),
    /// Tests the condition of a node. With `exec`, the statements of the node run first.
    Test {
        node: Node,
        neg: bool,
        exec: bool,
        t: usize,
        f: usize,
    },
    /// Goes to target `i` for case `i` of the switch node.
    Dispatch { node: Node, table: Vec<usize> },
    /// Goes to a target.
    Jump(usize),
    /// Ends the run after a node with the exit `Stop`.
    Halt,
    /// A step that no correct tree reaches: a missing label or the end of the tree.
    Bad,
}

/// Lowered code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Code {
    /// The steps.
    pub(crate) steps: Vec<Step>,
}

/// A label of the lowering: a step index after the patch.
type Lbl = usize;

/// The break and continue targets of one loop or switch.
#[derive(Debug, Clone, Copy)]
struct Ctx {
    brk: Lbl,
    cont: Option<Lbl>,
}

/// One task of the work list.
enum Task<'a> {
    Tree(&'a Tree),
    Cond(&'a Cond, Lbl, Lbl),
    Emit(Step),
    Mark(Lbl),
    Push(Ctx),
    Pop,
}

/// The state of one lowering.
struct Lower<'a> {
    shape: &'a Shape,
    steps: Vec<Step>,
    labels: Vec<Option<usize>>,
    nodes: BTreeMap<Node, Lbl>,
    ctx: Vec<Ctx>,
}

impl Lower<'_> {
    fn label(&mut self) -> Lbl {
        self.labels.push(None);
        self.labels.len() - 1
    }

    fn node_label(&mut self, n: Node) -> Lbl {
        if let Some(&l) = self.nodes.get(&n) {
            return l;
        }
        let l = self.label();
        self.nodes.insert(n, l);
        l
    }

    fn mark(&mut self, l: Lbl) {
        if let Some(slot) = self.labels.get_mut(l) {
            *slot = Some(self.steps.len());
        }
    }

    /// Gives the count of cases of a switch node.
    fn cases(&self, n: Node) -> usize {
        match self.shape.exit(n) {
            Exit::Switch(list) => list.len(),
            _ => 0,
        }
    }

    /// Adds the tasks of one tree, in reverse order.
    fn tree<'t>(&mut self, t: &'t Tree, work: &mut Vec<Task<'t>>) {
        let mut out: Vec<Task<'t>> = Vec::new();
        match t {
            Tree::Block(n) => {
                out.push(Task::Emit(Step::Exec(*n)));
                if self.shape.exit(*n).is_stop() {
                    out.push(Task::Emit(Step::Halt));
                }
            }
            Tree::Seq(items) => out.extend(items.iter().map(Task::Tree)),
            Tree::If { cond, then, els } => {
                let (lt, lf, end) = (self.label(), self.label(), self.label());
                out.push(Task::Cond(cond, lt, lf));
                out.push(Task::Mark(lt));
                out.push(Task::Tree(then));
                out.push(Task::Emit(Step::Jump(end)));
                out.push(Task::Mark(lf));
                if let Some(e) = els {
                    out.push(Task::Tree(e));
                }
                out.push(Task::Mark(end));
            }
            Tree::Loop {
                kind, cond, body, ..
            } => self.lower_loop(*kind, cond.as_ref(), body, &mut out),
            Tree::Switch { on, arms, .. } => {
                let exit = self.label();
                let mut table = vec![exit; self.cases(*on)];
                let mut parts = Vec::new();
                for arm in arms {
                    let l = self.label();
                    for &c in &arm.cases {
                        if let Some(slot) = table.get_mut(c) {
                            *slot = l;
                        }
                    }
                    parts.push((l, &arm.body));
                }
                out.push(Task::Emit(Step::Dispatch { node: *on, table }));
                out.push(Task::Push(Ctx {
                    brk: exit,
                    cont: None,
                }));
                for (l, body) in parts {
                    out.push(Task::Mark(l));
                    out.push(Task::Tree(body));
                    out.push(Task::Emit(Step::Jump(exit)));
                }
                out.push(Task::Pop);
                out.push(Task::Mark(exit));
            }
            Tree::Goto(n) => {
                let l = self.node_label(*n);
                out.push(Task::Emit(Step::Jump(l)));
            }
            Tree::Label(n) => {
                let l = self.node_label(*n);
                out.push(Task::Mark(l));
            }
            Tree::Break(_) => {
                let step = self.ctx.last().map_or(Step::Bad, |c| Step::Jump(c.brk));
                out.push(Task::Emit(step));
            }
            Tree::Continue(_) => {
                let step = self
                    .ctx
                    .iter()
                    .rev()
                    .find_map(|c| c.cont)
                    .map_or(Step::Bad, Step::Jump);
                out.push(Task::Emit(step));
            }
        }
        work.extend(out.into_iter().rev());
    }

    /// Adds the tasks of a loop.
    fn lower_loop<'t>(
        &mut self,
        kind: LoopKind,
        cond: Option<&'t Cond>,
        body: &'t Tree,
        out: &mut Vec<Task<'t>>,
    ) {
        let (head, exit) = (self.label(), self.label());
        match (kind, cond) {
            (LoopKind::While, Some(c)) => {
                let inner = self.label();
                out.push(Task::Mark(head));
                out.push(Task::Cond(c, inner, exit));
                out.push(Task::Mark(inner));
                out.push(Task::Push(Ctx {
                    brk: exit,
                    cont: Some(head),
                }));
                out.push(Task::Tree(body));
                out.push(Task::Pop);
                out.push(Task::Emit(Step::Jump(head)));
            }
            (LoopKind::DoWhile, Some(c)) => {
                let test = self.label();
                out.push(Task::Mark(head));
                out.push(Task::Push(Ctx {
                    brk: exit,
                    cont: Some(test),
                }));
                out.push(Task::Tree(body));
                out.push(Task::Pop);
                out.push(Task::Mark(test));
                out.push(Task::Cond(c, head, exit));
            }
            _ => {
                out.push(Task::Mark(head));
                out.push(Task::Push(Ctx {
                    brk: exit,
                    cont: Some(head),
                }));
                out.push(Task::Tree(body));
                out.push(Task::Pop);
                out.push(Task::Emit(Step::Jump(head)));
            }
        }
        out.push(Task::Mark(exit));
    }

    /// Adds the tasks of a condition with the targets `t` and `f`, in reverse order.
    #[expect(
        clippy::many_single_char_names,
        reason = "t and f name the targets of the branch"
    )]
    fn cond<'t>(&mut self, c: &'t Cond, t: Lbl, f: Lbl, work: &mut Vec<Task<'t>>) {
        match c {
            Cond::Leaf { node, neg, exec } => work.push(Task::Emit(Step::Test {
                node: *node,
                neg: *neg,
                exec: *exec,
                t,
                f,
            })),
            Cond::And(a, b) => {
                let mid = self.label();
                work.push(Task::Cond(b, t, f));
                work.push(Task::Mark(mid));
                work.push(Task::Cond(a, mid, f));
            }
            Cond::Or(a, b) => {
                let mid = self.label();
                work.push(Task::Cond(b, t, f));
                work.push(Task::Mark(mid));
                work.push(Task::Cond(a, t, mid));
            }
        }
    }

    /// Gives the step index of a label, or the index of the last step (`Bad`).
    fn resolve(&self, l: Lbl) -> usize {
        self.labels
            .get(l)
            .copied()
            .flatten()
            .unwrap_or_else(|| self.steps.len().saturating_sub(1))
    }
}

/// Lowers `tree` over `shape`. The last step is always `Bad`.
pub(crate) fn lower(tree: &Tree, shape: &Shape) -> Code {
    let mut low = Lower {
        shape,
        steps: Vec::new(),
        labels: Vec::new(),
        nodes: BTreeMap::new(),
        ctx: Vec::new(),
    };
    let mut work = vec![Task::Tree(tree)];
    while let Some(task) = work.pop() {
        match task {
            Task::Tree(t) => low.tree(t, &mut work),
            Task::Cond(c, t, f) => low.cond(c, t, f, &mut work),
            Task::Emit(s) => low.steps.push(s),
            Task::Mark(l) => low.mark(l),
            Task::Push(c) => low.ctx.push(c),
            Task::Pop => {
                let _ = low.ctx.pop();
            }
        }
    }
    low.steps.push(Step::Bad);
    let steps = low
        .steps
        .iter()
        .map(|s| match s {
            Step::Test {
                node,
                neg,
                exec,
                t,
                f,
            } => Step::Test {
                node: *node,
                neg: *neg,
                exec: *exec,
                t: low.resolve(*t),
                f: low.resolve(*f),
            },
            Step::Dispatch { node, table } => Step::Dispatch {
                node: *node,
                table: table.iter().map(|l| low.resolve(*l)).collect(),
            },
            Step::Jump(l) => Step::Jump(low.resolve(*l)),
            other => other.clone(),
        })
        .collect();
    Code { steps }
}
