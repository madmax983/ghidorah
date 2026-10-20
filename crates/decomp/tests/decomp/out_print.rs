//! The C printer on hand-made views (WP-23): statements, conditions, loops, switches, jumps,
//! casts, precedence, calls, strings and the ops of each line.

use std::collections::BTreeSet;

use ghidorah_base::{Address, FuncId, RegVar, Storage, VarId};
use ghidorah_decomp::print::{self, CallTarget, LineKind};
use ghidorah_decomp::shape::{NodeKind, ShapeNode};
use ghidorah_decomp::{
    Arm, Call, Callee, Cond, Decomp, Exit, Expr, LoopKind, Mode, NoEnv, NodeView, Shape, Stmt,
    Tree, Var, VarIdx, VarKind, View,
};
use ghidorah_ir::{Loc, NoNames, Node, OpId, Opc};

use crate::shapes::node;

/// The entry of the hand-made functions.
pub const ENTRY: u64 = 0x1000;

/// Gives the address of node `i`: 16 bytes for each node.
pub fn at_of(i: usize) -> u64 {
    ENTRY + 0x10 * u64::try_from(i).expect("small")
}

/// Gives the op `seq` of the instruction `k` of node `i`.
pub fn op(i: usize, k: u64, seq: u16) -> OpId {
    OpId {
        addr: at_of(i) + 4 * k,
        seq,
    }
}

/// Gives a variable read.
pub fn v(i: u32, w: u8) -> Expr {
    Expr::Var { var: VarIdx(i), w }
}

/// Gives a constant.
pub fn k(value: u64, w: u8) -> Expr {
    Expr::Const { value, w }
}

/// Gives a binary expression.
pub fn bin(opc: Opc, w: u8, x: Expr, y: Expr, at: OpId) -> Expr {
    Expr::Bin {
        op: opc,
        w,
        sub: 0,
        x: Box::new(x),
        y: Box::new(y),
        at,
    }
}

/// Gives a unary expression with the aux byte `sub`.
pub fn un(opc: Opc, w: u8, sub: u8, x: Expr, at: OpId) -> Expr {
    Expr::Un {
        op: opc,
        w,
        sub,
        x: Box::new(x),
        at,
    }
}

/// Gives the variable ID of a storage in the hand-made function.
pub fn var_id(storage: Storage) -> VarId {
    VarId {
        func: FuncId(Address::ram(ENTRY)),
        storage,
    }
}

/// Gives parameter `n` with `w` bits.
pub fn param(n: u16, w: u8) -> Var {
    Var {
        id: var_id(Storage::Param(n)),
        w,
        kind: VarKind::Param,
        home: None,
        input: None,
    }
}

/// Gives a register value with the name `name`.
pub fn temp(name: &str, def: u64, w: u8) -> Var {
    Var {
        id: var_id(Storage::Reg(
            RegVar::new(name, def).expect("a register name"),
        )),
        w,
        kind: VarKind::Temp,
        home: None,
        input: None,
    }
}

/// Gives the stack slot `k`.
pub fn local(k: i64, w: u8) -> Var {
    Var {
        id: var_id(Storage::Stack(k)),
        w,
        kind: VarKind::Local,
        home: None,
        input: None,
    }
}

/// One node of a hand-made view.
pub struct Spec {
    /// The exit.
    pub exit: Exit,
    /// The statements.
    pub stmts: Vec<Stmt>,
    /// The branch condition of a `Cond` exit.
    pub cond: Option<Expr>,
    /// The flow op at the end of the node.
    pub term: Option<OpId>,
}

impl Spec {
    /// Gives a node with statements and an exit.
    pub fn new(exit: Exit, stmts: Vec<Stmt>) -> Self {
        Self {
            exit,
            stmts,
            cond: None,
            term: None,
        }
    }

    /// Gives a branch node of `cond` with the flow op `term`.
    pub fn branch(t: usize, f: usize, cond: Expr, term: OpId) -> Self {
        Self {
            exit: Exit::Cond {
                t: node(t),
                f: node(f),
            },
            stmts: Vec::new(),
            cond: Some(cond),
            term: Some(term),
        }
    }
}

/// Gives the ops of an expression and its inner nodes.
fn expr_ops(e: &Expr, out: &mut BTreeSet<u64>) {
    for x in e.preorder() {
        if let Some(at) = x.at() {
            out.insert(at.addr);
        }
    }
}

/// Makes a decompile of hand-made nodes with `vars` and the tree `tree`.
pub fn decomp(specs: Vec<Spec>, vars: Vec<Var>, tree: Tree) -> Decomp {
    let mut addrs = BTreeSet::new();
    let mut nodes = Vec::new();
    let mut views = Vec::new();
    for (i, s) in specs.into_iter().enumerate() {
        for st in &s.stmts {
            addrs.insert(st.at().addr);
            for e in st.exprs() {
                expr_ops(e, &mut addrs);
            }
        }
        if let Some(c) = &s.cond {
            expr_ops(c, &mut addrs);
        }
        if let Some(t) = s.term {
            addrs.insert(t.addr);
        }
        nodes.push(ShapeNode {
            addr: at_of(i),
            kind: NodeKind::Block(node(i)),
            pure: s.stmts.is_empty(),
            exit: s.exit,
        });
        views.push(NodeView {
            stmts: s.stmts,
            cond: s.cond,
            target: None,
            cases: Vec::new(),
            term: s.term,
            ops: Vec::new(),
            span: Some((at_of(i), at_of(i) + 0x10)),
        });
    }
    Decomp {
        view: View {
            entry: ENTRY,
            shape: Shape {
                entry: Node(0),
                nodes,
            },
            nodes: views,
            vars,
            insns: addrs.into_iter().map(|a| (a, 4)).collect(),
            effects: std::collections::BTreeSet::new(),
        },
        tree,
        mode: Mode::Structured,
        elided: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Gives the text lines of a print with `NoEnv`.
pub fn text_of(d: &Decomp) -> Vec<String> {
    print::print(d, &NoEnv, &NoNames, "f")
        .lines
        .into_iter()
        .map(|l| l.text)
        .collect()
}

fn ret(e: Expr, at: OpId) -> Stmt {
    Stmt::Return {
        uses: vec![(Loc::RAX, e)],
        at,
    }
}

fn assign(var: u32, value: Expr, at: OpId) -> Stmt {
    Stmt::Assign {
        var: VarIdx(var),
        value,
        at,
    }
}

#[test]
fn prints_if_else_with_a_flipped_compare() {
    let lt = bin(Opc::ULt, 64, v(0, 64), k(5, 64), op(0, 0, 0));
    let d = decomp(
        vec![
            Spec::branch(1, 2, lt, op(0, 1, 0)),
            Spec::new(Exit::Stop, vec![ret(k(1, 64), op(1, 0, 0))]),
            Spec::new(Exit::Stop, vec![ret(v(0, 64), op(2, 0, 0))]),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![
            Tree::Block(node(0)),
            Tree::If {
                cond: Cond::Leaf {
                    node: node(0),
                    neg: true,
                    exec: false,
                },
                then: Box::new(Tree::Block(node(2))),
                els: Some(Box::new(Tree::Block(node(1)))),
            },
        ]),
    );
    assert_eq!(
        text_of(&d),
        [
            "uint64_t f(uint64_t param_1)",
            "{",
            "    if (param_1 >= 5) {",
            "        return param_1;",
            "    } else {",
            "        return 1;",
            "    }",
            "}",
        ]
    );
}

#[test]
fn prints_loops_breaks_and_continues() {
    let ne = bin(Opc::Ne, 64, v(1, 64), k(0, 64), op(0, 0, 0));
    let step = assign(
        1,
        bin(Opc::Sub, 64, v(1, 64), k(1, 64), op(1, 0, 0)),
        op(1, 0, 0),
    );
    let d = decomp(
        vec![
            Spec::branch(1, 2, ne, op(0, 1, 0)),
            Spec::new(Exit::Fall(node(0)), vec![step]),
            Spec::new(Exit::Stop, vec![ret(v(1, 64), op(2, 0, 0))]),
        ],
        vec![param(0, 64), temp("rax", 0x1004, 64)],
        Tree::Seq(vec![
            Tree::Loop {
                kind: LoopKind::While,
                cond: Some(Cond::leaf(node(0))),
                body: Box::new(Tree::Seq(vec![
                    Tree::Block(node(1)),
                    Tree::Continue(node(0)),
                ])),
                head: node(0),
                follow: Some(node(2)),
            },
            Tree::Loop {
                kind: LoopKind::DoWhile,
                cond: Some(Cond::leaf(node(0))),
                body: Box::new(Tree::Break(node(2))),
                head: node(0),
                follow: Some(node(2)),
            },
            Tree::Loop {
                kind: LoopKind::Endless,
                cond: None,
                body: Box::new(Tree::Break(node(2))),
                head: node(0),
                follow: Some(node(2)),
            },
            Tree::Block(node(2)),
        ]),
    );
    assert_eq!(
        text_of(&d),
        [
            "uint64_t f(void)",
            "{",
            "    while (v1 != 0) {",
            "        v1 = v1 - 1;",
            "        continue;",
            "    }",
            "    do {",
            "        break;",
            "    } while (v1 != 0);",
            "    while (true) {",
            "        break;",
            "    }",
            "    return v1;",
            "}",
        ]
    );
}

#[test]
fn prints_a_switch_with_merged_cases() {
    let mut d = decomp(
        vec![
            Spec::new(Exit::Switch(vec![node(1), node(2), node(1)]), Vec::new()),
            Spec::new(Exit::Stop, vec![ret(k(7, 64), op(1, 0, 0))]),
            Spec::new(Exit::Fall(node(3)), Vec::new()),
            Spec::new(Exit::Stop, vec![ret(k(0, 64), op(3, 0, 0))]),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![
            Tree::Switch {
                on: node(0),
                arms: vec![
                    Arm {
                        cases: vec![0, 2],
                        body: Tree::Block(node(1)),
                    },
                    Arm {
                        cases: vec![1],
                        body: Tree::empty(),
                    },
                ],
                follow: Some(node(3)),
            },
            Tree::Block(node(3)),
        ]),
    );
    d.view.nodes[0].target = Some(v(0, 64));
    d.view.nodes[0].term = Some(op(0, 0, 0));
    assert_eq!(
        text_of(&d),
        [
            "uint64_t f(uint64_t param_1)",
            "{",
            "    switch (param_1) {",
            "    case 0:",
            "    case 2:",
            "        return 7;",
            "    case 1:",
            "        break;",
            "    }",
            "    return 0;",
            "}",
        ]
    );
}

#[test]
fn prints_gotos_labels_and_stores() {
    let store = Stmt::Store {
        w: 32,
        addr: bin(Opc::Add, 64, v(0, 64), k(8, 64), op(0, 0, 0)),
        value: k(0, 32),
        at: op(0, 0, 1),
    };
    let d = decomp(
        vec![
            Spec::new(Exit::Fall(node(1)), vec![store]),
            Spec::new(
                Exit::Stop,
                vec![Stmt::Return {
                    uses: Vec::new(),
                    at: op(1, 0, 0),
                }],
            ),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![
            Tree::Block(node(0)),
            Tree::Goto(node(1)),
            Tree::Label(node(1)),
            Tree::Block(node(1)),
        ]),
    );
    assert_eq!(
        text_of(&d),
        [
            "void f(uint64_t param_1)",
            "{",
            "    *(uint32_t *)(param_1 + 8) = 0;",
            "    goto L_1010;",
            "L_1010:",
            "    return;",
            "}",
        ]
    );
}

#[test]
fn casts_only_where_widths_change() {
    let a = op(0, 0, 0);
    let trunc = un(Opc::Trunc, 32, 0, v(0, 64), a);
    let zext = un(Opc::ZExt, 64, 32, trunc.clone(), a);
    let sext = un(Opc::SExt, 64, 32, trunc.clone(), a);
    let slt = bin(Opc::SLt, 32, trunc, k(0xffff_ffff, 32), a);
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![
                assign(1, zext, op(0, 0, 1)),
                assign(2, sext, op(0, 0, 2)),
                assign(3, slt, op(0, 0, 3)),
                assign(
                    1,
                    bin(Opc::Add, 64, v(1, 64), k(u64::MAX - 7, 64), op(0, 1, 0)),
                    op(0, 1, 0),
                ),
                ret(v(1, 64), op(0, 2, 0)),
            ],
        )],
        vec![
            param(0, 64),
            temp("rax", 0x1000, 64),
            temp("rcx", 0x1000, 64),
            temp("rdx", 0x1000, 1),
        ],
        Tree::Block(node(0)),
    );
    assert_eq!(
        text_of(&d)[2..7],
        [
            "    v1 = (uint64_t)(uint32_t)param_1;",
            "    v2 = (int64_t)(int32_t)param_1;",
            "    v3 = (int32_t)param_1 < -1;",
            "    v1 = v1 - 8;",
            "    return v1;",
        ]
    );
}

#[test]
fn parentheses_follow_the_precedence() {
    let a = op(0, 0, 0);
    let sum = bin(Opc::Add, 64, v(0, 64), v(1, 64), a);
    let prod = bin(Opc::Mul, 64, sum.clone(), k(3, 64), a);
    let diff = bin(Opc::Sub, 64, v(0, 64), sum.clone(), a);
    let left = bin(Opc::Sub, 64, sum, v(1, 64), a);
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![
                assign(2, prod, op(0, 0, 1)),
                assign(2, diff, op(0, 0, 2)),
                assign(2, left, op(0, 0, 3)),
                ret(v(2, 64), op(0, 1, 0)),
            ],
        )],
        vec![param(0, 64), param(1, 64), local(-0x14, 64)],
        Tree::Block(node(0)),
    );
    assert_eq!(
        text_of(&d)[2..5],
        [
            "    local_14 = (param_1 + param_2) * 3;",
            "    local_14 = param_1 - (param_1 + param_2);",
            "    local_14 = param_1 + param_2 - param_2;",
        ]
    );
}

#[test]
fn calls_strings_and_line_ops() {
    let call = Call {
        callee: Callee::Direct(0x2000),
        args: vec![(Loc::RDI, Expr::Str { addr: 0x3000 })],
        set: std::iter::once(Loc::RDI).collect(),
        push: None,
        mem: None,
        rets: vec![(Loc::RAX, VarIdx(0))],
        ret: None,
        noreturn: false,
        tail: false,
        at: op(0, 0, 0),
    };
    let tail = Call {
        callee: Callee::Direct(0x2100),
        args: vec![(Loc::RDI, v(0, 64))],
        set: std::iter::once(Loc::RDI).collect(),
        push: None,
        mem: None,
        rets: Vec::new(),
        ret: None,
        noreturn: false,
        tail: true,
        at: op(0, 1, 0),
    };
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![Stmt::Call(call), Stmt::Call(tail)],
        )],
        vec![temp("rax", 0x1000, 64)],
        Tree::Block(node(0)),
    );
    let printed = print::print(&d, &NoEnv, &NoNames, "f");
    let texts: Vec<&str> = printed.lines.iter().map(|l| l.text.as_str()).collect();
    assert!(
        texts.contains(&"    v1 = FUN_00002000((char *)0x3000);"),
        "{texts:?}"
    );
    assert!(texts.contains(&"    return FUN_00002100(v1);"), "{texts:?}");
    let first = printed
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Stmt)
        .expect("a statement line");
    assert_eq!(first.ops, vec![op(0, 0, 0)]);
    assert_eq!(first.span, Some((at_of(0), 4)));
    assert_eq!(first.strings, vec![0x3000]);
    assert_eq!(first.calls[0].target, CallTarget::Addr(0x2000));
    assert_eq!(first.calls[0].name, "FUN_00002000");
    assert_eq!(printed.vars.len(), 1);
    assert_eq!(printed.vars[0].name, "v1");
    assert_eq!(printed.vars[0].ty, "uint64_t");
    assert_eq!(printed.vars[0].source, "default");
}

/// Gives a counted loop: `v1 = 0`, a test `v1 < 0xa` in a pure node, then a body that adds
/// `v1` to `v2` and steps `v1`. With `skip`, the body has a `continue` to the head.
fn counted(skip: bool) -> Decomp {
    let init = assign(1, k(0, 64), op(0, 0, 0));
    let lt = bin(Opc::ULt, 64, v(1, 64), k(10, 64), op(1, 0, 0));
    let add = assign(
        2,
        bin(Opc::Add, 64, v(2, 64), v(1, 64), op(2, 0, 0)),
        op(2, 0, 0),
    );
    let step = assign(
        1,
        bin(Opc::Add, 64, v(1, 64), k(1, 64), op(2, 1, 0)),
        op(2, 1, 0),
    );
    let mut body = vec![Tree::Block(node(2))];
    if skip {
        body.insert(0, Tree::Continue(node(1)));
    }
    decomp(
        vec![
            Spec::new(Exit::Fall(node(1)), vec![init]),
            Spec::branch(2, 3, lt, op(1, 1, 0)),
            Spec::new(Exit::Fall(node(1)), vec![add, step]),
            Spec::new(Exit::Stop, vec![ret(v(2, 64), op(3, 0, 0))]),
        ],
        vec![
            param(0, 64),
            temp("rcx", 0x1000, 64),
            temp("rax", 0x1000, 64),
        ],
        Tree::Seq(vec![
            Tree::Block(node(0)),
            Tree::Loop {
                kind: LoopKind::While,
                cond: Some(Cond::leaf(node(1))),
                body: Box::new(Tree::Seq(body)),
                head: node(1),
                follow: Some(node(3)),
            },
            Tree::Block(node(3)),
        ]),
    )
}

#[test]
fn prints_a_for_loop_when_its_parts_are_adjacent() {
    let d = counted(false);
    let printed = print::print(&d, &NoEnv, &NoNames, "f");
    let texts: Vec<&str> = printed.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        texts[2..6],
        [
            "    for (v1 = 0; v1 < 0xa; v1 = v1 + 1) {",
            "        v2 = v2 + v1;",
            "    }",
            "    return v2;",
        ],
        "{texts:?}"
    );
    let head = printed
        .lines
        .iter()
        .find(|l| l.text.contains("for ("))
        .expect("the for line");
    for at in [op(0, 0, 0), op(1, 0, 0), op(1, 1, 0), op(2, 1, 0)] {
        assert!(head.ops.contains(&at), "{at} is on the for line");
    }
}

#[test]
fn a_continue_keeps_the_while_loop() {
    let texts = text_of(&counted(true));
    assert!(texts.contains(&"    v1 = 0;".to_owned()), "{texts:?}");
    assert!(
        texts.contains(&"    while (v1 < 0xa) {".to_owned()),
        "{texts:?}"
    );
    assert!(!texts.iter().any(|t| t.contains("for (")), "{texts:?}");
}
