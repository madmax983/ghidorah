//! Unit tests of the output modules (WP-23): precedence, windows, the line map, metrics,
//! warnings, the self-check and the cache.

use std::collections::BTreeSet;

use ghidorah_base::{Address, FuncId, Rev, WarningCode};
use ghidorah_db::CommentKind;
use ghidorah_decomp::cache::{self, Cache, Key};
use ghidorah_decomp::linemap::{self, LineRow};
use ghidorah_decomp::metrics::{self, Metrics};
use ghidorah_decomp::print::{CallRow, CallTarget, Line, LineKind};
use ghidorah_decomp::selfcheck::{self, Validation};
use ghidorah_decomp::structure::FlatReason;
use ghidorah_decomp::warnings::{self, Remedy, WarningRow};
use ghidorah_decomp::{
    Cond, ElideReason, Elided, Exit, Mode, Opts, Output, Passes, Stmt, Tree, Warning, precedence,
};
use ghidorah_ir::{Loc, OpId, Opc};

use crate::out_print::{ENTRY, Spec, at_of, decomp, k, op, param};
use crate::shapes::node;

fn line(text: &str, kind: LineKind, depth: u16, ops: Vec<OpId>, span: Option<(u64, u64)>) -> Line {
    Line {
        text: text.to_owned(),
        kind,
        depth,
        ops,
        span,
        comment: None,
        calls: Vec::new(),
        strings: Vec::new(),
    }
}

fn output(lines: Vec<Line>) -> Output {
    Output {
        entry: ENTRY,
        name: "f".to_owned(),
        lines,
        elided: Vec::new(),
        vars: Vec::new(),
        warnings: Vec::new(),
        metrics: metrics::measure(&[], Mode::Structured, Validation::Ok),
    }
}

#[test]
fn precedence_table_and_parentheses() {
    let add = precedence::binary(Opc::Add).expect("+");
    assert_eq!(
        (add.text, add.prec, add.signed),
        ("+", precedence::ADD, false)
    );
    let sdiv = precedence::binary(Opc::SDiv).expect("/");
    assert_eq!(
        (sdiv.text, sdiv.prec, sdiv.signed),
        ("/", precedence::MUL, true)
    );
    let shr = precedence::binary(Opc::AShr).expect(">>");
    assert!(shr.signed && shr.prec == precedence::SHIFT);
    assert_eq!(
        precedence::binary(Opc::Eq).map(|b| b.prec),
        Some(precedence::EQ)
    );
    assert_eq!(precedence::binary(Opc::SLe).map(|b| b.text), Some("<="));
    assert!(precedence::binary(Opc::Rol).is_none());
    for (opc, text) in [
        (Opc::Eq, "!="),
        (Opc::Ne, "=="),
        (Opc::ULt, ">="),
        (Opc::ULe, ">"),
        (Opc::SLt, ">="),
        (Opc::SLe, ">"),
    ] {
        assert_eq!(precedence::negated(opc), Some(text), "{opc:?}");
    }
    assert_eq!(precedence::negated(Opc::Add), None);
    assert!(precedence::parens(precedence::ADD, precedence::MUL, false));
    assert!(!precedence::parens(precedence::MUL, precedence::ADD, true));
    assert!(precedence::parens(precedence::ADD, precedence::ADD, true));
    assert!(!precedence::parens(precedence::ADD, precedence::ADD, false));
}

#[test]
fn windows_page_through_the_lines() {
    let lines: Vec<Line> = (0..7u64)
        .map(|i| {
            line(
                &format!("l{i}"),
                LineKind::Stmt,
                1,
                vec![op(0, i, 0)],
                Some((at_of(0) + 4 * i, 4)),
            )
        })
        .collect();
    let out = output(lines);
    let w = out.window(1, 3);
    assert_eq!((w.start, w.count, w.total(), w.next()), (1, 3, 7, Some(4)));
    assert_eq!(w.text(), "l0\nl1\nl2\n");
    let rows: Vec<usize> = w.rows().iter().map(|r| r.line).collect();
    assert_eq!(rows, [1, 2, 3]);
    let last = out.window(6, 10);
    assert_eq!((last.count, last.next()), (2, None));
    assert_eq!(last.lines().len(), 2);
    let past = out.window(9, 3);
    assert_eq!(
        (past.count, past.next(), past.text()),
        (0, None, String::new())
    );
    assert_eq!(out.text().lines().count(), 7);
}

#[test]
fn window_calls_and_strings_keep_their_lines() {
    let mut a = line(
        "a",
        LineKind::Stmt,
        1,
        vec![op(0, 0, 0)],
        Some((at_of(0), 4)),
    );
    a.calls.push(CallRow {
        target: CallTarget::Addr(0x2000),
        name: "g".to_owned(),
    });
    let mut b = line(
        "b",
        LineKind::Stmt,
        1,
        vec![op(0, 1, 0)],
        Some((at_of(0) + 4, 4)),
    );
    b.strings.push(0x3000);
    let out = output(vec![a, b]);
    let w = out.window(2, 1);
    assert!(w.calls().is_empty());
    assert_eq!(w.strings(), vec![(2, 0x3000)]);
    let all = out.window(1, 2);
    assert_eq!(all.calls().len(), 1);
    assert_eq!(all.calls()[0].0, 1);
}

#[test]
fn line_rows_and_cover_reasons() {
    let mut comment = line("// c", LineKind::Comment, 1, Vec::new(), Some((0x1020, 4)));
    comment.comment = Some(CommentKind::Pre);
    let lines = vec![
        line("f()", LineKind::Head, 0, Vec::new(), None),
        line(
            "a;",
            LineKind::Stmt,
            1,
            vec![op(0, 0, 0)],
            Some((0x1000, 8)),
        ),
        comment,
    ];
    assert_eq!(linemap::row(1, &lines[0]), None);
    assert_eq!(
        linemap::row(2, &lines[1]),
        Some(LineRow {
            line: 2,
            start: 0x1000,
            size: 8,
            ops: vec![op(0, 0, 0)],
            comment: None,
        })
    );
    let rows = linemap::rows(1, &lines);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].comment, Some(CommentKind::Pre));
    let insns = [
        (0x1000, 4),
        (0x1004, 4),
        (0x1008, 4),
        (0x100c, 4),
        (0x1020, 4),
    ];
    let flow = BTreeSet::from([0x100c]);
    let body = [
        (0x1000, 4),
        (0x1004, 4),
        (0x1008, 4),
        (0x100c, 4),
        (0x1010, 2),
        (0x1020, 4),
    ];
    let mut elided = vec![Elided {
        start: 0x1008,
        size: 4,
        reason: ElideReason::Canary,
    }];
    let dropped = linemap::cover(&lines, &insns, &flow, &BTreeSet::new(), &body, &mut elided);
    assert!(dropped.is_empty(), "{dropped:?}");
    elided.sort();
    let reasons: Vec<(u64, ElideReason)> = elided.iter().map(|e| (e.start, e.reason)).collect();
    assert_eq!(
        reasons,
        [
            (0x1008, ElideReason::Canary),
            (0x100c, ElideReason::Flow),
            (0x1010, ElideReason::Padding),
        ]
    );
    for (a, _) in body {
        assert!(linemap::covered(&lines, &elided, a), "{a:#x}");
    }
    assert!(!linemap::covered(&lines, &elided, 0x1030));
    assert_eq!(ElideReason::Flow.name(), "control flow");
    assert_eq!(ElideReason::NoEffect.name(), "no effect");
    assert_eq!(ElideReason::Padding.name(), "padding");
}

#[test]
fn metrics_count_the_lines() {
    let lines = vec![
        line("f()", LineKind::Head, 0, Vec::new(), None),
        line("{", LineKind::Open, 0, Vec::new(), None),
        line("if (a) {", LineKind::Open, 1, Vec::new(), None),
        line("x;", LineKind::Stmt, 2, Vec::new(), None),
        line("goto L_1;", LineKind::Goto, 2, Vec::new(), None),
        line("}", LineKind::Close, 1, Vec::new(), None),
        line("L_1:", LineKind::Label, 1, Vec::new(), None),
        line("y;", LineKind::Stmt, 1, Vec::new(), None),
        line("break;", LineKind::Jump, 1, Vec::new(), None),
        line("}", LineKind::Close, 0, Vec::new(), None),
    ];
    let m = metrics::measure(&lines, Mode::Flat(FlatReason::Fuel), Validation::Repaired);
    assert_eq!(
        m,
        Metrics {
            goto_count: 1,
            label_count: 1,
            max_nesting: 2,
            stmt_count: 2,
            mode: Mode::Flat(FlatReason::Fuel),
            validation: Validation::Repaired,
        }
    );
    assert_eq!(Validation::Ok.name(), "ok");
    assert_eq!(Validation::Repaired.name(), "repaired");
}

#[test]
fn warning_rows_sort_and_name_remedies() {
    let call = ghidorah_decomp::Call {
        callee: ghidorah_decomp::Callee::Direct(0x2000),
        args: Vec::new(),
        set: ghidorah_ir::LocSet::EMPTY,
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: Vec::new(),
        ret: None,
        noreturn: true,
        tail: false,
        at: op(1, 0, 0),
    };
    let d = decomp(
        vec![
            Spec::new(Exit::Fall(node(1)), Vec::new()),
            Spec::new(Exit::Stop, vec![Stmt::Call(call)]),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![Tree::Block(node(0)), Tree::Block(node(1))]),
    );
    let w = |code, at| Warning { code, at };
    let found = [
        w(WarningCode::NoreturnAssumed, at_of(1)),
        w(WarningCode::LiftUnsupported, 0x1004),
        w(WarningCode::JumptableUnresolved, 0x1004),
        w(WarningCode::LiftUnsupported, 0x1004),
        w(WarningCode::StructureSelfcheck, ENTRY),
    ];
    let rows = warnings::rows(&found, &d.view);
    assert_eq!(
        rows,
        [
            WarningRow {
                at: ENTRY,
                code: WarningCode::StructureSelfcheck,
                remedy: Some(Remedy::Disasm(ENTRY)),
            },
            WarningRow {
                at: 0x1004,
                code: WarningCode::JumptableUnresolved,
                remedy: Some(Remedy::JumpTable(0x1004)),
            },
            WarningRow {
                at: 0x1004,
                code: WarningCode::LiftUnsupported,
                remedy: Some(Remedy::Insn(0x1004)),
            },
            WarningRow {
                at: at_of(1),
                code: WarningCode::NoreturnAssumed,
                remedy: Some(Remedy::Disasm(0x2000)),
            },
        ]
    );
}

/// Gives a two-way branch. With `wrong`, its tree swaps the branches.
fn branchy(wrong: bool) -> ghidorah_decomp::Decomp {
    let cond = crate::out_print::bin(
        Opc::Eq,
        64,
        crate::out_print::v(0, 64),
        k(0, 64),
        op(0, 0, 0),
    );
    let ret = |i: usize| Stmt::Return {
        uses: vec![(Loc::RAX, k(u64::try_from(i).expect("small"), 64))],
        at: op(i, 0, 0),
    };
    decomp(
        vec![
            Spec::branch(1, 2, cond, op(0, 1, 0)),
            Spec::new(Exit::Stop, vec![ret(1)]),
            Spec::new(Exit::Stop, vec![ret(2)]),
        ],
        vec![param(0, 64)],
        Tree::If {
            cond: Cond::leaf(node(0)).with_exec(),
            then: Box::new(Tree::Block(node(if wrong { 2 } else { 1 }))),
            els: Some(Box::new(Tree::Block(node(if wrong { 1 } else { 2 })))),
        },
    )
}

#[test]
fn selfcheck_keeps_a_faithful_tree() {
    let mut d = branchy(false);
    assert!(selfcheck::traces_match(&d));
    let tree = d.tree.clone();
    assert_eq!(selfcheck::check(&mut d), Validation::Ok);
    assert_eq!((d.tree, d.mode), (tree, Mode::Structured));
    assert!(d.warnings.is_empty());
    assert_ne!(selfcheck::body_hash(&branchy(false).view), 0);
}

#[test]
fn selfcheck_repairs_a_wrong_tree() {
    let mut d = branchy(true);
    assert!(!selfcheck::traces_match(&d));
    assert_eq!(selfcheck::check(&mut d), Validation::Repaired);
    assert_eq!(d.mode, Mode::Flat(FlatReason::SelfCheck));
    assert_eq!(d.tree, ghidorah_decomp::flat::tree(&d.view.shape));
    assert!(selfcheck::traces_match(&d));
    assert_eq!(
        d.warnings,
        [Warning {
            code: WarningCode::StructureSelfcheck,
            at: ENTRY,
        }]
    );
}

#[test]
fn cache_keys_and_eviction() {
    let a = Opts::default();
    let b = Opts {
        passes: Passes {
            fold: false,
            ..Passes::ALL
        },
        ..Opts::default()
    };
    assert_ne!(cache::opts_hash(&a), cache::opts_hash(&b));
    assert_eq!(cache::opts_hash(&a), cache::opts_hash(&Opts::default()));
    let key = |n: u64| Key {
        func: FuncId(Address::ram(0x1000 + n)),
        epoch: Rev(1),
        opts: 7,
    };
    let mut c = Cache::new(2);
    assert!(c.is_empty());
    let out = output(Vec::new());
    let _ = c.put(key(0), out.clone());
    let _ = c.put(key(1), out.clone());
    assert!(c.get(&key(0)).is_some());
    let _ = c.put(key(2), out.clone());
    assert_eq!(c.len(), 2);
    assert!(c.get(&key(1)).is_none(), "the oldest use goes first");
    assert!(c.get(&key(0)).is_some() && c.get(&key(2)).is_some());
    assert_eq!((c.stats().hits, c.stats().misses), (3, 1));
    let mut one = Cache::new(0);
    let _ = one.put(key(0), out.clone());
    let _ = one.put(key(1), out);
    assert_eq!(one.len(), 1);
}
