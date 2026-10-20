//! Regression tests of the decompiler core.

use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::Duration;

use ghidorah_base::WarningCode;
use ghidorah_decomp::{ElideReason, Elided, Line, LineKind, LoopKind, Opts, Tree};
use ghidorah_decomp::{interp_ast, linemap};
use ghidorah_ir::{Arg, Builder, Config, Loc, NoImage, Opc, StopReason};

use crate::progs::{Program, body_with, decompile, l1_of};

/// A pure `do .. while` loop whose condition stays true ends on fuel in the value mode.
#[expect(
    clippy::many_single_char_names,
    reason = "the test program names each IR value with one letter"
)]
#[test]
fn regress_pure_loop_takes_fuel() {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    let x = b.get(Loc::RDI).expect("get");
    let c = b.binary(Opc::Eq, 64, x.into(), Arg::k(0)).expect("eq");
    b.put(Loc::RAX, c.into()).expect("put");
    b.begin(0x1004, 4).expect("in order");
    let y = b.get(Loc::RAX).expect("get");
    b.flow(Opc::CJump, y.into(), Arg::k(0x1004)).expect("jcc");
    b.begin(0x1008, 4).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000, 0x1004, 0x1008], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: vec![(Loc::RDI, 0)],
    };
    let ssa = l1_of(&p);
    let d = decompile(&p, &ssa, &Opts::default());
    let has_loop = d.tree.preorder().iter().any(|t| {
        matches!(
            t,
            Tree::Loop {
                kind: LoopKind::DoWhile,
                ..
            }
        )
    });
    assert!(has_loop, "{:?}", d.tree);
    let (tx, rx) = mpsc::channel();
    let setup = p.setup;
    std::thread::spawn(move || {
        let out = interp_ast::run(&d, &NoImage, &Config::default(), &setup, 1_000);
        let _ = tx.send(out.reason);
    });
    let reason = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the value run ends on fuel");
    assert_eq!(reason, StopReason::FuelExhausted);
}

/// The fuzz target `pipeline_elf` found a function of 100,000 instructions in one block: a
/// region of zero fill. The view of one block compared each instruction with every op of the
/// block, so the decompile took minutes. A block of 40,000 instructions now ends in seconds.
#[test]
fn regress_long_block_view_is_not_quadratic() {
    const COUNT: u64 = 40_000;
    let mut b = Builder::new();
    for k in 0..COUNT {
        b.begin(0x1000 + k, 1).expect("in order");
        let x = b.get(Loc::RAX).expect("get");
        let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1)).expect("add");
        b.put(Loc::RAX, y.into()).expect("put");
    }
    b.begin(0x1000 + COUNT, 1).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: Vec::new(),
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let ssa = l1_of(&p);
        let d = decompile(&p, &ssa, &Opts::default());
        let _ = tx.send(d.tree.preorder().len());
    });
    let nodes = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the decompile of one long block ends in 10 s");
    assert!(nodes > 0);
}

/// Gives a statement line with the address range `span`.
fn line_at(span: (u64, u64)) -> Line {
    Line {
        text: "x;".to_owned(),
        kind: LineKind::Stmt,
        depth: 1,
        ops: Vec::new(),
        span: Some(span),
        comment: None,
        calls: Vec::new(),
        strings: Vec::new(),
    }
}

/// A range that ends at the top address holds its last byte. The old half-open ranges of the
/// line map saturated at `u64::MAX`, so they lost that byte (verification-07).
#[test]
fn regress_linemap_covers_top_byte() {
    let top = Elided {
        start: u64::MAX,
        size: 1,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[top], u64::MAX));
    assert!(!linemap::covered(&[], &[top], u64::MAX - 1));
    let two = Elided {
        start: u64::MAX - 1,
        size: 2,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[two], u64::MAX));
    assert!(linemap::covered(&[], &[two], u64::MAX - 1));
    let line = line_at((u64::MAX - 1, 2));
    assert!(linemap::covered(std::slice::from_ref(&line), &[], u64::MAX));
    assert!(!linemap::covered(&[line], &[], u64::MAX - 2));
    let past = Elided {
        start: u64::MAX - 1,
        size: 8,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[past], u64::MAX));
    let merged = linemap::merge(vec![two, top]);
    assert_eq!(merged, vec![two, top], "{merged:?}");
}

/// A printer that drops a store or a call must not hide it as `no effect`. With no printed
/// line, `cover` gives no elided row for the store, the call and the return. It gives
/// `W_STRUCTURE_SELFCHECK` at each of them. A dead add stays `no effect` (tests-tdd-01).
#[test]
fn regress_linemap_does_not_hide_dropped_store() {
    let mut b = Builder::new();
    b.begin(0x2000, 4).expect("in order");
    let addr = b.get(Loc::RDI).expect("get");
    b.store(64, addr.into(), Arg::k(1)).expect("store");
    b.begin(0x2004, 5).expect("in order");
    b.flow(Opc::Call, Arg::k(0x9000), Arg::Nil).expect("call");
    b.begin(0x2009, 1).expect("in order");
    let dead = b.get(Loc::RDI).expect("get");
    let _ = b
        .binary(Opc::Add, 64, dead.into(), Arg::k(1))
        .expect("a dead add");
    b.begin(0x200a, 1).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x2000], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x2000,
        setup: Vec::new(),
    };
    let ssa = l1_of(&p);
    let d = decompile(&p, &ssa, &Opts::default());
    assert_eq!(
        d.view.effects,
        BTreeSet::from([0x2000, 0x2004, 0x200a]),
        "{:?}",
        d.view.insns
    );
    let units = d.view.insns.clone();
    let mut elided = Vec::new();
    let warnings = linemap::cover(
        &[],
        &d.view.insns,
        &BTreeSet::new(),
        &d.view.effects,
        &units,
        &mut elided,
    );
    assert_eq!(
        elided,
        vec![Elided {
            start: 0x2009,
            size: 1,
            reason: ElideReason::NoEffect,
        }]
    );
    let at: Vec<u64> = warnings.iter().map(|w| w.at).collect();
    assert_eq!(at, [0x2000, 0x2004, 0x200a], "{warnings:?}");
    assert!(
        warnings
            .iter()
            .all(|w| w.code == WarningCode::StructureSelfcheck),
        "{warnings:?}"
    );
    let printed = ghidorah_decomp::finish(
        d,
        &ghidorah_decomp::NoEnv,
        &ghidorah_ir::NoNames,
        "f",
        &units,
    );
    assert!(
        printed
            .warnings
            .iter()
            .all(|w| w.code != WarningCode::StructureSelfcheck),
        "the printer shows each effect: {:?}",
        printed.warnings
    );
}

/// Gives each variable token `v<N>` of `text` with a flag: `true` when the token is the left
/// side of an assignment. A store through a pointer reads its variable.
fn var_tokens(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut start = None;
        let ends = line
            .char_indices()
            .chain(std::iter::once((line.len(), ' ')));
        for (k, ch) in ends {
            let ident = ch.is_ascii_alphanumeric() || ch == '_';
            match (ident, start) {
                (true, None) => start = Some(k),
                (false, Some(s)) => {
                    start = None;
                    let word = &line[s..k];
                    let digits = word.strip_prefix('v').unwrap_or_default();
                    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                        continue;
                    }
                    let before = line[..s].trim_start();
                    let lead =
                        before.is_empty() || before.ends_with("for (") || before.ends_with("; ");
                    let def = lead && line[k..].starts_with(" = ");
                    out.push((word.to_owned(), def));
                }
                _ => {}
            }
        }
    }
    out
}

/// Gives the variables `v<N>` that `text` reads but never assigns.
pub fn undefined_reads(text: &str) -> BTreeSet<String> {
    let tokens = var_tokens(text);
    let defs: BTreeSet<&String> = tokens.iter().filter(|t| t.1).map(|t| &t.0).collect();
    tokens
        .iter()
        .filter(|t| !t.1 && !defs.contains(&t.0))
        .map(|t| t.0.clone())
        .collect()
}

/// Gives the variables `v<N>` that `text` assigns but never reads.
fn dead_assigns(text: &str) -> BTreeSet<String> {
    let tokens = var_tokens(text);
    let reads: BTreeSet<&String> = tokens.iter().filter(|t| !t.1).map(|t| &t.0).collect();
    tokens
        .iter()
        .filter(|t| t.1 && !reads.contains(&t.0))
        .map(|t| t.0.clone())
        .collect()
}

/// Gives the decompiled text of the function at `entry` of the fixture `fixture`.
pub fn text_at(fixture: &str, entry: u64) -> String {
    let p = crate::fixtures::program(fixture);
    ghidorah_decomp::render(
        p,
        crate::fixtures::fid(entry),
        &Opts::default(),
        &ghidorah_ir::NoNames,
        &mut ghidorah_base::Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {entry:#x}: {e}"))
    .text()
}

/// A function that passes an entry value on to a call or a tail call has that parameter.
/// `cc::recover` counted a call as a read of its target only. So the namer limit made the
/// entry value a register value with no def, and the head lost the parameter. A caller of
/// such a function lost the argument (r2-engine-01).
#[test]
fn regress_forwarded_params_stay_params() {
    let main = crate::regress_sema::text("hello.gcc-O2", "main");
    assert!(
        main.starts_with("uint64_t main(uint64_t param_1)\n"),
        "{main}"
    );
    assert!(main.contains("return run(param_1);"), "{main}");
    let left = crate::regress_sema::text("two_helpers.gcc-O2", "left_value");
    assert!(left.contains("helper(param_1)"), "{left}");
    assert!(undefined_reads(&left).is_empty(), "{left}");
    let wrapper = text_at("pe/pe_main.exe", 0x1_4000_1236);
    let head = wrapper.lines().next().unwrap_or_default();
    assert_eq!(head.matches("param_").count(), 4, "{wrapper}");
    assert!(
        wrapper.contains("FUN_140001242(param_1, param_2, param_3, param_4)"),
        "{wrapper}"
    );
    let caller = crate::regress_sema::text("two_helpers.gcc-O2", "main");
    assert!(
        caller.contains("left_value(") && !caller.contains("left_value()"),
        "{caller}"
    );
    assert!(caller.contains("right_value(param_1)"), "{caller}");
    assert!(dead_assigns(&caller).is_empty(), "{caller}");
}

/// The fixtures whose text must read no entry value of an argument register as a register
/// value.
const PARAM_FIXTURES: [&str; 14] = [
    "hello.clang-O2",
    "hello.clang-O2.stripped",
    "hello.gcc-O2",
    "hello.gcc-O2-nocet-nopie",
    "hello.gcc-O2-noplt",
    "hello.gcc-O2.noeh",
    "hello.gcc-O2.noshdr",
    "hello.gcc-O2.stripped",
    "two_helpers.gcc-O2",
    "two_helpers.clang-O2",
    "strings.gcc-O2",
    "varargs.gcc-O2",
    "pe/pe_main.exe",
    "pe/pe_flags.exe",
];

/// Gives the undefined reads of the text of each function of `fixture` whose variable holds
/// the entry value of an integer argument register. The entry stack pointer, a floating
/// register and the other registers have no parameter number of their own, so the check
/// leaves them out.
fn undefined_params(fixture: &str) -> Vec<String> {
    let p = crate::fixtures::program(fixture);
    let args: BTreeSet<Loc> = ghidorah_analysis::cc::conv_of(p)
        .int_args
        .iter()
        .filter_map(|n| ghidorah_analysis::cc::loc_of(n))
        .collect();
    let mut bad = Vec::new();
    for f in p.funcs().iter().filter(|f| !f.func.flags.thunk) {
        let id = f.id();
        let d = ghidorah_decomp::decompile(
            p,
            id,
            &Opts::default(),
            &mut ghidorah_base::Fuel::new(50_000_000),
        )
        .unwrap_or_else(|e| panic!("{fixture} {:#x}: {e}", id.0.off));
        let vars = d.view.vars.clone();
        let env = ghidorah_decomp::ProgramEnv(p);
        let body = ghidorah_decomp::print::body_units(p, id);
        let out = ghidorah_decomp::finish(d, &env, &ghidorah_ir::NoNames, "f", &body);
        let text = out.text();
        for name in undefined_reads(&text) {
            let input = out
                .vars
                .iter()
                .find(|r| r.name == name)
                .and_then(|r| vars.iter().find(|v| v.id == r.id))
                .and_then(|v| v.input);
            if input.is_some_and(|l| args.contains(&l)) {
                bad.push(format!("{fixture} {:#x} reads {name}:\n{text}", id.0.off));
            }
        }
    }
    bad
}

/// No function text of the fixtures reads a variable with no def that holds the entry value
/// of an argument register. Such a variable is a lost parameter (r2-engine-01).
#[test]
fn regress_no_undefined_register_values() {
    let bad: Vec<String> = PARAM_FIXTURES
        .iter()
        .flat_map(|f| undefined_params(f))
        .collect();
    assert!(bad.is_empty(), "{} reads:\n{}", bad.len(), bad.join("\n"));
}
