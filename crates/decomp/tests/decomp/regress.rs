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

/// Tells if each read of the variable `name` in `text` is a store of its value to memory:
/// `*(..) = name;`. The integer save area of a varargs function stores the entry values of the
/// argument registers after the named parameters. They are register values, not parameters.
fn save_area_only(text: &str, name: &str) -> bool {
    let store = format!(" = {name};");
    text.lines()
        .filter(|l| var_tokens(l).iter().any(|(t, _)| t == name))
        .all(|l| l.trim_start().starts_with("*(") && l.ends_with(&store))
}

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
        let varargs = ghidorah_analysis::cc::params(p, id, &mut ghidorah_base::Fuel::unlimited())
            .is_ok_and(|(params, _)| params.varargs);
        for name in undefined_reads(&text) {
            if varargs && save_area_only(&text, &name) {
                continue;
            }
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

/// Gives the count of the top-level arguments of the first call of `name` in `text`.
fn arg_count(text: &str, name: &str) -> usize {
    let start = text
        .find(&format!("{name}("))
        .unwrap_or_else(|| panic!("no call of {name}: {text}"));
    let body = &text[start + name.len() + 1..];
    let (mut depth, mut commas) = (0usize, 0usize);
    for ch in body.chars() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => return if body.starts_with(')') { 0 } else { commas + 1 },
            ')' => depth -= 1,
            ',' if depth == 0 => commas += 1,
            _ => {}
        }
    }
    commas + 1
}

/// A slot of the MS x64 convention is its position: `rcx` or `xmm0` is slot 0, up to `r9` or
/// `xmm3`. `Env::param_count` gave the count of the integer slots only, and the namer named
/// no floating slot. So `c` of `m3(int a, double b, int c)` read as a register value, and a
/// caller passed 2 of the 3 arguments (r2-engine-02).
#[test]
fn regress_positional_param_slots() {
    let fixture = "pe/pe_cc.exe";
    let body = |text: &str| text.lines().skip(1).collect::<Vec<_>>().join("\n");
    let m3 = text_at(fixture, 0x1_4000_1130);
    let head = m3.lines().next().unwrap_or_default();
    assert_eq!(head.matches("param_").count(), 3, "{m3}");
    assert!(body(&m3).contains("param_3"), "r8 is param_3: {m3}");
    let m4 = text_at(fixture, 0x1_4000_1150);
    assert!(body(&m4).contains("param_4"), "r9 is param_4: {m4}");
    let g2 = text_at(fixture, 0x1_4000_11c0);
    assert!(body(&g2).contains("param_2"), "rdx is param_2: {g2}");
    for text in [&m3, &m4, &g2] {
        assert!(undefined_reads(text).is_empty(), "{text}");
    }
    let start = text_at(fixture, 0x1_4000_11e0);
    assert_eq!(arg_count(&start, "FUN_140001130"), 3, "{start}");
    assert_eq!(arg_count(&start, "FUN_140001150"), 4, "{start}");
    assert_eq!(arg_count(&start, "FUN_1400011c0"), 2, "{start}");
}

/// Gives the output of the function `name` of the fixture `fixture`.
fn output_of(fixture: &str, name: &str) -> ghidorah_decomp::Output {
    let p = crate::fixtures::program(fixture);
    let entry = crate::fixtures::entry_of(p, name);
    ghidorah_decomp::render(
        p,
        crate::fixtures::fid(entry),
        &Opts::default(),
        &ghidorah_ir::NoNames,
        &mut ghidorah_base::Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {name}: {e}"))
}

/// Gives the names of the call rows of an output.
fn call_names(out: &ghidorah_decomp::Output) -> Vec<String> {
    out.lines
        .iter()
        .flat_map(|l| &l.calls)
        .map(|c| c.name.clone())
        .collect()
}

/// `finish` of the `-fno-plt` build calls `puts` through its GOT slot: `call [rip+x]`. The
/// call named its target `DAT_00000003`, the EXTERNAL address of the import (known-04).
/// The finding names `main`, but `main` of hello only tail calls `run`.
#[test]
fn regress_noplt_got_call_names_import() {
    let fixture = "hello.gcc-O2-noplt";
    let finish = output_of(fixture, "finish");
    let text = finish.text();
    assert!(text.contains("puts(\"Goodbye.\");"), "{text}");
    assert!(!text.contains("DAT_"), "{text}");
    assert_eq!(call_names(&finish), ["puts"], "{text}");
    let main = output_of(fixture, "main");
    assert!(
        call_names(&main).iter().all(|n| !n.starts_with("DAT_")),
        "{}",
        main.text()
    );
}

/// `greet` of the `-fno-plt` build ends with `jmp [rip+x]` through the GOT slot of
/// `__printf_chk` at stack height 0. It is no thunk, so the jump stayed a `goto` that read no
/// argument register (known-05). The finding names `puts`, but the slot is the one of
/// `__printf_chk`: `greet` calls `printf`, which the build fortifies.
#[test]
fn regress_noplt_got_jump_is_tail_call() {
    let greet = output_of("hello.gcc-O2-noplt", "greet");
    let text = greet.text();
    assert!(
        text.contains("return __printf_chk(2, \"Hello, %s!\\n\", param_1);"),
        "{text}"
    );
    assert!(!text.contains("goto"), "{text}");
    assert_eq!(call_names(&greet), ["__printf_chk"], "{text}");
}

/// `_start` calls `__libc_start_main` through its GOT slot after `and rsp, -16`. The push of
/// the return address can alias the slot, so the load did not fold into the call. The call
/// names the import, so the load stayed as an assignment that no line reads (known-04).
#[test]
fn regress_import_call_slot_load_has_no_statement() {
    for fixture in ["hello.gcc-O2", "hello.gcc-O2-noplt"] {
        let text = output_of(fixture, "_start").text();
        assert!(text.contains("__libc_start_main("), "{text}");
        assert!(dead_assigns(&text).is_empty(), "{text}");
    }
}

/// `_start` of `syscall_only` takes no register argument. The six reads of a `Syscall` op went
/// up to it through the call reads. So its head had six parameters and it passed them on to
/// `emit_banner` (r3-engine-03).
#[test]
fn regress_syscall_reads_its_arity_text() {
    for fixture in [
        "syscall_only.gcc-O0",
        "syscall_only.gcc-O2",
        "syscall_only.clang-O2",
    ] {
        let text = output_of(fixture, "_start").text();
        assert!(text.starts_with("void _start(void)\n"), "{fixture}: {text}");
        assert!(text.contains("emit_banner();"), "{fixture}: {text}");
    }
}

/// A call of a callee with a short count kept each argument register up to the last one that
/// the caller writes. The text printed none of those registers. But the uses kept scratch
/// values alive, so the values did not fold (r3-engine-02). A known count is now the use
/// list of the call.
#[test]
fn regress_known_count_keeps_folds() {
    let f0152 = output_of("large.clang-O2", "f0152").text();
    assert!(
        f0152.contains("return f0011(0xf97f86ef * param_2, 0xbb1bcd8a ^ param_1);"),
        "{f0152}"
    );
    let copy = output_of("canary.gcc-O0", "copy_name").text();
    assert!(!copy.contains("= v12 - 0x30;"), "{copy}");
}

/// An import with no Tier-0 prototype has no count. The thunk of `Sleep` got a recovered
/// count of 0. So a caller printed `Sleep();` and dropped the argument that `mov ecx, eax`
/// sets (r3-engine-04).
#[test]
fn regress_open_import_count_keeps_set_args() {
    let p = crate::fixtures::program("pe/pe_main.exe");
    let out = ghidorah_decomp::render(
        p,
        crate::fixtures::fid(0x1_4000_10b0),
        &Opts::default(),
        &ghidorah_ir::NoNames,
        &mut ghidorah_base::Fuel::new(50_000_000),
    )
    .expect("the text of FUN_1400010b0");
    let line = out
        .lines
        .iter()
        .find(|l| {
            l.calls
                .iter()
                .any(|c| c.target == ghidorah_decomp::CallTarget::Addr(0x1_4000_11e0))
        })
        .expect("the call of the Sleep thunk");
    assert_eq!(arg_count(&line.text, "Sleep"), 1, "{}", out.text());
}

/// Gives the parameter texts of the head of `text`. The variadic marker `...` is not a
/// parameter.
fn head_params(text: &str) -> Vec<String> {
    let head = text.lines().next().unwrap_or_default();
    let (Some(open), Some(close)) = (head.find('('), head.rfind(')')) else {
        panic!("no parameter list: {head}");
    };
    let list = &head[open + 1..close];
    list.split(", ")
        .filter(|p| *p != "void" && *p != "...")
        .map(str::to_owned)
        .collect()
}

/// Gives the text of the function at `entry` of `p` after the rename of the function to
/// `name`.
fn renamed_text(fixture: &str, entry: u64, name: &str) -> String {
    let mut p = crate::fixtures::program(fixture).clone();
    let label = ghidorah_db::SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("edit", ghidorah_db::Source::User, label)
        .expect("a transaction");
    let edit = ghidorah_db::Edit::SetName {
        addr: ghidorah_base::Address::ram(entry),
        key: None,
        kind: ghidorah_db::SymKind::Function,
        primary: true,
        name: Some(tx.fact(name.to_owned())),
        evidence: Vec::new(),
    };
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    ghidorah_decomp::render(
        &p,
        crate::fixtures::fid(entry),
        &Opts::default(),
        &ghidorah_ir::NoNames,
        &mut ghidorah_base::Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {entry:#x}: {e}"))
    .text()
}

/// The varargs prologue stores `rsi` .. `r9` to the register save area. The namer counted
/// those stores as reads of parameter slots, and the head took the slots that the text reads.
/// So `log_msg` and `sum_va` printed six parameters, and a Tier-0 prototype or a signature no
/// longer bounded the head (r3-engine-01). The registers of the save area are no named
/// parameters, and a fact count bounds the head.
#[test]
fn regress_varargs_head_keeps_fact_count() {
    let mut seen = 0;
    for build in ["gcc-O0", "gcc-O2", "clang-O2"] {
        let truth = std::fs::read_to_string(
            crate::fixtures::root().join(format!("fixtures/truth/varargs.{build}.json")),
        )
        .expect("the truth file");
        let truth = crate::fixtures::json(&truth);
        let funcs = truth
            .get("functions")
            .and_then(ghidorah_json::Value::as_array)
            .expect("the truth functions");
        for name in ["log_msg", "sum_va"] {
            let addr = funcs
                .iter()
                .find(|f| f.get("name").and_then(ghidorah_json::Value::as_str) == Some(name))
                .and_then(|f| f.get("addr").and_then(ghidorah_json::Value::as_str))
                .and_then(ghidorah_base::hex::parse_u64)
                .expect("the truth address");
            for fixture in [
                format!("varargs.{build}"),
                format!("varargs.{build}.stripped"),
            ] {
                let text = text_at(&fixture, addr);
                assert_eq!(head_params(&text).len(), 1, "{fixture} {name}: {text}");
                seen += 1;
            }
        }
    }
    assert_eq!(seen, 12, "six builds of two functions");
    let printf = renamed_text("varargs.gcc-O2", 0x14c0, "printf");
    let head = printf.lines().next().unwrap_or_default();
    assert_eq!(head_params(&printf).len(), 1, "{printf}");
    assert!(head.ends_with(", ...)"), "the variadic marker: {printf}");
    let puts = renamed_text("varargs.gcc-O2", 0x1300, "puts");
    assert_eq!(head_params(&puts).len(), 1, "{puts}");
}
