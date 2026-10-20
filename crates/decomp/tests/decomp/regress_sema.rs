//! Regression tests of the meaning of the decompiled text. Each test compares the C text or
//! the IR value with the meaning of the machine code.

use ghidorah_base::Fuel;
use ghidorah_decomp::print::{self, PrintEnv, Signature};
use ghidorah_decomp::{Call, Callee, Cond, Exit, Opts, Stmt, Tree, VarIdx};
use ghidorah_ir::{Loc, LocSet, NoNames, Opc};

use crate::fixtures::{entry_of, fid, program};
use crate::out_print::{ENTRY, Spec, bin, decomp, k, op, param, temp, text_of, un, v};
use crate::shapes::node;

/// Gives the decompiled text of the function `name` of the fixture `fixture`.
pub fn text(fixture: &str, name: &str) -> String {
    let p = program(fixture);
    let entry = entry_of(p, name);
    ghidorah_decomp::render(
        p,
        fid(entry),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {name}: {e}"))
    .text()
}

/// Gives the lines of the text of `fixture` and `name`, without the indentation.
fn lines(fixture: &str, name: &str) -> Vec<String> {
    text(fixture, name)
        .lines()
        .map(|l| l.trim().to_owned())
        .collect()
}

/// Gives the text of `if (!c) return 1; return 0;` for the compare `opc` of `param_1`.
fn negated_test(opc: Opc) -> Vec<String> {
    let test = bin(opc, 64, v(0, 64), v(0, 64), op(0, 0, 0));
    let ret = |value: u64, i: usize| Stmt::Return {
        uses: vec![(Loc::RAX, k(value, 64))],
        at: op(i, 0, 0),
    };
    let d = decomp(
        vec![
            Spec::branch(2, 1, test, op(0, 1, 0)),
            Spec::new(Exit::Stop, vec![ret(1, 1)]),
            Spec::new(Exit::Stop, vec![ret(0, 2)]),
        ],
        vec![param(0, 64)],
        Tree::Seq(vec![
            Tree::Block(node(0)),
            Tree::If {
                cond: Cond::leaf(node(0)).negate(),
                then: Box::new(Tree::Block(node(1))),
                els: None,
            },
            Tree::Block(node(2)),
        ]),
    );
    text_of(&d)
}

/// A negated `TestZ` leaf is `x != 0`, and a negated `TestNZ` leaf is `x == 0`. The printer
/// gave each negated test the text of the plain test (decomp-01).
#[test]
fn regress_negated_test_polarity() {
    let z = negated_test(Opc::TestZ);
    assert_eq!(z[2], "    if (param_1 != 0) {", "{z:?}");
    let nz = negated_test(Opc::TestNZ);
    assert_eq!(nz[2], "    if (param_1 == 0) {", "{nz:?}");
}

/// `xor eax, eax` reads `eax` through two `Trunc` ops with two op IDs. Its value is 0, so the
/// text is `0`. The zero rule of the printer compared the op IDs too (decomp-07).
#[test]
fn regress_zero_rule_ignores_op_ids() {
    let trunc = |seq| un(Opc::Trunc, 32, 0, v(0, 64), op(0, 0, seq));
    let xor = bin(Opc::Xor, 32, trunc(1), trunc(3), op(0, 0, 4));
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![Stmt::Return {
                uses: vec![(Loc::RAX, xor)],
                at: op(0, 1, 0),
            }],
        )],
        vec![param(0, 64)],
        Tree::Block(node(0)),
    );
    let t = text_of(&d);
    assert_eq!(t[2], "    return 0;", "{t:?}");
}

/// `sum_squares` reads only `edi` (`and edi, 0x3f`). Its `xor eax, eax` and `xor edx, edx`
/// give 0, so the text has no `^`, and the function line has one parameter. The text read
/// `v1 ^ v1` of a variable with no def, and the function line had 3 parameters (decomp-07).
#[test]
fn regress_zero_idiom_params() {
    let sum = text("loops.gcc-O2", "sum_squares");
    assert!(
        sum.starts_with("uint64_t sum_squares(uint64_t param_1)\n"),
        "{sum}"
    );
    assert!(sum.contains("return 0;"), "{sum}");
    assert!(!sum.contains(" ^ "), "{sum}");
    let count = text("loops.gcc-O2", "count_bits");
    assert!(
        count.starts_with("uint64_t count_bits(uint64_t param_1)\n"),
        "{count}"
    );
    let grid = text("loops.gcc-O2", "grid_walk");
    assert!(
        grid.starts_with("uint64_t grid_walk(uint64_t param_1, uint64_t param_2)\n"),
        "{grid}"
    );
    assert!(grid.contains("return 0;"), "{grid}");
}

/// Gives the text between `start` and the next `)` after each place of `start` in `text`.
fn args_after<'t>(text: &'t str, start: &str) -> Vec<&'t str> {
    text.match_indices(start)
        .filter_map(|(i, _)| {
            let rest = text.get(i + start.len()..)?;
            rest.split([')', ',']).next()
        })
        .collect()
}

/// `main` of xor_decode.clang-O2 passes `lea rdi,[rsp+0x9]` to `decode`, `puts` and
/// `strlen`, and no instruction between the calls changes `rsp`. So the three arguments are
/// one expression. L1 kept the stack pointer 8 bytes low after each call, so each later call
/// got another pointer (decomp-04).
#[test]
fn regress_stack_pointer_after_call() {
    let t = text("xor_decode.clang-O2", "main");
    let mut seen: Vec<&str> = Vec::new();
    for call in ["decode(", "puts(", "strlen("] {
        let got = args_after(&t, call);
        assert_eq!(got.len(), 1, "{call}: {t}");
        seen.extend(got);
    }
    assert!(seen[0].ends_with(" + 9"), "{t}");
    assert!(seen.iter().all(|a| *a == seen[0]), "{seen:?}\n{t}");
    // gcc pops rbx with `pop rbx` at `[rsp+0x20]` after `add rsp,0x20`, and 5 calls run
    // before. The buffer is at `rsp + 9`, so the pop reads the base of the buffer + 0x20.
    let g = text("xor_decode.gcc-O2", "main");
    let buffer = args_after(&g, "decode(")[0];
    let line = g
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&format!("{buffer} = ")) && l.ends_with(" + 9;"))
        .unwrap_or_else(|| panic!("no def of {buffer}: {g}"));
    let base = line
        .trim_start_matches(&format!("{buffer} = "))
        .trim_end_matches(" + 9;");
    assert!(
        g.contains(&format!(" = {base} + 0x20;")) || g.contains(&format!("({base} + 0x20)")),
        "the pop of rbx reads {base} + 0x20: {g}"
    );
}

/// Gives the top-level arguments of the call text `name(..)` in `line`.
fn call_args<'t>(line: &'t str, name: &str) -> Vec<&'t str> {
    let Some(start) = line.find(&format!("{name}(")) else {
        return Vec::new();
    };
    let body = &line[start + name.len() + 1..];
    let mut out = Vec::new();
    let (mut depth, mut from, mut quoted) = (0i32, 0usize, false);
    for (i, ch) in body.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth == 0 => {
                out.push(body[from..i].trim());
                return out;
            }
            ')' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(body[from..i].trim());
                from = i + 1;
            }
            _ => {}
        }
    }
    out
}

/// `push r14` at 0x10ec puts the 7th argument of `__printf_chk` on the stack: the
/// `grid_walk` result. The call took its arguments from registers only, so the text lost it
/// (decomp-05).
#[test]
fn regress_stack_argument_of_call() {
    let t = text("loops.gcc-O2", "main");
    let line = t
        .lines()
        .find(|l| l.contains("__printf_chk("))
        .unwrap_or_else(|| panic!("no __printf_chk call: {t}"));
    let args = call_args(line, "__printf_chk");
    assert_eq!(args.len(), 7, "{line}");
    let last = args[6];
    let grid = t
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_suffix(" = grid_walk((uint64_t)(uint32_t)v13, 7);"))
        .or_else(|| {
            t.lines()
                .map(str::trim)
                .find(|l| l.contains("= grid_walk("))
                .and_then(|l| l.split(" = ").next())
        })
        .unwrap_or_else(|| panic!("no grid_walk result: {t}"));
    assert!(
        t.contains(&format!("{last} = (uint64_t)(uint32_t){grid};")) || last.ends_with(grid),
        "the 7th argument {last} is the grid_walk result {grid}: {t}"
    );
}

/// `mov rdi,rbx; call rbp` passes the node to the visitor. The variable of `rdi` also holds
/// the entry value of `rdi`, so the printer counted no argument. gcc -O0 sets `rdi` through
/// a stack slot. It calls through `rdx`, so that register is not an argument (decomp-06).
#[test]
fn regress_indirect_call_arguments() {
    for fixture in ["recursion.gcc-O2", "recursion.clang-O2", "recursion.gcc-O0"] {
        let t = text(fixture, "walk");
        assert!(t.contains("(*param_2)(param_1);"), "{fixture}: {t}");
        assert!(t.starts_with("void walk("), "{fixture}: {t}");
        assert!(!t.contains("return v"), "{fixture}: {t}");
    }
}

/// A callee with no return value leaves no result in `rax`. `free_list` and `decode` return
/// no value, and the text assigned their `rax` and read it (decomp-11).
#[test]
fn regress_void_callee_result() {
    let main = text("struct_access.gcc-O2", "main");
    let free = main
        .lines()
        .map(str::trim)
        .find(|l| l.contains("free_list("))
        .unwrap_or_else(|| panic!("{main}"));
    assert!(free.starts_with("free_list("), "{main}");
    assert!(main.contains("return 0;"), "{main}");
    let main = text("xor_decode.gcc-O2", "main");
    let decode = main
        .lines()
        .map(str::trim)
        .find(|l| l.contains("decode("))
        .unwrap_or_else(|| panic!("{main}"));
    assert!(decode.starts_with("decode("), "{main}");
}

/// The facts of a hand-made function: the callee at 0x2000 returns no value.
struct VoidCallee;

impl ghidorah_decomp::Env for VoidCallee {
    fn callee_name(&self, addr: u64) -> Option<String> {
        (addr == 0x2000).then(|| "sink".to_owned())
    }
    fn is_noreturn(&self, _addr: u64) -> bool {
        false
    }
    fn is_string(&self, _addr: u64) -> bool {
        false
    }
}

impl PrintEnv for VoidCallee {
    fn signature(&self, addr: u64) -> Option<Signature> {
        (addr == 0x2000).then(|| Signature {
            params: Vec::new(),
            names: Vec::new(),
            ret: None,
            variadic: false,
        })
    }
}

/// The printer drops the result of a call whose callee signature has no return value. A
/// later read of the variable reads a value with no def (decomp-11).
#[test]
fn regress_void_signature_drops_result() {
    let call = Call {
        callee: Callee::Direct(0x2000),
        args: Vec::new(),
        set: LocSet::EMPTY,
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: vec![(Loc::RAX, VarIdx(0))],
        ret: None,
        noreturn: false,
        tail: false,
        at: op(0, 0, 0),
    };
    let d = decomp(
        vec![Spec::new(
            Exit::Stop,
            vec![
                Stmt::Call(call),
                Stmt::Return {
                    uses: vec![(Loc::RAX, v(0, 64))],
                    at: op(0, 1, 0),
                },
            ],
        )],
        vec![temp("rax", ENTRY, 64)],
        Tree::Block(node(0)),
    );
    let lines: Vec<String> = print::print(&d, &VoidCallee, &NoNames, "f")
        .lines
        .into_iter()
        .map(|l| l.text)
        .collect();
    assert_eq!(lines[2], "    sink();", "{lines:?}");
}

/// The canary pass removed the canary store but kept the reload, the `fs:0x28` load and the
/// difference. The failure call still read the difference, and the reload lost its class when
/// its store went. The text read a slot that no statement wrote (decomp-09).
#[test]
fn regress_canary_statements_go_together() {
    for (fixture, store) in [
        ("recursion.gcc-O0", 0x12b0u64),
        ("xor_decode.gcc-O0", 0),
        ("xor_decode.gcc-O2", 0),
        ("recursion.gcc-O2", 0),
    ] {
        let p = program(fixture);
        let out = ghidorah_decomp::render(
            p,
            fid(entry_of(p, "main")),
            &Opts::default(),
            &NoNames,
            &mut Fuel::new(50_000_000),
        )
        .unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let t = out.text();
        assert!(
            !t.contains(" + 0x28)"),
            "{fixture}: the fs:0x28 load stays: {t}"
        );
        assert!(
            !t.lines()
                .any(|l| l.trim().contains(" - v") && l.contains(" = v") && !l.contains('(')),
            "{fixture}: a canary difference stays: {t}"
        );
        if store != 0 {
            assert!(
                out.elided
                    .iter()
                    .any(|e| e.reason == ghidorah_decomp::ElideReason::Canary
                        && e.start <= store
                        && store < e.start + e.size),
                "{fixture}: the store at {store:#x} is not a canary range: {:?}",
                out.elided
            );
        }
    }
}

/// `call [rip+0x2fd8]` at 0x11af of `_start` pushes its return address 0x11b5. After
/// `and rsp, -16` the stack offset is unknown, so the push stayed a store and printed as
/// `*(uint64_t *)(v - 8) = 0x11b5;` (decomp-12).
#[test]
fn regress_call_push_is_not_a_store() {
    for fixture in ["xor_decode.gcc-O2", "hello.gcc-O2", "loops.clang-O2"] {
        let p = program(fixture);
        let entry = p.addrs_named("_start").first().map(|a| a.off);
        let Some(entry) = entry else {
            continue;
        };
        let out = ghidorah_decomp::render(
            p,
            fid(entry),
            &Opts::default(),
            &NoNames,
            &mut Fuel::new(50_000_000),
        )
        .unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let t = out.text();
        let stores: Vec<&str> = t
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("*(uint64_t *)") && l.contains(") = 0x"))
            .collect();
        assert!(stores.is_empty(), "{fixture}: {stores:?}\n{t}");
        assert!(t.contains("(0x"), "{fixture}: the call of main stays: {t}");
    }
}

/// Gives the opaque instruction call of the view of `d` at `addr`.
fn intrinsic_at(d: &ghidorah_decomp::Decomp, addr: u64) -> Call {
    d.view
        .nodes
        .iter()
        .flat_map(|n| &n.stmts)
        .flat_map(|s| {
            let mut found: Vec<Call> = Vec::new();
            if let Stmt::Call(c) = s {
                found.push(c.clone());
            }
            for e in s.exprs() {
                for x in e.preorder() {
                    if let ghidorah_decomp::Expr::Call(c) = x {
                        found.push(c.as_ref().clone());
                    }
                }
            }
            found
        })
        .find(|c| c.at.addr == addr && matches!(c.callee, Callee::Intrinsic(_)))
        .unwrap_or_else(|| panic!("no opaque instruction at {addr:#x}"))
}

/// Gives the register locations of the arguments of a call in order.
fn arg_locs(c: &Call) -> Vec<Loc> {
    c.args.iter().map(|(l, _)| *l).collect()
}

/// `pcmpgtd xmm10,xmm0` at 0x12aa computes `xmm10 > xmm0`, and `pandn xmm10,xmm7` at 0x12b4
/// computes `~xmm10 & xmm7`. The uses of an opaque instruction were a set in register order,
/// so the text gave `__pcmpgtd(xmm0, xmm10)`. `pshufd` lost its control byte (decomp-08).
#[test]
fn regress_intrinsic_operand_order() {
    let xmm = |n| Loc::xmm(n).expect("an XMM register");
    let p = program("loops.clang-O2");
    let entry = entry_of(p, "grid_walk");
    let d = ghidorah_decomp::decompile(p, fid(entry), &Opts::default(), &mut Fuel::unlimited())
        .expect("the decompile");
    let cmp = intrinsic_at(&d, 0x12aa);
    assert_eq!(arg_locs(&cmp)[..2], [xmm(10), xmm(0)], "{cmp:?}");
    let andn = intrinsic_at(&d, 0x12b4);
    assert_eq!(arg_locs(&andn)[..2], [xmm(10), xmm(7)], "{andn:?}");
    let shuffle = intrinsic_at(&d, 0x12be);
    assert_eq!(arg_locs(&shuffle).first(), Some(&xmm(10)), "{shuffle:?}");
    assert_eq!(shuffle.imm, [0xee]);
    assert_eq!(intrinsic_at(&d, 0x12c9).imm, [0x55]);
    let text = text("loops.clang-O2", "grid_walk");
    assert!(
        text.contains(", 0xee)") && text.contains(", 0x55)"),
        "{text}"
    );
}

/// Fusion moves the compare of `test rdx,rdx` (0x12d2) and `cmp r12,rbx` (0x12f7) to the
/// branch. So the condition lines held only the branch, and the compares got `no effect`. An out-of-SSA copy took the address of its join block, not the address of its
/// move: `xor ebx,ebx` (0x12da) for the loop counter (decomp-10).
#[test]
fn regress_line_map_of_compares_and_copies() {
    let p = program("xor_decode.gcc-O2");
    let out = ghidorah_decomp::render(
        p,
        fid(entry_of(p, "decode")),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .expect("the render");
    let line = |pred: &dyn Fn(&str) -> bool| {
        out.lines
            .iter()
            .find(|l| pred(l.text.trim()))
            .unwrap_or_else(|| panic!("no line: {}", out.text()))
    };
    let span = |l: &ghidorah_decomp::Line| l.span.expect("a line range");
    let guard = line(&|t| t == "if (param_3 != 0) {");
    assert_eq!(span(guard).0, 0x12d2, "{guard:?}");
    let back = line(&|t| t.starts_with("} while (param_3 != "));
    let (start, size) = span(back);
    assert!(start <= 0x12f7 && 0x12f7 < start + size, "{back:?}");
    let init = line(&|t| t.ends_with(" = 0;") && !t.starts_with('*'));
    assert_eq!(span(init).0, 0x12da, "{init:?}");
    for addr in [0x12d2u64, 0x12f7] {
        assert!(
            !out.elided
                .iter()
                .any(|e| e.start <= addr && addr < e.start + e.size),
            "{addr:#x} is elided: {:?}",
            out.elided
        );
    }
}

/// `test rdx,rdx; je 12fc` at 0x12d2 of `decode` skips the loop when `n == 0`. So the loop
/// runs under `param_3 != 0`. `test rdx,rdx; jne 1260` at 0x126b of `gcd` loops while the
/// remainder is not 0, so the loop breaks on `== 0` (decomp-01).
#[test]
fn regress_negated_test_polarity_fixtures() {
    let decode = lines("xor_decode.gcc-O2", "decode");
    assert!(
        decode.iter().any(|l| l == "if (param_3 != 0) {"),
        "{decode:#?}"
    );
    let gcd = text("loops.gcc-O2", "gcd");
    let zero_tests = gcd
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("if (") && l.contains("== 0"))
        .count();
    assert_eq!(zero_tests, 2, "{gcd}");
    assert!(!gcd.contains("!= 0"), "{gcd}");
}
