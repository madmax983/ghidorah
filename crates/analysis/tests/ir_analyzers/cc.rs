//! Parameter recovery and the varargs prologue (design Section 7.10, AC-090a).

use std::time::{Duration, Instant};

use ghidorah_analysis::cc::{self, ParamSource, Params};
use ghidorah_analysis::fir::{self, Opts, l1};
use ghidorah_base::Fuel;
use ghidorah_db::Program;
use ghidorah_ir::{Loc, Opc, Switches};
use ghidorah_json::Value;
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{ElfBuilder, Section};
use ghidorah_types::cc::SYSV_X86_64;

use crate::support::{
    analyze, cached, fid, fir_of, fixtures, list, named, program_of, truth, truth_funcs,
};

/// The prototypes of the calling-convention fixture: name, count and varargs.
fn prototypes(t: &Value) -> Vec<(String, u32, bool)> {
    let protos = t
        .get("facts")
        .and_then(|f| f.get("prototypes"))
        .and_then(Value::as_array)
        .expect("prototypes");
    protos
        .iter()
        .map(|p| {
            let name = p.get("name").and_then(Value::as_str).expect("a name");
            let count = p.get("params").and_then(Value::as_u64).expect("a count");
            let varargs = p.get("varargs").and_then(Value::as_bool).expect("a flag");
            (
                name.to_owned(),
                u32::try_from(count).expect("a small count"),
                varargs,
            )
        })
        .collect()
}

#[test]
fn ac_090a_param_counts() {
    let (mut total, mut right) = (0, 0);
    let mut misses = Vec::new();
    for f in fixtures() {
        if f.program != "varargs" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for (name, count, _) in prototypes(&t) {
            let (params, _) =
                cc::params(p, fid(funcs[&name]), &mut Fuel::unlimited()).expect("the params");
            total += 1;
            if params.count() == count {
                right += 1;
            } else {
                misses.push(format!("{} {name}: {params:?}", f.path));
            }
        }
    }
    assert!(total >= 60, "six builds of 13 functions: {total}");
    assert!(right * 100 >= total * 95, "{right} of {total}: {misses:?}");
}

#[test]
fn varargs_prologues() {
    for f in fixtures() {
        if f.program != "varargs" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for (name, count, varargs) in prototypes(&t) {
            let ir = fir_of(p, funcs[&name]);
            let got = cc::recover(&ir, &SYSV_X86_64);
            assert_eq!(got.varargs, varargs, "{} {name}", f.path);
            if varargs {
                assert_eq!(got.count(), count, "{} {name}: named params", f.path);
            }
        }
    }
}

#[test]
fn regress_shlx_prototype_two_params() {
    // shlx rax, rdi, rsi; ret
    let mut p = crate::blob::load(&[0xc4, 0xe2, 0xc9, 0xf7, 0xc7, 0xc3], 0);
    let _ = crate::support::analyze(&mut p);
    let base = crate::blob::BASE;
    let (params, source) = cc::params(&p, fid(base), &mut Fuel::unlimited()).expect("params");
    assert_eq!(source, ParamSource::Recovered);
    assert!(params.count() <= 2, "{params:?}");
    let ir = fir_of(&p, base);
    let effects: Vec<_> = ir
        .arena
        .ops()
        .iter()
        .filter(|op| op.opc == Opc::Intrinsic)
        .filter_map(|op| ir.arena.effect(op))
        .collect();
    assert_eq!(effects.len(), 1, "the shlx intrinsic");
    for e in effects {
        for loc in [Loc::RSP, Loc::RBP] {
            assert!(!e.uses.contains(loc) && !e.defs.contains(loc), "{e:?}");
        }
    }
}

#[test]
fn params_from_prototypes() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let puts = named(p, "puts@plt");
    let (params, source) = cc::params(p, fid(puts), &mut Fuel::unlimited()).expect("params");
    assert_eq!(source, ParamSource::Prototype);
    assert_eq!(params.count(), 1);
    let finish = named(p, "finish");
    let (params, source) = cc::params(p, fid(finish), &mut Fuel::unlimited()).expect("params");
    assert_eq!(source, ParamSource::Recovered);
    assert_eq!(
        params,
        Params {
            int: 1,
            ..Params::default()
        }
    );
    assert!(cc::params(p, fid(0x3), &mut Fuel::unlimited()).is_err());
    assert_eq!(cc::conv_of(p).name, "sysv");
    let t = truth("fixtures/truth/hello.gcc-O2.json");
    assert!(list(&t, "functions").len() > 5);
}

/// Gives the recovered parameter count of the function at `entry` of the fixture `path`.
fn recovered(path: &str, entry: u64) -> u32 {
    let p = cached(path);
    let (params, source) = cc::params(p, fid(entry), &mut Fuel::new(10_000_000))
        .unwrap_or_else(|e| panic!("{path} {entry:#x}: {e}"));
    assert_eq!(source, ParamSource::Recovered, "{path} {entry:#x}");
    params.count()
}

/// A function that passes its entry values on to a call or a tail call has those
/// parameters. The recovery counted a call as a read of its target only (r2-engine-01).
#[test]
fn regress_forwarded_param_counts() {
    let hello = cached("fixtures/bin/hello.gcc-O2");
    let main = named(hello, "main");
    assert_eq!(recovered("fixtures/bin/hello.gcc-O2", main), 1);
    let two = cached("fixtures/bin/two_helpers.gcc-O2");
    let left = named(two, "left_value");
    assert_eq!(recovered("fixtures/bin/two_helpers.gcc-O2", left), 1);
    assert_eq!(recovered("fixtures/bin/pe/pe_main.exe", 0x1_4000_1236), 4);
    let ir = fir_of(hello, main);
    assert_eq!(
        cc::recover(&ir, &SYSV_X86_64).count(),
        0,
        "recover reads no callee"
    );
}

/// Gives an analyzed executable whose entry `F` makes `n` calls, one to each function `g_i`.
/// Each `g_i` is a lone `ret` with no signature. Gives the program and the address of `F`.
fn fan_out(n: usize) -> (Program, u64) {
    let body = n * 5 + 1;
    let mut text = Vec::new();
    for i in 0..n {
        let next = i64::try_from(i * 5 + 5).expect("small");
        let target = i64::try_from(body + i * 2).expect("small");
        let rel = i32::try_from(target - next).expect("a near call");
        text.push(0xe8);
        text.extend_from_slice(&rel.to_le_bytes());
    }
    text.push(0xc3);
    for _ in 0..n {
        text.extend_from_slice(&[0xc3, 0xcc]);
    }
    let (bytes, layout) = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .build_with_layout();
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    let _ = analyze(&mut p);
    let f = layout.section(".text").expect("the code section").addr;
    (p, f)
}

/// `solve` found the callees of a function in one pass of the data flow for each callee, with
/// no fuel. So 4,000 calls to functions with no signature took 26 s. The fuel of the caller
/// did not see the work (r3-robust-01). The work now takes fuel for each block and each call
/// op. It grows linearly with the call count.
#[test]
fn regress_solve_children_linear() {
    let mut used = Vec::new();
    for n in [400usize, 800] {
        let (p, f) = fan_out(n);
        assert_eq!(p.funcs().len(), n + 1, "F and each g_i are functions");
        let mut build = Fuel::unlimited();
        let _ = fir::build(&p, fid(f), &Opts::DEFAULT, &mut build).expect("the IR of F");
        let started = Instant::now();
        let mut fuel = Fuel::unlimited();
        let (params, source) = cc::params(&p, fid(f), &mut fuel).expect("the params of F");
        let took = started.elapsed();
        assert_eq!(
            (params, source),
            (Params::default(), ParamSource::Recovered)
        );
        let extra = fuel.used() - build.used();
        let calls = u64::try_from(n).expect("small");
        assert!(
            extra >= calls,
            "{n} calls: the solve takes {extra} units after the build"
        );
        assert!(took < Duration::from_secs(5), "{n} calls: {took:?}");
        used.push(fuel.used());
    }
    assert!(
        used[1] * 2 <= used[0] * 5,
        "the fuel is not linear: {used:?}"
    );
}

/// Gives an analyzed executable whose entry `F` calls `t` functions `g_i`. Each `g_i` calls
/// `h_1`. Each `h_j` calls `h_(j + 1)` up to `h_k`, then runs `m` instructions. Gives the
/// program, the address of `F` and the address of each `h_j`.
fn shared_chain(t: usize, k: usize, m: usize) -> (Program, u64, Vec<u64>) {
    let call = |text: &mut Vec<u8>, to: usize| {
        let next = i64::try_from(text.len() + 5).expect("small");
        let rel = i32::try_from(i64::try_from(to).expect("small") - next).expect("a near call");
        text.push(0xe8);
        text.extend_from_slice(&rel.to_le_bytes());
    };
    let f_len = t * 5 + 1;
    let g_len = 6;
    let h_len = 5 + m * 3 + 1;
    let g_at = |i: usize| f_len + i * g_len;
    let h_at = |j: usize| f_len + t * g_len + j * h_len;
    let mut text = Vec::new();
    for i in 0..t {
        call(&mut text, g_at(i));
    }
    text.push(0xc3);
    for _ in 0..t {
        call(&mut text, h_at(0));
        text.push(0xc3);
    }
    for j in 0..k {
        if j + 1 < k {
            call(&mut text, h_at(j + 1));
        } else {
            text.extend_from_slice(&[0x31, 0xc0, 0x90, 0x90, 0x90]);
        }
        for _ in 0..m {
            text.extend_from_slice(&[0x83, 0xc0, 0x01]);
        }
        text.push(0xc3);
    }
    let (bytes, layout) = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .build_with_layout();
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    let _ = analyze(&mut p);
    let base = layout.section(".text").expect("the code section").addr;
    let hs = (0..k)
        .map(|j| base + u64::try_from(h_at(j)).expect("small"))
        .collect();
    (p, base, hs)
}

/// Gives the fuel of the L1 build of the function at `f`.
fn l1_fuel(p: &Program, f: u64) -> u64 {
    let mut fuel = Fuel::unlimited();
    let _ = l1::build(p, fid(f), &Opts::DEFAULT, &Switches::all(), &mut fuel).expect("the L1");
    fuel.used()
}

/// The L1 build gave each callee a fresh tank of 1,000,000 units and a solve with no memo. So
/// a callee that shared large callees with other callees built them again each time. The fuel
/// of the caller did not see the work (r3-robust-02). The solves of the callees now take the
/// fuel of the caller. One memo holds the bases of their functions.
#[test]
fn regress_callee_solves_use_caller_fuel() {
    let (p, f, hs) = shared_chain(10, 8, 1000);
    let conv = cc::conv_of(&p);
    let mut own = Fuel::unlimited();
    let l0 = fir::build(&p, fid(f), &Opts::DEFAULT, &mut own).expect("the IR of F");
    let _ = l1::lift(l0, conv, &Switches::all(), &mut own).expect("the L1 of F");
    let small = own.used() * 2;
    let built = l1::build(
        &p,
        fid(f),
        &Opts::DEFAULT,
        &Switches::all(),
        &mut Fuel::new(small),
    );
    assert!(
        built.is_err(),
        "the callee solves need more than {small} units"
    );
    let mut chain = Fuel::unlimited();
    for h in hs {
        let _ = fir::build(&p, fid(h), &Opts::DEFAULT, &mut chain).expect("the IR of h");
    }
    let one = l1_fuel(&p, f);
    let (p2, f2, _) = shared_chain(20, 8, 1000);
    let two = l1_fuel(&p2, f2);
    assert!(
        one >= chain.used(),
        "{one} units, the h chain takes {}",
        chain.used()
    );
    assert!(
        two * 2 <= one * 5,
        "the fuel is not linear: {one} and {two}"
    );
    assert!(
        two - one < chain.used(),
        "the h chain builds once: {one} and {two}, the chain takes {}",
        chain.used()
    );
}
