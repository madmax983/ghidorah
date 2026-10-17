//! The expression oracle: the AST value interpreter against the L0 interpreter (AC-101).

use std::path::PathBuf;

use ghidorah_base::Fuel;
use ghidorah_decomp::interp_ast;
use ghidorah_decomp::{Opts, Passes};
use ghidorah_ir::{Config, Interp, Loc, StopReason};
use ghidorah_json::Value;
use ghidorah_testkit::rng::Xoshiro256ss;

use crate::fixtures::{
    ProgramImage, STACK_LO, STACK_SIZE, decompile, entry_of, json, l1_of, program, root,
};
use crate::progs::{
    decompile as decompile_gen, l1_of as gen_l1, ram_image, random_program, run_ast, run_l0,
};

/// The fuel of one L0 run of a leaf function.
const LEAF_FUEL: u64 = 200_000;

/// The leaf functions of one truth file: the fixture and the names.
fn leaf_files() -> Vec<(String, Vec<String>)> {
    let dir = root().join("fixtures/truth");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the truth directory")
        .map(|e| e.expect("entry").path())
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        let t = json(&std::fs::read_to_string(&p).expect("a truth file"));
        let leaves: Vec<String> = t
            .get("leaf_functions")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|l| l.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        if leaves.is_empty() {
            continue;
        }
        let fixture = t
            .get("fixture")
            .and_then(Value::as_str)
            .expect("a fixture name")
            .to_owned();
        out.push((fixture, leaves));
    }
    out
}

/// Gives the argument lists of the leaf vectors of one function.
fn vector_args(fixture: &str, name: &str) -> Vec<Vec<u64>> {
    let path = root().join(format!("tests/golden/semantics/leaf/{fixture}.jsonl"));
    let text = std::fs::read_to_string(&path).expect("a leaf vector file");
    text.lines()
        .skip(1)
        .map(json)
        .filter(|v| v.get("fn").and_then(Value::as_str) == Some(name))
        .map(|v| {
            v.get("args")
                .and_then(Value::as_array)
                .expect("args")
                .iter()
                .map(|a| {
                    ghidorah_base::hex::parse_u64(a.as_str().expect("a hex string"))
                        .expect("a hex number")
                })
                .collect()
        })
        .collect()
}

/// Checks each leaf function of one fixture. Gives the count of runs and the failures.
fn check_fixture(fixture: &str, leaves: &[String]) -> (usize, Vec<String>) {
    let p = program(fixture);
    let image = ProgramImage(p);
    let mut runs = 0;
    let mut failures = Vec::new();
    for name in leaves {
        let entry = entry_of(p, name);
        let ir = l1_of(p, entry);
        let d = decompile(p, entry, &Opts::default());
        for args in vector_args(fixture, name).iter().take(250) {
            let mut setup = vec![(Loc::RSP, u128::from(STACK_LO + STACK_SIZE - 0x100))];
            for (loc, v) in [Loc::RDI, Loc::RSI, Loc::RDX].into_iter().zip(args) {
                setup.push((loc, u128::from(*v)));
            }
            let mut interp = Interp::new(&ir.l0.arena, &image, Config::default());
            for &(loc, v) in &setup {
                interp.set_loc(loc, v);
            }
            let stop = interp.run(entry, &mut Fuel::new(LEAF_FUEL));
            let ast = interp_ast::run(&d, &image, &Config::default(), &setup, 4 * LEAF_FUEL);
            runs += 1;
            let want_rax = Some(interp.loc(Loc::RAX));
            let got_rax = ast
                .uses
                .iter()
                .find(|(l, _)| *l == Loc::RAX)
                .and_then(|u| u.1);
            let same_mem = ast.writes.iter().all(|(a, b)| interp.read(*a) == Some(*b));
            if stop.reason != StopReason::Returned
                || ast.reason != stop.reason
                || ast.at != stop.at
                || got_rax != want_rax
                || !same_mem
            {
                failures.push(format!(
                    "{fixture} {name}({args:x?}): L0 {:?} at {} rax {want_rax:x?}, AST {:?} at {} rax {got_rax:x?}",
                    stop.reason, stop.at, ast.reason, ast.at
                ));
            }
        }
    }
    (runs, failures)
}

#[test]
fn ac_101_expression_oracle() {
    let files = leaf_files();
    assert_eq!(
        files.len(),
        9,
        "the O0 and O2nv builds of loops, switch and xor_decode"
    );
    let results: Vec<(usize, Vec<String>)> = std::thread::scope(|s| {
        #[expect(
            clippy::needless_collect,
            reason = "every thread starts before the first join"
        )]
        let handles: Vec<_> = files
            .iter()
            .map(|(fixture, leaves)| s.spawn(move || check_fixture(fixture, leaves)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let runs: usize = results.iter().map(|r| r.0).sum();
    let failures: Vec<&String> = results.iter().flat_map(|r| &r.1).collect();
    assert!(runs >= 5_000, "only {runs} leaf runs");
    assert!(
        failures.is_empty(),
        "{} failures:\n{:#?}",
        failures.len(),
        failures.iter().take(10).collect::<Vec<_>>()
    );
    let mut rng = Xoshiro256ss::seed_from_u64(0x0101);
    let mut compared = 0;
    for i in 0..1_000u64 {
        let prog = random_program(&mut rng);
        let image = ram_image(i);
        let want = run_l0(&prog, &image);
        let ssa = gen_l1(&prog);
        for passes in [Passes::ALL, Passes::NONE] {
            let opts = Opts {
                passes,
                ..Opts::default()
            };
            let d = decompile_gen(&prog, &ssa, &opts);
            if want.reason == StopReason::FuelExhausted {
                continue;
            }
            let got = run_ast(&prog, &d, &image);
            assert_eq!(got, want, "program {i} with {passes:?}: {d:#?}");
            compared += 1;
        }
    }
    assert!(compared > 1_000, "only {compared} random runs compared");
}
