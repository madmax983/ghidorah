//! Each function of the unstripped T1 and T2 fixtures decompiles. The tree of each function gives
//! the block traces of its shape under 4 branch oracles. The text of each function defines each
//! label once, and each `goto` names a label of the text.

use std::collections::BTreeSet;

use ghidorah_base::Fuel;
use ghidorah_decomp::interp_ast::{Seeded, cfg_trace, tree_trace};
use ghidorah_decomp::{Line, LineKind, Mode, Opts, ProgramEnv, print};
use ghidorah_ir::NoNames;
use ghidorah_json::Value;

use crate::fixtures::{entry_of, fid, json, program, root};

/// The T1 and T2 fixtures with the variant `none`, in manifest order.
fn plain() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    json(&text)
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures")
        .iter()
        .filter(|f| {
            matches!(f.get("tier").and_then(Value::as_str), Some("T1" | "T2"))
                && f.get("variant").and_then(Value::as_str) == Some("none")
        })
        .filter_map(|f| f.get("path").and_then(Value::as_str))
        .map(|p| p.trim_start_matches("fixtures/bin/").to_owned())
        .collect()
}

/// Decompiles each function of one fixture. Gives the counts of functions and of FLAT
/// outputs, and the failures.
fn check(name: &str) -> (usize, usize, Vec<String>) {
    let p = program(name);
    let (mut count, mut flat) = (0, 0);
    let mut failures = Vec::new();
    for view in p.funcs() {
        if view.func.flags.thunk {
            continue;
        }
        let entry = view.id().0.off;
        let d = match ghidorah_decomp::decompile(
            p,
            fid(entry),
            &Opts::default(),
            &mut Fuel::new(50_000_000),
        ) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{name} {entry:#x}: {e}"));
                continue;
            }
        };
        count += 1;
        if matches!(d.mode, Mode::Flat(_)) {
            flat += 1;
        }
        for seed in 0..4u64 {
            let oracle = Seeded(seed.wrapping_mul(0x9e37_79b9).wrapping_add(entry));
            let want = cfg_trace(&d.view.shape, &oracle, 400);
            let got = tree_trace(&d.tree, &d.view.shape, &oracle, 400);
            if got != want {
                failures.push(format!("{name} {entry:#x}: trace mismatch for seed {seed}"));
                break;
            }
        }
        let out = ghidorah_decomp::finish(
            d,
            &ProgramEnv(p),
            &NoNames,
            "f",
            &print::body_units(p, fid(entry)),
        );
        failures.extend(
            label_faults(&out.lines)
                .into_iter()
                .map(|fault| format!("{name} {entry:#x}: {fault}")),
        );
    }
    (count, flat, failures)
}

/// Gives the label faults of one function: a label that the text defines twice, or a `goto`
/// to an undefined label.
fn label_faults(lines: &[Line]) -> Vec<String> {
    let mut defined = BTreeSet::new();
    let mut faults = Vec::new();
    for line in lines.iter().filter(|l| l.kind == LineKind::Label) {
        let text = line.text.trim();
        let name = text.strip_suffix(':').unwrap_or(text);
        if !defined.insert(name.to_owned()) {
            faults.push(format!("the label {name} is defined twice"));
        }
    }
    for line in lines.iter().filter(|l| l.kind == LineKind::Goto) {
        let text = line.text.trim();
        let name = text
            .strip_prefix("goto ")
            .and_then(|t| t.split(';').next())
            .unwrap_or(text);
        if !defined.contains(name) {
            faults.push(format!("`{text}` names no label of the text"));
        }
    }
    faults
}

/// The gcc -O2 `parse_number` of `cold_split` copies a value on the edge to the block at
/// 0x1301. The edge node had the address of its target block, so the text defined `L_1301`
/// twice, and a `goto L_1301` had two targets (r2-engine-04).
#[test]
fn regress_edge_label_unique() {
    let p = program("cold_split.gcc-O2");
    let entry = entry_of(p, "parse_number");
    let out = ghidorah_decomp::render(
        p,
        fid(entry),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .expect("the decompile");
    let text = out.text();
    let faults = label_faults(&out.lines);
    assert!(faults.is_empty(), "{faults:?}\n{text}");
    assert_eq!(text.matches("L_1301:").count(), 1, "{text}");
    let edge = out
        .lines
        .iter()
        .find(|l| l.kind == LineKind::Label && l.text.starts_with("L_1301_"))
        .map_or_else(
            || panic!("no label of the edge copies:\n{text}"),
            |l| l.text.trim_end_matches(':').to_owned(),
        );
    assert_eq!(text.matches(&format!("goto {edge};")).count(), 1, "{text}");
    assert!(text.contains("goto L_1301;"), "{text}");
}

#[test]
fn every_t1_and_t2_function_decompiles() {
    let names = plain();
    assert!(names.len() > 40, "only {} fixtures", names.len());
    let chunks: Vec<Vec<String>> = (0..4)
        .map(|k| names.iter().skip(k).step_by(4).cloned().collect())
        .collect();
    let results: Vec<(usize, usize, Vec<String>)> = std::thread::scope(|s| {
        #[expect(
            clippy::needless_collect,
            reason = "every thread starts before the first join"
        )]
        let handles: Vec<_> = chunks
            .iter()
            .map(|chunk| {
                s.spawn(move || {
                    let mut total = (0, 0, Vec::new());
                    for n in chunk {
                        let (c, f, e) = check(n);
                        total.0 += c;
                        total.1 += f;
                        total.2.extend(e);
                    }
                    total
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let count: usize = results.iter().map(|r| r.0).sum();
    let flat: usize = results.iter().map(|r| r.1).sum();
    let failures: Vec<&String> = results.iter().flat_map(|r| &r.2).collect();
    assert!(count > 1_500, "only {count} functions");
    assert!(
        failures.is_empty(),
        "{} failures:\n{:#?}",
        failures.len(),
        failures.iter().take(10).collect::<Vec<_>>()
    );
    assert!(flat * 20 <= count, "{flat} of {count} functions are FLAT");
}
