//! Fuzz target `snapshot_load` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case decodes the input
//! bytes as a snapshot. Then the input bytes change the JSON tree of a good snapshot. Each group
//! of three bytes picks a node and puts a new value in its place. The case decodes the new tree
//! and restores it into a fresh program.
//!
//! A case gives a snapshot error or a program, and never a panic. A failed restore changes
//! nothing.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_db::migrate::ExtMap;
use ghidorah_db::{Program, snapshot};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: the changed snapshot decodes. Stage 2: it restores.
const STAGES: [&str; 3] = ["input", "decoded", "restored"];

/// The largest number of node changes of one case.
const MAX_CHANGES: usize = 6;

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/snapshot_load")
}

fn program() -> Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/crackme.gcc-O2");
    let bytes = std::fs::read(path).expect("the fixture");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("the program")
}

/// One step of a path into a JSON tree.
enum Step {
    Key(String),
    Index(usize),
}

/// Finds the path of node `n` in depth-first order. Gives `true` when it finds it.
fn nth_path(v: &Value, n: &mut usize, path: &mut Vec<Step>) -> bool {
    if *n == 0 {
        return true;
    }
    *n -= 1;
    match v {
        Value::Array(items) => {
            for (i, x) in items.iter().enumerate() {
                path.push(Step::Index(i));
                if nth_path(x, n, path) {
                    return true;
                }
                path.pop();
            }
        }
        Value::Object(o) => {
            for (k, x) in o.iter() {
                path.push(Step::Key(k.to_owned()));
                if nth_path(x, n, path) {
                    return true;
                }
                path.pop();
            }
        }
        _ => {}
    }
    false
}

fn at_mut<'a>(v: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    let Some((first, rest)) = path.split_first() else {
        return Some(v);
    };
    let next = match first {
        Step::Key(k) => v.as_object_mut()?.get_mut(k)?,
        Step::Index(i) => v.as_array_mut()?.get_mut(*i)?,
    };
    at_mut(next, rest)
}

/// Gives the new value of a change.
fn replacement(op: u8, old: &Value) -> Value {
    match op % 8 {
        0 => Value::Null,
        1 => Value::from(u64::from(op)),
        2 => Value::from("0x1084"),
        3 => Value::Array(Vec::new()),
        4 => Value::Bool(op > 128),
        5 => Value::from(u64::MAX),
        6 => match old {
            Value::Array(items) => Value::Array(items.iter().take(1).cloned().collect()),
            other => other.clone(),
        },
        _ => Value::from("not a value"),
    }
}

/// Changes the tree of `seed` with the input bytes.
fn changed(seed: &Value, input: &[u8]) -> Value {
    let mut tree = seed.clone();
    for chunk in input.chunks(3).take(MAX_CHANGES) {
        let at = chunk
            .iter()
            .take(2)
            .fold(0usize, |a, b| a * 256 + usize::from(*b));
        let mut n = at % 4096;
        let mut path = Vec::new();
        if !nth_path(&tree, &mut n, &mut path) {
            continue;
        }
        if let Some(node) = at_mut(&mut tree, &path) {
            let op = chunk.get(2).copied().unwrap_or(0);
            *node = replacement(op, node);
        }
    }
    tree
}

/// Gives the bytes of each shard file of the analysis layer of `start` by name.
fn reader(start: &Program) -> impl FnMut(&str) -> Option<Vec<u8>> + use<> {
    let texts = snapshot::shard_texts(start.analysis()).expect("the shard texts");
    move |name: &str| texts.get(name).map(|t| t.clone().into_bytes())
}

fn target(start: &Program, seed: &Value, input: &[u8]) -> Outcome {
    let mut read = reader(start);
    let _ = snapshot::decode(input, &swap(), &mut read);
    let text = ghidorah_json::write(&changed(seed, input));
    let Ok(snap) = snapshot::decode(text.as_bytes(), &ExtMap::default(), &mut read) else {
        return Outcome::reached(0);
    };
    let mut p = start.clone();
    match snap.restore(&mut p) {
        Ok(()) => Outcome::reached(2),
        Err(_) if p.state_hash() == start.state_hash() => Outcome::reached(1),
        Err(e) => Outcome::violation(1, format!("a failed restore changes the program: {e}")),
    }
}

#[test]
fn fuzz_snapshot_load() {
    let start = program();
    let text = snapshot::encode(&start, 0, None).expect("the snapshot");
    let seed = ghidorah_json::parse(&text, &snapshot::SNAPSHOT_LIMITS).expect("the snapshot JSON");
    assert!(
        snapshot::decode(text.as_bytes(), &ExtMap::default(), &mut reader(&start)).is_ok(),
        "the seed decodes"
    );
    let corpus = vec![vec![0, 0, 0], text.into_bytes()];
    let run = |input: &[u8]| target(&start, &seed, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);
    let mut config = Config::new("snapshot_load", 2_000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 16_384;
    config.stack_size = 8 * 1024 * 1024;
    let report =
        fuzz::run(&config, &corpus, run).unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2_000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(report.reached[1] > 0, "decode share: {:?}", report.reached);
}

/// Gives a map that swaps `ext:0x1` and `ext:0x2`, so a version 1 input takes the remap path.
fn swap() -> ExtMap {
    let ext = ghidorah_base::Address::external;
    ExtMap::from_pairs([(ext(1), ext(2)), (ext(2), ext(1))])
}
