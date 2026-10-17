//! Fixture helpers and the decompile tests over fixture functions: FLAT output, canary
//! removal, tail calls and per-call-site noreturn.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ghidorah_analysis::fir::Opts as FirOpts;
use ghidorah_analysis::fir::l1::{self, L1Ir};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Limits, WarningCode};
use ghidorah_db::Program;
use ghidorah_decomp::shape::NodeKind;
use ghidorah_decomp::{
    Callee, Decomp, ElideReason, Exit, FlatReason, Mode, Opts, ProgramEnv, Stmt, Tree,
};
use ghidorah_ir::{Image, Switches};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, Perms, load};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).expect("the JSON parses")
}

/// Loads and analyzes the fixture `name` under `fixtures/bin`.
fn analyzed(name: &str) -> Program {
    let bytes = std::fs::read(root().join("fixtures/bin").join(name)).expect("the fixture bytes");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the bytes load");
    let mut p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary");
    let out = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
    p
}

/// Gives the analyzed program of a fixture. The test binary builds each one once.
pub fn program(name: &str) -> &'static Program {
    type Cache = std::sync::Mutex<BTreeMap<String, &'static Program>>;
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut map = cache.lock().expect("the cache lock");
    if let Some(p) = map.get(name) {
        return p;
    }
    let p: &'static Program = Box::leak(Box::new(analyzed(name)));
    map.insert(name.to_owned(), p);
    p
}

/// Gives the entry of the function named `name`.
pub fn entry_of(p: &Program, name: &str) -> u64 {
    p.addrs_named(name)
        .first()
        .map_or_else(|| panic!("the program names {name}"), |a| a.off)
}

/// Gives the function ID of an entry.
pub const fn fid(entry: u64) -> FuncId {
    FuncId(Address::ram(entry))
}

/// Builds the L1 form of the function at `entry`.
pub fn l1_of(p: &Program, entry: u64) -> L1Ir {
    l1::build(
        p,
        fid(entry),
        &FirOpts::DEFAULT,
        &Switches::all(),
        &mut Fuel::unlimited(),
    )
    .unwrap_or_else(|e| panic!("the L1 form of {entry:#x}: {e}"))
}

/// Decompiles the function at `entry` with `opts`.
pub fn decompile(p: &Program, entry: u64, opts: &Opts) -> Decomp {
    ghidorah_decomp::decompile(p, fid(entry), opts, &mut Fuel::unlimited())
        .unwrap_or_else(|e| panic!("the decompile of {entry:#x}: {e}"))
}

/// The lowest address of the test stack.
pub const STACK_LO: u64 = 0x7fff_0000;

/// The size of the test stack.
pub const STACK_SIZE: u64 = 0x1_0000;

/// The memory of a program plus a writable stack of zero bytes.
pub struct ProgramImage<'a>(pub &'a Program);

impl Image for ProgramImage<'_> {
    fn read(&self, addr: u64) -> Option<u8> {
        if (STACK_LO..STACK_LO + STACK_SIZE).contains(&addr) {
            return Some(0);
        }
        self.0
            .mem()
            .read(addr, 1, &Limits::DEFAULT)
            .ok()
            .and_then(|b| b.first().copied())
    }

    fn writable(&self, addr: u64) -> bool {
        (STACK_LO..STACK_LO + STACK_SIZE).contains(&addr)
            || self
                .0
                .mem()
                .region_at(addr)
                .is_some_and(|r| r.perms.contains(Perms::WRITE))
    }
}

/// Gives the block nodes of a shape.
fn block_nodes(d: &Decomp) -> Vec<ghidorah_ir::Node> {
    d.view
        .shape
        .ids()
        .filter(|n| {
            matches!(
                d.view.shape.node(*n).map(|s| s.kind),
                Some(NodeKind::Block(_))
            )
        })
        .collect()
}

#[test]
fn ac_100_flat_fallback() {
    let p = program("switch.gcc-O2");
    let entry = entry_of(p, "apply_op");
    let full = decompile(p, entry, &Opts::default());
    let blocks = block_nodes(&full);
    assert!(blocks.len() > 3, "apply_op has a switch: {}", blocks.len());
    let opts = Opts {
        max_nodes: blocks.len() - 1,
        ..Opts::default()
    };
    let d = decompile(p, entry, &opts);
    assert_eq!(d.mode, Mode::Flat(FlatReason::MaxNodes));
    assert_eq!(d.mode.fallback_mode(), "flat");
    let mut seen = d.tree.nodes();
    seen.sort_unstable();
    let mut all: Vec<_> = d.view.shape.ids().collect();
    all.sort_unstable();
    assert_eq!(seen, all, "FLAT output holds each node once");
    assert!(
        d.warnings
            .iter()
            .any(|w| w.code == WarningCode::BudgetFlat && w.at == entry),
        "{:?}",
        d.warnings
    );
    assert_eq!(
        full.mode,
        Mode::Structured,
        "the default budget structures it"
    );
}

/// Tells if a statement calls a function with this name.
fn calls_named(p: &Program, s: &Stmt, name: &str) -> bool {
    let env = ProgramEnv(p);
    match s {
        Stmt::Call(c) => match c.callee {
            Callee::Direct(t) => {
                ghidorah_decomp::Env::callee_name(&env, t).is_some_and(|n| n.contains(name))
            }
            _ => false,
        },
        _ => false,
    }
}

#[test]
fn canary_check_elided() {
    let p = program("canary.gcc-O2");
    for name in ["copy_name", "checksum_line"] {
        let entry = entry_of(p, name);
        let d = decompile(p, entry, &Opts::default());
        let placed = d.tree.nodes();
        for n in placed {
            let stmts = &d.view.nodes[n.index()].stmts;
            assert!(
                !stmts.iter().any(|s| calls_named(p, s, "__stack_chk_fail")),
                "{name}: the failure call is in the output"
            );
        }
        assert!(
            d.elided.iter().any(|e| e.reason == ElideReason::Canary),
            "{name}: {:?}",
            d.elided
        );
        let kept = decompile(
            p,
            entry,
            &Opts {
                passes: ghidorah_decomp::Passes {
                    canary: false,
                    ..ghidorah_decomp::Passes::ALL
                },
                ..Opts::default()
            },
        );
        let has_fail = kept.tree.nodes().iter().any(|n| {
            kept.view.nodes[n.index()]
                .stmts
                .iter()
                .any(|s| calls_named(p, s, "__stack_chk_fail"))
        });
        assert!(has_fail, "{name}: the canary switch keeps the check");
    }
}

#[test]
fn tail_call_returns_callee() {
    let p = program("hello.gcc-O2");
    let entry = entry_of(p, "run");
    let finish = entry_of(p, "finish");
    let ir = l1_of(p, entry);
    assert_eq!(ir.tail_calls.len(), 1, "run ends in a tail jump");
    let d = decompile(p, entry, &Opts::default());
    let tail: Vec<_> = d
        .view
        .nodes
        .iter()
        .flat_map(|n| &n.stmts)
        .filter_map(|s| match s {
            Stmt::Call(c) if c.tail => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(tail.len(), 1, "one tail call");
    assert_eq!(tail[0].callee, Callee::Direct(finish));
    assert!(
        tail[0]
            .args
            .iter()
            .any(|(l, _)| *l == ghidorah_ir::Loc::RDI),
        "the tail call reads its argument"
    );
}

#[test]
fn noreturn_call_sites() {
    let p = program("noreturn_wrappers.gcc-O2");
    let entry = entry_of(p, "check_args");
    let d = decompile(p, entry, &Opts::default());
    let mut ends = 0;
    for (i, n) in d.view.nodes.iter().enumerate() {
        let Some(Stmt::Call(c)) = n.stmts.last() else {
            continue;
        };
        if c.noreturn {
            ends += 1;
            assert_eq!(d.view.shape.nodes[i].exit, Exit::Stop);
        }
    }
    assert!(ends >= 2, "die and die_code do not return: {ends}");
    assert!(
        matches!(d.tree, Tree::Seq(_) | Tree::If { .. }),
        "{:?}",
        d.tree
    );
}
