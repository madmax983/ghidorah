//! Shared helpers of the facts tests: analyzed fixtures and names.

use std::path::PathBuf;

use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, ImportId, Limits};
use ghidorah_db::Program;
use ghidorah_loader::{LoadOpts, load};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Loads the fixture `name` of `fixtures/bin` and runs the analysis to completion.
pub fn analyzed(name: &str) -> Program {
    let bytes = std::fs::read(root().join("fixtures/bin").join(name)).expect("the fixture");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("it loads");
    let mut p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("a program");
    let out = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete);
    p
}

/// Gives the function with the symbol `name`.
pub fn func(p: &Program, name: &str) -> FuncId {
    let addr = *p.addrs_named(name).first().expect("the symbol exists");
    FuncId(addr)
}

/// Gives the import `name`.
pub fn import(name: &str) -> ImportId {
    ImportId::elf(name).expect("an import name")
}

/// Gives the RAM address `off`.
pub const fn ram(off: u64) -> Address {
    Address::ram(off)
}
