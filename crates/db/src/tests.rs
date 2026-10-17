//! Shared test helpers: a fixture program with a seeded analysis layer.
//!
//! The seeded layer of `hello.gcc-O2` has 4-byte code units from `0x1080` to `0x117f`.
//! It also has three functions, two references, a string, a jump table and a symbol. Each
//! analysis fact has a why-record, so the program holds every invariant.

pub(crate) mod ops;

use std::path::PathBuf;
use std::sync::OnceLock;

use ghidorah_base::{Address, FuncId, JumpTableId, Limits, Range, StringId, TxId};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_types::{Prim, Sig, TypeId};

use crate::fact::{Origin, SessionLabel};
use crate::funcs::{Function, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::{CodeUnit, FlowKind};
use crate::program::{AnalysisSet, Program};
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::strings::{Encoding, StrInfo};
use crate::symbols::SymKind;
use crate::why::{FactKey, RuleCode, Why};

/// The first code unit of the seeded layer.
pub(crate) const CODE_FIRST: u64 = 0x1080;

/// The end of the code units of the seeded layer.
pub(crate) const CODE_END: u64 = 0x1180;

/// The entries of the seeded functions.
pub(crate) const FUNCS: [u64; 3] = [0x1080, 0x10c0, 0x1100];

/// The string of the seeded layer.
pub(crate) const STRING: u64 = 0x2004;

/// The jump of the seeded jump table.
pub(crate) const JUMP: u64 = 0x1140;

/// Loads a fixture of `fixtures/bin`.
pub(crate) fn fixture(name: &str) -> Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bin")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).unwrap();
    Program::from_binary(binary, mem, &Limits::DEFAULT).unwrap()
}

/// Gives a session label.
pub(crate) fn session(name: &str) -> SessionLabel {
    SessionLabel::new(name).unwrap()
}

/// Gives an origin.
pub(crate) fn origin(source: Source, tx: u64, name: &str) -> Origin {
    Origin::new(source, TxId(tx), session(name), false)
}

/// Gives a RAM address.
pub(crate) const fn ram(off: u64) -> Address {
    Address::ram(off)
}

/// Gives the code unit starts of the seeded layer.
pub(crate) fn units() -> Vec<u64> {
    (CODE_FIRST..CODE_END).step_by(4).collect()
}

fn why(rule: &str, premises: Vec<FactKey>) -> Why {
    Why {
        rule: RuleCode::new(rule).unwrap(),
        premises,
    }
}

fn body(first: u64, last: u64) -> RangeSet {
    let mut set = RangeSet::new();
    set.insert(Range { first, last });
    set
}

/// Builds a seeded analysis set. `variant` 1 adds a fourth function and a second string.
pub(crate) fn analysis_set(p: &Program, variant: u8) -> AnalysisSet {
    let entry = p.binary().entry_points.first().map_or(0, |e| e.addr);
    let mut t = AnalysisSet::default();
    for off in units() {
        let flow = if off == JUMP {
            FlowKind::IJmp
        } else {
            FlowKind::Seq
        };
        t.listing
            .insert_unit(
                off,
                CodeUnit::Insn {
                    len: 4,
                    flow,
                    flags: 0,
                },
            )
            .unwrap();
        t.why
            .insert(
                FactKey::CodeUnit(off),
                why("R_TEST_DISASM", vec![FactKey::Entry(entry)]),
            )
            .unwrap();
    }
    let mut funcs = vec![(0x1080, 0x10bf), (0x10c0, 0x10ff), (0x1100, 0x113f)];
    if variant == 1 {
        funcs.push((0x1150, 0x117f));
    }
    for (first, last) in funcs {
        let mut f = Function::new(ram(first), StartReason::Call, 90, Source::Analysis);
        f.body = body(first, last);
        t.funcs.insert(f).unwrap();
        t.why
            .insert(
                FactKey::Func(FuncId(ram(first))),
                why("R_TEST_CALL", vec![FactKey::CodeUnit(first)]),
            )
            .unwrap();
    }
    add_rest(&mut t, variant);
    t
}

/// Adds the references, the strings, the symbol and the jump table of a seeded set.
fn add_rest(t: &mut AnalysisSet, variant: u8) {
    let o = Origin::analysis();
    let refs = [
        (0x1084, 0x10c0, RefType::UnconditionalCall),
        (0x1088, STRING, RefType::Read),
    ];
    for (from, to, kind) in refs {
        let key = RefKey {
            from: ram(from),
            op_index: 0,
            to: ram(to),
            kind,
        };
        t.refs.add(Ref { key, primary: true }, &o).unwrap();
        t.why
            .insert(
                FactKey::Ref(key),
                why("R_TEST_REF", vec![FactKey::CodeUnit(from)]),
            )
            .unwrap();
    }
    let mut strings = vec![STRING];
    if variant == 1 {
        strings.push(0x2010);
    }
    for at in strings {
        t.strings.insert(
            at,
            StrInfo {
                encoding: Encoding::Ascii,
                len: 5,
                referenced: at == STRING,
            },
        );
        t.why
            .insert(
                FactKey::Str(StringId(ram(at))),
                why("R_TEST_STRING", vec![]),
            )
            .unwrap();
    }
    let name = if variant == 1 { "sub_one" } else { "sub_zero" };
    let key = t
        .symbols
        .add(ram(0x1100), name.to_string(), SymKind::Function, &o)
        .unwrap();
    t.why
        .insert(
            FactKey::Symbol(ram(0x1100), key),
            why("R_TEST_NAME", vec![FactKey::Func(FuncId(ram(0x1100)))]),
        )
        .unwrap();
    let table = JumpTable {
        base: Some(ram(0x2000)),
        entry_size: 4,
        count: 2,
        targets: vec![ram(0x1150), ram(0x1160)],
        method: JtMethod::A,
        resolved: true,
    };
    t.jumptables
        .set(JumpTableId(ram(JUMP)), Some(table), &o)
        .unwrap();
    t.why
        .insert(
            FactKey::JumpTable(JumpTableId(ram(JUMP))),
            why("R_TEST_JT", vec![FactKey::CodeUnit(JUMP)]),
        )
        .unwrap();
}

/// Gives the ID of the function type `int (void)` in the types of `p`. The first call adds it.
pub(crate) fn func_type(p: &mut Program) -> TypeId {
    let store = p.types_mut().store_mut();
    let int = store.prim(Prim::Int);
    store
        .func(Sig {
            ret: int,
            params: Vec::new(),
            variadic: false,
            cc: None,
            noreturn: false,
        })
        .unwrap()
}

/// Gives a clone of the seeded program: `hello.gcc-O2` with the seeded analysis layer and
/// the function type `int (void)`.
pub(crate) fn seeded() -> Program {
    static SEEDED: OnceLock<Program> = OnceLock::new();
    SEEDED
        .get_or_init(|| {
            let mut p = fixture("hello.gcc-O2");
            func_type(&mut p);
            let set = analysis_set(&p, 0);
            p.swap_analysis(Box::new(set));
            p
        })
        .clone()
}
