//! The seed analyzers: entry points, symbols, PLT stubs, FDEs, call targets and flow refs.

use ghidorah_base::Address;
use ghidorah_db::{Program, RefType, StartReason};
use ghidorah_loader::EntryKind;

use crate::support::{analyzed, fid, named, truth, truth_addr};

fn reason(p: &Program, at: u64) -> Option<StartReason> {
    p.func(fid(at)).map(|f| f.func.start_reason)
}

/// Tells if a call reference from the body of `caller` goes to `to`.
fn calls(p: &Program, caller: u64, to: Address) -> bool {
    p.analysis().refs().any(|r| {
        r.value.key.kind == RefType::UnconditionalCall
            && r.value.key.to == to
            && p.owner_of(r.value.key.from) == Some(fid(caller))
    })
}

#[test]
fn seeds_of_an_unstripped_file() {
    let p = analyzed("fixtures/bin/hello.gcc-O2");
    let entry = p
        .binary()
        .entry_points
        .iter()
        .find(|e| e.kind == EntryKind::Entry)
        .expect("an entry")
        .addr;
    assert_eq!(reason(&p, entry), Some(StartReason::Entry));
    let main = named(&p, "main");
    assert_eq!(reason(&p, main), Some(StartReason::Symbol));
    let main_f = p.func(fid(main)).expect("main");
    assert_eq!(main_f.func.confidence, 100);
    assert!(main_f.func.size() > 2);
    let puts = named(&p, "puts@plt");
    let stub = p.func(fid(puts)).expect("the stub");
    assert_eq!(stub.func.start_reason, StartReason::PltStub);
    assert_eq!(stub.func.confidence, 100);
    assert!(stub.func.flags.thunk);
    let finish = named(&p, "finish");
    assert!(
        calls(&p, finish, Address::ram(puts)),
        "finish calls puts@plt"
    );
    let libc = p
        .imports()
        .values()
        .find(|i| i.id.name() == Some("__libc_start_main"))
        .expect("the import");
    assert!(
        calls(&p, entry, libc.ext),
        "_start calls the import through its slot"
    );
}

#[test]
fn seeds_of_a_stripped_file() {
    let name = "noreturn_wrappers.gcc-O2.stripped";
    let p = analyzed(&format!("fixtures/bin/{name}"));
    let t = truth(name);
    let die = truth_addr(&t, "die");
    assert_eq!(
        reason(&p, die),
        Some(StartReason::Call),
        "a call beats an FDE"
    );
    let main = truth_addr(&t, "main");
    assert_eq!(
        reason(&p, main),
        Some(StartReason::Main),
        "MainDiscovery beats an FDE"
    );
    assert_eq!(p.func(fid(main)).map(|f| f.func.confidence), Some(95));
    let check = truth_addr(&t, "check_args");
    assert_eq!(p.func(fid(check)).map(|f| f.func.confidence), Some(95));
}

#[test]
fn every_truth_function_is_found() {
    for name in [
        "two_helpers.gcc-O2",
        "loops.gcc-O0",
        "switch.clang-O2",
        "canary.gcc-O2",
        "noreturn_wrappers.clang-O2.stripped",
    ] {
        let p = analyzed(&format!("fixtures/bin/{name}"));
        let t = truth(name);
        let funcs = t
            .get("functions")
            .and_then(|f| f.as_array())
            .expect("functions");
        // A tail-call target with no size waits for the FETCH rule of WP-19.
        let tail_targets: Vec<&str> = t
            .get("tail_calls")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_array()?.get(1)?.as_str())
            .collect();
        for f in funcs {
            let at = f
                .get("addr")
                .and_then(|a| a.as_str())
                .and_then(ghidorah_base::hex::parse_u64)
                .expect("an address");
            let fname = f.get("name").and_then(|n| n.as_str()).unwrap_or_default();
            let size = f
                .get("size")
                .and_then(ghidorah_json::Value::as_u64)
                .unwrap_or_default();
            if size == 0 && tail_targets.contains(&fname) {
                continue;
            }
            assert!(
                p.func(fid(at)).is_some(),
                "{name}: {fname} at {at:#x} is a function"
            );
        }
    }
}

/// Gives the program header index of the first executable `PT_LOAD` of an ELF64 file.
fn exec_load(bytes: &[u8]) -> usize {
    let word = |at: usize, n: usize| {
        bytes[at..at + n]
            .iter()
            .rev()
            .fold(0usize, |v, b| (v << 8) | usize::from(*b))
    };
    let (phoff, phnum) = (word(32, 8), word(56, 2));
    (0..phnum)
        .find(|i| {
            let at = phoff + i * 56;
            word(at, 4) == 1 && word(at + 4, 4) & 1 == 1
        })
        .expect("an executable PT_LOAD")
}

/// The fuzz target `pipeline_elf` found an executable segment with 0x2b file bytes and a
/// zero fill of 2^45 bytes. The recursive descent decoded 100,000 instructions of zero fill,
/// and the analysis and the decompile of that function took seconds. A zero fill holds no code.
#[test]
fn regress_no_code_in_zero_fill() {
    use ghidorah_loader::{LoadOpts, Perms};
    use ghidorah_testkit::elf::{ElfBuilder, Loc, Malformed, PhdrField, Section, Symbol};

    let base = ElfBuilder::exec()
        .section(Section::code(".text", &[0x90; 8]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 8))
        .entry(Loc::section(".text", 0))
        .strip_section_headers();
    let index = exec_load(&base.build());
    let bytes = base
        .malformed(Malformed::Phdr(index, PhdrField::Memsz, 1 << 40))
        .build();
    let mut p = crate::support::program_of(&bytes, &LoadOpts::AUTO);
    crate::support::analyze(&mut p);
    let code = p
        .mem()
        .regions()
        .find(|r| r.perms.contains(Perms::EXECUTE))
        .cloned()
        .expect("the executable region");
    assert!(code.va.len() > 1 << 39, "the region has the zero fill");
    let file_end = code.va.first + code.file_size;
    let funcs = p.funcs();
    assert!(!funcs.is_empty(), "the entry function exists");
    for f in funcs {
        for r in f.func.body.ranges() {
            assert!(
                r.last < file_end,
                "{:#x}: body {r:?} in the zero fill",
                f.id().0.off
            );
        }
    }
}

/// Two binaries that differ only in the order of the function symbols at one address give one
/// state hash and one function name. The `Symbols` analyzer took the premise of the last
/// alias and pushed the extents in table order (known-06). The state hash holds the hash of
/// the file bytes. So each program takes the memory and the file hash of the first file, and
/// the binary model of its own file.
#[test]
fn regress_symbol_alias_order_is_stable() {
    use ghidorah_base::Limits;
    use ghidorah_loader::{LoadOpts, load};
    use ghidorah_testkit::elf::{ElfBuilder, Loc, Section, Symbol};

    // The entry: ret, then nop padding. The aliases: xor eax, eax; ret; then nop padding.
    let code = [
        0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90,
        0x90,
    ];
    let at = Loc::section(".text", 8);
    let aliases = [
        Symbol::func("zeta", at.clone(), 8),
        Symbol::func("alpha", at.clone(), 3),
        Symbol::func("mid", at.clone(), 5).weak(),
        Symbol::func("local_one", at, 6).local(),
    ];
    let file = |order: &[usize]| {
        let mut b = ElfBuilder::exec()
            .section(Section::code(".text", &code))
            .entry(Loc::section(".text", 0));
        for &k in order {
            b = b.symbol(aliases[k].clone());
        }
        load(&b.build(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("the bytes load")
    };
    let (base, mem) = file(&[0, 1, 2, 3]);
    let build = |order: &[usize]| {
        let (mut binary, _) = file(order);
        binary.identity.sha256 = base.identity.sha256;
        let mut p = Program::from_binary(binary, mem.clone(), &Limits::DEFAULT).expect("load");
        crate::support::analyze(&mut p);
        p
    };
    let first = build(&[0, 1, 2, 3]);
    let entry = first
        .binary()
        .symbols
        .iter()
        .find(|s| s.name.as_str() == Some("alpha"))
        .expect("the alias")
        .addr;
    let name = |p: &Program| p.name(Address::ram(entry)).map(|n| n.text);
    assert_eq!(
        name(&first).as_deref(),
        Some("alpha"),
        "global, then name order"
    );
    let hash = first.state_hash().expect("the hash");
    for order in [[1, 0, 2, 3], [2, 1, 0, 3], [1, 2, 3, 0]] {
        let other = build(&order);
        assert_eq!(name(&other), name(&first), "{order:?}");
        assert_eq!(
            other.state_hash().expect("the hash"),
            hash,
            "the order {order:?} changes the state"
        );
    }
}
