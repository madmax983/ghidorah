//! `References`: operand, relocation and table references (AC-085a).

use std::collections::BTreeMap;

use ghidorah_analysis::analyzers::refs::{self, MIN_IMM, SLOT_SIZE};
use ghidorah_analysis::{Rule, Until};
use ghidorah_base::{Address, Fuel, ImportId, SpaceId};
use ghidorah_db::{Program, RefKey, RefType};
use ghidorah_loader::{RelocForm, RelocSource, RelocType, SymTable};
use ghidorah_testkit::elf::consts::EM_AARCH64;
use ghidorah_testkit::elf::{
    ElfBuilder, FixupKind, ImportKind, Layout, Loc, Reloc, RelocTable, Section, Symbol,
};

use crate::support::{all_t1_full, analyze_full, built, program, t1_full};

/// `R_X86_64_RELATIVE`.
const RELATIVE: u32 = 8;
/// `R_X86_64_64`.
const ABS64: u32 = 1;

/// Gives the data references of the analysis layer: the keys with a type of 100 or above.
fn data_refs(p: &Program) -> Vec<RefKey> {
    p.analysis()
        .refs()
        .iter()
        .map(|r| r.value.key)
        .filter(|k| !k.kind.is_flow())
        .collect()
}

/// Gives the address of the placed section `name`.
fn sec(layout: &Layout, name: &str) -> u64 {
    layout.section(name).expect("the section").addr
}

/// Gives the EXTERNAL address of the ELF import `name`.
fn ext(p: &Program, name: &str) -> Address {
    let id = ImportId::elf(name).expect("an import ID");
    p.imports().get(&id).expect("the import").ext
}

/// The code of the operand test: one instruction of each access, two immediates and `ret`.
fn operand_code() -> Section {
    let bytes = [
        0x8b, 0x05, 0, 0, 0, 0, // mov eax, [rip+.data]
        0x89, 0x05, 0, 0, 0, 0, // mov [rip+.data+8], eax
        0x01, 0x05, 0, 0, 0, 0, // add [rip+.data+16], eax
        0x48, 0x8d, 0x05, 0, 0, 0, 0, // lea rax, [rip+.rodata]
        0xbf, 0, 0, 0, 0, // mov edi, .rodata+4
        0xbf, 0x10, 0, 0, 0,    // mov edi, 0x10
        0xc3, // ret
    ];
    Section::code(".text", &bytes)
        .fixup(2, FixupKind::Rel32, Loc::section(".data", 0))
        .fixup(8, FixupKind::Rel32, Loc::section(".data", 8))
        .fixup(14, FixupKind::Rel32, Loc::section(".data", 16))
        .fixup(21, FixupKind::Rel32, Loc::section(".rodata", 0))
        .fixup(26, FixupKind::Abs32, Loc::section(".rodata", 4))
}

/// Builds the operand test file from `builder` and analyzes it.
fn operand_file(builder: ElfBuilder) -> (Program, Layout) {
    let b = builder
        .section(operand_code())
        .section(Section::rodata(".rodata", b"abcdefgh\0"))
        .section(Section::data(".data", &[0; 24]));
    let (mut p, layout) = built(&b);
    let _ = analyze_full(&mut p);
    (p, layout)
}

#[test]
fn specs_and_rows() {
    use ghidorah_analysis::analyzers::strings;
    use ghidorah_analysis::{Scheduler, Trigger, Until};
    assert_eq!((refs::SPEC.name, refs::SPEC.priority), ("References", 600));
    assert_eq!(
        (strings::SPEC.name, strings::SPEC.priority),
        ("Strings", 650)
    );
    for spec in [&refs::SPEC, &strings::SPEC] {
        assert!(
            !spec.listens(Trigger::Signatures),
            "band {} is below 800",
            spec.priority
        );
        assert!(spec.listens(Trigger::Bytes));
    }
    assert!(refs::SPEC.listens(Trigger::Instructions));
    assert_eq!(refs::SPEC.option("min_imm"), Some(MIN_IMM));
    let list = crate::support::full_list();
    let names: Vec<&str> = list.iter().map(|s| s.name).collect();
    assert_eq!(names.iter().filter(|n| **n == "References").count(), 1);
    assert_eq!(names.iter().filter(|n| **n == "Strings").count(), 1);
    let mut p = crate::support::program("fixtures/bin/hello.gcc-O2");
    let mut sched = Scheduler::with_analyzers(list.clone());
    assert_eq!(sched.analyzers().len(), list.len());
    let out = sched
        .run(&mut p, Until::Full, &mut ghidorah_base::Fuel::unlimited())
        .expect("a run");
    assert!(!out.resume);
    let rows = sched.rows();
    let ran = |name: &str| rows.iter().find(|r| r.name == name).map(|r| r.runs);
    assert!(ran("References") >= Some(1), "{rows:?}");
    assert!(ran("Strings") >= Some(1), "{rows:?}");
    let mut triage = crate::support::program("fixtures/bin/hello.gcc-O2");
    let mut sched = Scheduler::with_analyzers(list);
    let _ = sched
        .run(
            &mut triage,
            Until::Triage,
            &mut ghidorah_base::Fuel::unlimited(),
        )
        .expect("a triage run");
    assert!(
        !triage.analysis().strings().is_empty(),
        "bands 600 and 650 are triage bands"
    );
}

#[test]
fn ac_085a_xref_shape() {
    let mut kinds = BTreeMap::new();
    for (path, p) in all_t1_full() {
        let found = p.check_invariants();
        assert!(found.is_empty(), "{path}: {found:?}");
        for layer in [p.base(), p.analysis()] {
            for r in layer.refs().iter() {
                let k = r.value.key;
                assert!(
                    k.from.is_ram()
                        && (p.code_unit(k.from.off).is_some() || p.data_def(k.from.off).is_some()),
                    "{path}: {k:?} starts at an instruction or a data slot"
                );
                let mapped = k.to.is_ram() && p.mem().region_at(k.to.off).is_some();
                assert!(
                    mapped || k.to.space == SpaceId::EXTERNAL,
                    "{path}: {k:?} ends in mapped memory or in the EXTERNAL space"
                );
                *kinds.entry(k.kind).or_insert(0u64) += 1;
            }
        }
        assert!(!data_refs(p).is_empty(), "{path} has data references");
    }
    for kind in [RefType::Read, RefType::Write, RefType::Data] {
        assert!(
            kinds.get(&kind).copied().unwrap_or(0) > 0,
            "the fixtures hold {kind}"
        );
    }
}

#[test]
fn operand_ref_kinds() {
    let (p, layout) = operand_file(ElfBuilder::exec());
    let text = sec(&layout, ".text");
    let data = sec(&layout, ".data");
    let ro = sec(&layout, ".rodata");
    assert!(ro + 4 >= MIN_IMM, "the immediate is an address");
    let got: Vec<(u64, i8, u64, RefType)> = data_refs(&p)
        .iter()
        .map(|k| (k.from.off - text, k.op_index, k.to.off, k.kind))
        .collect();
    assert_eq!(
        got,
        [
            (0x00, 1, data, RefType::Read),
            (0x06, 0, data + 8, RefType::Write),
            (0x0c, 0, data + 16, RefType::ReadWrite),
            (0x12, 1, ro, RefType::Data),
            (0x19, 1, ro + 4, RefType::Data),
        ]
    );
    for k in data_refs(&p) {
        let why = p.why(&ghidorah_db::FactKey::Ref(k)).expect("a why-record");
        assert_eq!(why.rule.as_str(), Rule::OperandRef.code());
        assert_eq!(why.premises, [ghidorah_db::FactKey::CodeUnit(k.from.off)]);
    }
    // A position-independent file has no immediate references, even at a high base.
    let (pie, layout) = operand_file(ElfBuilder::dyn_object().base(0x40_0000));
    let text = sec(&layout, ".text");
    let froms: Vec<u64> = data_refs(&pie).iter().map(|k| k.from.off - text).collect();
    assert_eq!(froms, [0x00, 0x06, 0x0c, 0x12]);
}

#[test]
fn reloc_slots_of_a_pie() {
    let p = t1_full("hello.gcc-O2");
    let slots: BTreeMap<u64, Address> = refs::slots(p)
        .into_iter()
        .map(|(at, s)| (at, s.to))
        .collect();
    let expect = BTreeMap::from([
        (0x3db0, Address::ram(0x1170)),
        (0x3db8, Address::ram(0x1130)),
        (0x3fd8, ext(p, "__libc_start_main")),
        (0x3fe0, ext(p, "_ITM_deregisterTMCloneTable")),
        (0x3fe8, ext(p, "__gmon_start__")),
        (0x3ff0, ext(p, "_ITM_registerTMCloneTable")),
        (0x3ff8, ext(p, "__cxa_finalize")),
        (0x4008, Address::ram(0x4008)),
    ]);
    assert_eq!(slots, expect, "JUMP_SLOT places are not pointer slots");
    for (at, to) in &expect {
        let def = p.data_def(*at).expect("a data definition at the slot");
        assert_eq!(def.value.len, SLOT_SIZE);
        let key = RefKey {
            from: Address::ram(*at),
            op_index: 0,
            to: *to,
            kind: RefType::Data,
        };
        assert!(p.analysis().refs().get(&key).is_some(), "{key:?}");
        let why = p
            .why(&ghidorah_db::FactKey::Data(*at))
            .expect("a why-record");
        assert_eq!(why.rule.as_str(), Rule::RelocPtr.code());
        assert_eq!(why.premises, [ghidorah_db::FactKey::Reloc(*at)]);
        let why = p
            .why(&ghidorah_db::FactKey::Ref(key))
            .expect("a why-record");
        assert_eq!(why.premises, [ghidorah_db::FactKey::Data(*at)]);
    }
}

/// Builds a file with pointers in `.data` and analyzes it.
fn table_file(builder: ElfBuilder) -> (Program, Layout) {
    let data = Section::data(".data", &[0; 40])
        .fixup(0, FixupKind::Abs64, Loc::section(".text", 0))
        .fixup(8, FixupKind::Abs64, Loc::section(".rodata", 0))
        .fixup(24, FixupKind::Abs64, Loc::section(".text", 1));
    let b = builder
        .section(Section::code(".text", &[0xc3, 0xc3]))
        .section(Section::rodata(".rodata", b"zzzzzzzz"))
        .section(data)
        .init_array(Loc::section(".text", 1));
    let (mut p, layout) = built(&b);
    let _ = analyze_full(&mut p);
    (p, layout)
}

#[test]
fn address_tables() {
    let (p, layout) = table_file(ElfBuilder::exec());
    let data = sec(&layout, ".data");
    let init = sec(&layout, ".init_array");
    let slots = refs::slots(&p);
    let got: Vec<(u64, u64, &str)> = slots
        .iter()
        .map(|(at, s)| (*at, s.to.off, s.why.rule.code()))
        .collect();
    let text = sec(&layout, ".text");
    let ro = sec(&layout, ".rodata");
    let table = Rule::AddrTable.code();
    let mut expect = vec![
        (data, text, table),
        (data + 8, ro, table),
        (init, text + 1, table),
    ];
    expect.sort_unstable();
    assert_eq!(got, expect, "a lone pointer is not a table");
    for (at, s) in &slots {
        assert!(
            s.why.premises.is_empty(),
            "{at:#x}: the bytes are the reason"
        );
        assert!(p.data_def(*at).is_some());
    }
    // A position-independent file has no address tables. An array is still an array.
    let (pie, layout) = table_file(ElfBuilder::dyn_object());
    let init = sec(&layout, ".init_array");
    let keys: Vec<u64> = refs::slots(&pie).into_keys().collect();
    assert_eq!(keys, [init]);
}

/// Builds the hostile relocation file. `addend` is the address of `.text` from a first layout.
fn reloc_file(text: u64) -> (Program, Layout) {
    let rela = |at: Loc, kind: u32, sym: Option<&str>, addend: i64| Reloc {
        table: RelocTable::Rela,
        at,
        kind,
        sym: sym.map(str::to_owned),
        addend,
    };
    let to_text = i64::try_from(text).expect("a small address");
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3, 0xc3]))
        .section(Section::data(".data", &[0; 32]))
        .export(Symbol::object("thing", Loc::section(".data", 24), 8))
        .import("puts", ImportKind::Got)
        .reloc(rela(Loc::section(".data", 0), RELATIVE, None, to_text))
        .reloc(rela(Loc::section(".data", 4), RELATIVE, None, to_text + 1))
        .reloc(rela(Loc::section(".data", 8), RELATIVE, None, 0x7fff_0000))
        .reloc(rela(Loc::section(".text", 0), RELATIVE, None, to_text))
        .reloc(rela(Loc::Abs(0xdead_0000), RELATIVE, None, to_text))
        .reloc(rela(Loc::section(".data", 16), ABS64, Some("thing"), 2));
    built(&b)
}

#[test]
fn reloc_slots_never_overlap() {
    let (_, first) = reloc_file(0);
    let text = sec(&first, ".text");
    let (mut p, layout) = reloc_file(text);
    assert_eq!(
        sec(&layout, ".text"),
        text,
        "the addend does not move the layout"
    );
    let _ = analyze_full(&mut p);
    let data = sec(&layout, ".data");
    let got = *layout.got.get("puts").expect("the GOT slot of puts");
    let slots: BTreeMap<u64, Address> = refs::slots(&p)
        .into_iter()
        .map(|(at, s)| (at, s.to))
        .collect();
    let expect = BTreeMap::from([
        (data, Address::ram(text)),
        (data + 16, Address::ram(data + 24 + 2)),
        (got, ext(&p, "puts")),
    ]);
    assert_eq!(
        slots, expect,
        "an overlap, an unmapped target, a code slot and an unmapped slot give no slot"
    );
    let found = p.check_invariants();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn relr_refs_exact() {
    let data = Section::data(".data.rel.ro", &[0; 24])
        .fixup(0, FixupKind::Abs64, Loc::section(".text", 0))
        .fixup(8, FixupKind::Abs64, Loc::section(".rodata", 2))
        .fixup(16, FixupKind::Abs64, Loc::section(".rodata", 4));
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::rodata(".rodata", b"no text\0"))
        .section(data)
        .relr(Loc::section(".data.rel.ro", 0))
        .relr(Loc::section(".data.rel.ro", 8));
    let (mut p, layout) = built(&b);
    let _ = analyze_full(&mut p);
    let slot = sec(&layout, ".data.rel.ro");
    let text = sec(&layout, ".text");
    let ro = sec(&layout, ".rodata");
    let expect = vec![
        RefKey {
            from: Address::ram(slot),
            op_index: 0,
            to: Address::ram(text),
            kind: RefType::Data,
        },
        RefKey {
            from: Address::ram(slot + 8),
            op_index: 0,
            to: Address::ram(ro + 2),
            kind: RefType::Data,
        },
    ];
    assert_eq!(
        data_refs(&p),
        expect,
        "each RELR place gives one exact reference"
    );
    for at in [slot, slot + 8] {
        let why = p
            .why(&ghidorah_db::FactKey::Data(at))
            .expect("a why-record");
        assert_eq!(why.rule.as_str(), Rule::RelocPtr.code());
    }
    assert!(
        p.data_def(slot + 16).is_none(),
        "a place without RELR is no slot"
    );
}

#[test]
fn reloc_targets_match_the_slots() {
    let p = t1_full("hello.gcc-O2");
    let slots = refs::slots(p);
    let mut seen = 0;
    for r in &p.binary().relocs {
        let to = refs::reloc_target(p, r);
        match slots.get(&r.offset) {
            Some(s) => {
                assert_eq!(to, Some(s.to), "{r:?}");
                seen += 1;
            }
            None => assert_eq!(to, None, "a JUMP_SLOT place is no pointer: {r:?}"),
        }
    }
    assert_eq!(seen, slots.len());
}

#[test]
fn other_machines_have_no_code_refs() {
    let data =
        Section::data(".data", &[0; 8]).fixup(0, FixupKind::Abs64, Loc::section(".rodata", 0));
    let b = ElfBuilder::exec()
        .machine(EM_AARCH64)
        .section(Section::code(".text", &[0x1f, 0x20, 0x03, 0xd5]))
        .section(Section::rodata(".rodata", b"survey text\0"))
        .section(data);
    let (mut p, layout) = built(&b);
    let _ = analyze_full(&mut p);
    assert!(
        data_refs(&p).is_empty(),
        "no x86-64 code and no x86-64 relocations"
    );
    assert!(refs::slots(&p).is_empty());
    let ro = sec(&layout, ".rodata");
    let info = p
        .string(ro)
        .expect("the scan reads the data of any machine");
    assert!(!info.referenced);
    let r = ghidorah_loader::Reloc {
        offset: ro,
        kind: RelocType(RELATIVE),
        sym: None,
        sym_table: SymTable::Dynsym,
        addend: 0,
        form: RelocForm::Rela,
        source: RelocSource::DynRela,
    };
    assert_eq!(refs::reloc_target(&p, &r), None);
}

#[test]
fn restart_keeps_the_references() {
    let mut p = program("fixtures/bin/socket_client.gcc-O2");
    let (mut sched, _) = analyze_full(&mut p);
    let before = p.state_hash().expect("a hash");
    let rev = p.rev();
    sched.restart(refs::SPEC.priority);
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a shadow run");
    assert!(out.commit.is_none_or(|c| c.noop), "the same facts");
    assert_eq!(p.state_hash().expect("a hash"), before);
    assert_eq!(p.rev(), rev);
}
