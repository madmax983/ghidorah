//! Seeds 11 (`DataPtr`) and 12 (`AddrTaken`) of design Section 7.3 (WP-19b, AC-257).
//!
//! The small files come from `ElfBuilder`. Their scheduler runs the shipped list with the two
//! seed analyzers. The fixture tests run the shipped list.

use std::collections::BTreeSet;

use ghidorah_analysis::analyzers::{addrtaken, dataptr};
use ghidorah_analysis::{AnalyzerSpec, Rule, RunState, Scheduler, Trigger, Until};
use ghidorah_base::{Address, Fuel, JumpTableId};
use ghidorah_db::{FactKey, Program, StartReason};
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{ElfBuilder, FixupKind, Layout, Loc, Reloc, RelocTable, Section};
use ghidorah_x86::{Opts, decode};

use crate::support::{cached, fid, fixtures, program_of, truth, truth_funcs};

/// `push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret`: five instructions.
const FUNC: [u8; 8] = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];

/// `R_X86_64_RELATIVE`.
const RELATIVE: u32 = 8;

/// Gives the shipped analyzer list with the two seed analyzers.
fn seeded() -> Vec<&'static AnalyzerSpec> {
    let mut list = ghidorah_analysis::ANALYZERS.to_vec();
    for spec in [&dataptr::SPEC, &addrtaken::SPEC] {
        if !list.iter().any(|s| s.id == spec.id) {
            list.push(spec);
        }
    }
    list
}

/// Builds the file of `b`, loads it and runs the seeded list to completion.
fn analyzed(b: &ElfBuilder) -> (Program, Layout) {
    let (bytes, layout) = b.build_with_layout();
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    let mut sched = Scheduler::with_analyzers(seeded());
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete);
    (p, layout)
}

/// Gives code bytes with each part at its offset and `int3` in the free bytes.
fn code(len: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
    let mut out = vec![0xcc; len];
    for (at, bytes) in parts {
        out[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    out
}

/// Gives the address of the placed section `name`.
fn sec(layout: &Layout, name: &str) -> u64 {
    layout.section(name).expect("the section").addr
}

/// Gives the start reason and the confidence of the function at `at`.
fn reason(p: &Program, at: u64) -> Option<(StartReason, u8)> {
    p.func(fid(at))
        .map(|f| (f.func.start_reason, f.func.confidence))
}

/// Gives the entries of the functions of `p`.
fn entries(p: &Program) -> Vec<u64> {
    p.funcs().iter().map(|v| v.id().0.off).collect()
}

/// Gives a PIE with an entry `ret` and FUNC at `.text+0x10`, `+0x20` and `+0x30`. The
/// `.data.rel.ro` section has `slots` slots. A RELR relocation puts the code offset
/// `targets[i]` in slot `i`. `rela` adds an `R_X86_64_RELATIVE` RELA relocation at a section
/// offset with its addend.
fn pie(targets: &[u64], slots: u64, rela: Option<(u64, i64)>) -> ElfBuilder {
    let text = code(
        0x40,
        &[(0, &[0xc3]), (0x10, &FUNC), (0x20, &FUNC), (0x30, &FUNC)],
    );
    let len = usize::try_from(slots * 8).expect("a small section");
    let mut data = Section::data(".data.rel.ro", &vec![0; len]);
    let mut b = ElfBuilder::dyn_object().section(Section::code(".text", &text));
    for (i, t) in (0u64..).zip(targets) {
        data = data.fixup(i * 8, FixupKind::Abs64, Loc::section(".text", *t));
        b = b.relr(Loc::section(".data.rel.ro", i * 8));
    }
    if let Some((at, addend)) = rela {
        b = b.reloc(Reloc {
            table: RelocTable::Rela,
            at: Loc::section(".data.rel.ro", at),
            kind: RELATIVE,
            sym: None,
            addend,
        });
    }
    b.section(data)
}

/// Gives the address of `.text` in the layout of `b`.
fn text_of(b: &ElfBuilder) -> u64 {
    sec(&b.build_with_layout().1, ".text")
}

/// Gives a small address as an addend.
fn addend(at: u64) -> i64 {
    i64::try_from(at).expect("a small address")
}

#[test]
fn seed_specs() {
    for (spec, name, band) in [
        (&dataptr::SPEC, "DataPtrSeeds", 450),
        (&addrtaken::SPEC, "AddrTakenSeeds", 460),
    ] {
        assert_eq!((spec.name, spec.priority), (name, band));
        for t in [Trigger::Bytes, Trigger::Instructions, Trigger::Functions] {
            assert!(spec.listens(t), "{name} listens to {}", t.name());
        }
        assert!(
            !spec.listens(Trigger::Signatures),
            "band {band} is below 800"
        );
    }
    assert_eq!(dataptr::SPEC.option("min_insns"), Some(dataptr::MIN_INSNS));
    assert_eq!(dataptr::SPEC.option("min_run"), Some(dataptr::MIN_RUN));
    assert_eq!((dataptr::CONFIDENCE, addrtaken::CONFIDENCE), (70, 75));
    assert_eq!(Rule::DataCodePtr.code(), "R_DATA_CODE_PTR");
    assert_eq!(Rule::AddrTaken.code(), "R_ADDR_TAKEN");
    assert_eq!(StartReason::DataPtr.name(), "data_ptr");
    assert_eq!(StartReason::AddrTaken.name(), "addr_taken");
}

#[test]
fn dataptr_seeds_relocated_table() {
    // A RELA relocation names its target in the addend. The layout does not depend on it.
    let text = text_of(&pie(&[0x10, 0x20], 3, Some((16, 0))));
    let b = pie(&[0x10, 0x20], 3, Some((16, addend(text + 0x30))));
    let (p, layout) = analyzed(&b);
    assert_eq!(
        sec(&layout, ".text"),
        text,
        "the addend does not move the layout"
    );
    let slot = sec(&layout, ".data.rel.ro");
    let found = dataptr::pointers(&p);
    let want: Vec<(u64, u64, bool)> = vec![
        (slot, text + 0x10, true),
        (slot + 8, text + 0x20, true),
        (slot + 16, text + 0x30, true),
    ];
    let got: Vec<(u64, u64, bool)> = found
        .iter()
        .map(|x| (x.slot, x.target, x.relocated))
        .collect();
    assert_eq!(got, want);
    for (i, at) in [text + 0x10, text + 0x20, text + 0x30]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            reason(&p, at),
            Some((StartReason::DataPtr, 70)),
            "{at:#x} starts a function"
        );
        let why = p.why(&FactKey::Func(fid(at))).expect("a why-record");
        assert_eq!(why.rule.as_str(), "R_DATA_CODE_PTR");
        let slot = slot + 8 * u64::try_from(i).expect("an index");
        assert_eq!(why.premises, [FactKey::Reloc(slot)]);
    }
    assert_eq!(reason(&p, text), Some((StartReason::Entry, 100)));
    let found = p.check_invariants();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn pointer_into_known_body_is_no_seed() {
    // The entry holds FUNC, and the pointers go to its second and third instruction.
    let text = code(0x10, &[(0, &FUNC)]);
    let data = Section::data(".data.rel.ro", &[0; 24])
        .fixup(0, FixupKind::Abs64, Loc::section(".text", 1))
        .fixup(8, FixupKind::Abs64, Loc::section(".text", 4))
        .fixup(16, FixupKind::Abs64, Loc::section(".text", 0));
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &text))
        .section(data)
        .relr(Loc::section(".data.rel.ro", 0))
        .relr(Loc::section(".data.rel.ro", 8))
        .relr(Loc::section(".data.rel.ro", 16));
    let (p, layout) = analyzed(&b);
    let text = sec(&layout, ".text");
    assert_eq!(dataptr::pointers(&p).len(), 3, "the pointers exist");
    assert_eq!(entries(&p), [text], "the body holds the targets");
    assert_eq!(
        reason(&p, text),
        Some((StartReason::Entry, 100)),
        "a known start keeps its reason"
    );
}

#[test]
fn pointer_to_data_is_no_seed() {
    let text = code(0x20, &[(0, &[0xc3]), (0x10, &FUNC)]);
    let data = Section::data(".data.rel.ro", &[0; 16])
        .fixup(0, FixupKind::Abs64, Loc::section(".rodata", 0))
        .fixup(8, FixupKind::Abs64, Loc::section(".text", 0x10));
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &text))
        .section(Section::rodata(".rodata", &FUNC))
        .section(data)
        .relr(Loc::section(".data.rel.ro", 0))
        .relr(Loc::section(".data.rel.ro", 8));
    let (p, layout) = analyzed(&b);
    let (text, ro) = (sec(&layout, ".text"), sec(&layout, ".rodata"));
    let targets: Vec<u64> = dataptr::pointers(&p).iter().map(|x| x.target).collect();
    assert_eq!(
        targets,
        [text + 0x10],
        "a pointer to data is no code pointer"
    );
    assert!(p.func(fid(ro)).is_none());
    assert_eq!(entries(&p), [text, text + 0x10]);
}

#[test]
fn unaligned_value_is_no_seed() {
    let text = code(0x30, &[(0, &[0xc3]), (0x10, &FUNC), (0x20, &FUNC)]);
    // Two pointers at the offsets `first` and `first + 8` of a file at a fixed address.
    let file = |first: u64| {
        let data = Section::data(".data", &[0; 24])
            .fixup(first, FixupKind::Abs64, Loc::section(".text", 0x10))
            .fixup(first + 8, FixupKind::Abs64, Loc::section(".text", 0x20));
        ElfBuilder::exec()
            .section(Section::code(".text", &text))
            .section(data)
    };
    let (p, layout) = analyzed(&file(4));
    assert!(dataptr::pointers(&p).is_empty());
    assert_eq!(entries(&p), [sec(&layout, ".text")]);
    let (p, layout) = analyzed(&file(0));
    let at = sec(&layout, ".text");
    assert_eq!(
        entries(&p),
        [at, at + 0x10, at + 0x20],
        "aligned pointers seed"
    );
    // A relocation at an unaligned place gives no code pointer either.
    let text = text_of(&pie(&[], 2, Some((4, 0))));
    let (p, layout) = analyzed(&pie(&[], 2, Some((4, addend(text + 0x10)))));
    assert!(dataptr::pointers(&p).is_empty());
    assert_eq!(entries(&p), [sec(&layout, ".text")]);
    let (p, _) = analyzed(&pie(&[], 2, Some((8, addend(text + 0x10)))));
    assert_eq!(entries(&p), [text, text + 0x10], "an aligned place seeds");
}

#[test]
fn single_unrelocated_pointer_is_no_seed() {
    let text = code(
        0x40,
        &[(0, &[0xc3]), (0x10, &FUNC), (0x20, &FUNC), (0x30, &FUNC)],
    );
    // A lone pointer, a 0 word, then a run of two pointers.
    let data = Section::data(".data", &[0; 32])
        .fixup(0, FixupKind::Abs64, Loc::section(".text", 0x10))
        .fixup(16, FixupKind::Abs64, Loc::section(".text", 0x20))
        .fixup(24, FixupKind::Abs64, Loc::section(".text", 0x30));
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .section(data);
    let (p, layout) = analyzed(&b);
    let (text, slot) = (sec(&layout, ".text"), sec(&layout, ".data"));
    let got: Vec<(u64, u64, bool)> = dataptr::pointers(&p)
        .iter()
        .map(|x| (x.slot, x.target, x.relocated))
        .collect();
    assert_eq!(
        got,
        [
            (slot + 16, text + 0x20, false),
            (slot + 24, text + 0x30, false)
        ]
    );
    assert!(
        p.func(fid(text + 0x10)).is_none(),
        "a lone pointer is no seed"
    );
    for (at, s) in [(text + 0x20, slot + 16), (text + 0x30, slot + 24)] {
        assert_eq!(reason(&p, at), Some((StartReason::DataPtr, 70)));
        let why = p.why(&FactKey::Func(fid(at))).expect("a why-record");
        assert_eq!(why.premises, [FactKey::Data(s)]);
    }
}

#[test]
fn short_decode_is_no_seed() {
    // 0x10: xor eax, eax; ret; then bytes that do not decode in 64-bit mode.
    // 0x1d: xor eax, eax; ret at the end of the executable region.
    let short = [0x31, 0xc0, 0xc3, 0x06, 0x06, 0x06, 0x06, 0x06];
    let text = code(
        0x20,
        &[(0, &[0xc3]), (0x10, &short), (0x1d, &[0x31, 0xc0, 0xc3])],
    );
    let data = Section::data(".data.rel.ro", &[0; 16])
        .fixup(0, FixupKind::Abs64, Loc::section(".text", 0x10))
        .fixup(8, FixupKind::Abs64, Loc::section(".text", 0x1d));
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &text))
        .section(data)
        .relr(Loc::section(".data.rel.ro", 0))
        .relr(Loc::section(".data.rel.ro", 8));
    let (p, layout) = analyzed(&b);
    let text = sec(&layout, ".text");
    assert_eq!(dataptr::pointers(&p).len(), 2, "the pointers exist");
    assert_eq!(dataptr::linear_insns(&p, text + 0x10, 4), 2);
    assert_eq!(dataptr::linear_insns(&p, text + 0x1d, 4), 2);
    assert_eq!(
        dataptr::linear_insns(&p, text, 4),
        4,
        "the int3 run decodes"
    );
    assert_eq!(entries(&p), [text]);
}

#[test]
fn padding_head_moves_the_start() {
    // 0x08: a 0 byte, a two-byte nop and int3 bytes before FUNC at 0x10.
    let text = code(
        0x20,
        &[(0, &[0xc3]), (0x08, &[0x00, 0x66, 0x90]), (0x10, &FUNC)],
    );
    let data = Section::data(".data.rel.ro", &[0; 8]).fixup(
        0,
        FixupKind::Abs64,
        Loc::section(".text", 0x08),
    );
    let b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &text))
        .section(data)
        .relr(Loc::section(".data.rel.ro", 0));
    let (p, layout) = analyzed(&b);
    let text = sec(&layout, ".text");
    assert_eq!(dataptr::skip_padding(&p, text + 0x08), Some(text + 0x10));
    assert_eq!(dataptr::skip_padding(&p, text + 0x10), Some(text + 0x10));
    assert_eq!(entries(&p), [text, text + 0x10]);
    assert_eq!(reason(&p, text + 0x10), Some((StartReason::DataPtr, 70)));
}

#[test]
fn jumptable_case_is_no_function() {
    // cmp rdi, 3; ja default; jmp [rdi*8 + table]; four cases; default: xor eax, eax; ret.
    let mut text = vec![
        0x48, 0x83, 0xff, 0x03, 0x77, 0x1f, 0xff, 0x24, 0xfd, 0, 0, 0, 0,
    ];
    for case in 1u8..=4 {
        text.extend_from_slice(&[0xb8, case, 0, 0, 0, 0xc3]);
    }
    text.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let cases = [0x0d, 0x13, 0x19, 0x1f];
    let mut table = Section::rodata(".rodata", &[0; 32]);
    for (i, at) in (0u64..).zip(cases) {
        table = table.fixup(i * 8, FixupKind::Abs64, Loc::section(".text", at));
    }
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &text).fixup(
            9,
            FixupKind::Abs32,
            Loc::section(".rodata", 0),
        ))
        .section(table);
    let (p, layout) = analyzed(&b);
    let text = sec(&layout, ".text");
    let targets: BTreeSet<u64> = dataptr::pointers(&p).iter().map(|x| x.target).collect();
    let want: BTreeSet<u64> = cases.iter().map(|c| text + c).collect();
    assert_eq!(targets, want, "the table is a run of code pointers");
    let jt = p
        .jump_table(JumpTableId(Address::ram(text + 6)))
        .expect("method A finds the table");
    assert!(jt.value.resolved);
    assert_eq!(entries(&p), [text], "no case starts a function");
}

#[test]
fn addr_taken_lea_seeds() {
    // lea rax, [rip+f]; ret at the entry. f at 0x10 is FUNC.
    let text = code(
        0x20,
        &[(0, &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3]), (0x10, &FUNC)],
    );
    let section =
        Section::code(".text", &text).fixup(3, FixupKind::Rel32, Loc::section(".text", 0x10));
    let b = ElfBuilder::dyn_object().section(section);
    let (p, layout) = analyzed(&b);
    let text = sec(&layout, ".text");
    let insn = decode(
        &p.mem()
            .read(text, 7, &ghidorah_base::Limits::DEFAULT)
            .expect("bytes"),
        text,
        &Opts::DEFAULT,
    )
    .expect("a lea");
    assert_eq!(addrtaken::taken(&p, &insn), Some(text + 0x10));
    assert_eq!(reason(&p, text + 0x10), Some((StartReason::AddrTaken, 75)));
    let why = p
        .why(&FactKey::Func(fid(text + 0x10)))
        .expect("a why-record");
    assert_eq!(why.rule.as_str(), "R_ADDR_TAKEN");
    assert_eq!(why.premises, [FactKey::CodeUnit(text)]);
}

#[test]
fn mov_immediate_seeds_only_at_a_fixed_address() {
    // mov edi, f; ret at the entry. f at 0x10 is FUNC.
    let text = code(0x20, &[(0, &[0xbf, 0, 0, 0, 0, 0xc3]), (0x10, &FUNC)]);
    let section =
        || Section::code(".text", &text).fixup(1, FixupKind::Abs32, Loc::section(".text", 0x10));
    let (p, layout) = analyzed(&ElfBuilder::exec().section(section()));
    let text_at = sec(&layout, ".text");
    assert_eq!(
        reason(&p, text_at + 0x10),
        Some((StartReason::AddrTaken, 75))
    );
    let (pie, layout) = analyzed(&ElfBuilder::dyn_object().base(0x40_0000).section(section()));
    let text_at = sec(&layout, ".text");
    assert!(
        pie.func(fid(text_at + 0x10)).is_none(),
        "a PIE immediate is no address"
    );
}

#[test]
fn ac_257_codeptr_precision() {
    let (mut noeh, mut noeh_false) = (0u64, Vec::new());
    for f in fixtures() {
        let t = truth(&f.truth);
        let want: BTreeSet<u64> = truth_funcs(&t).values().copied().collect();
        let p = cached(&f.path);
        for v in p.funcs().iter() {
            if !matches!(
                v.func.start_reason,
                StartReason::DataPtr | StartReason::AddrTaken
            ) {
                continue;
            }
            let at = v.id().0.off;
            let right = want.contains(&at);
            if f.variant == "noeh" {
                noeh += 1;
                if !right {
                    noeh_false.push(format!("{}: {at:#x}", f.path));
                }
            } else {
                assert!(right, "{}: {at:#x} is a false start", f.path);
            }
        }
    }
    assert!(
        noeh >= 100,
        "the seeds start functions without .eh_frame: {noeh}"
    );
    let wrong = u64::try_from(noeh_false.len()).expect("a count");
    assert!(
        wrong * 100 <= noeh,
        "{wrong} of {noeh} false: {noeh_false:?}"
    );
}
