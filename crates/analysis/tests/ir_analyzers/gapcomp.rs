//! Seed 13 (`GapComponent`) of design Section 7.3 (WP-19c, AC-078, AC-258).
//!
//! The blobs are raw x86-64 code at [`BASE`] with the entry `ret` at offset 0. The other code
//! is in gaps: no flow of the entry reaches it. Each test runs the shipped analyzer list.

use std::collections::BTreeSet;

use ghidorah_analysis::analyzers::{gapcomp, gaps};
use ghidorah_analysis::{ANALYZERS, AnalyzerId, Rule, Trigger, registry};
use ghidorah_base::{Address, JumpTableId};
use ghidorah_db::{FactKey, Program, StartReason};
use ghidorah_json::Value;
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{ElfBuilder, FixupKind, Loc, Section};

use crate::blob::{BASE, load, pad};
use crate::support::{analyze, cached, fid, fixtures, hex, list, program_of, truth, truth_funcs};

/// `push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret`: five instructions.
const FUNC: [u8; 8] = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];

/// `xor eax, eax; add eax, 1; add eax, 2`: three instructions that fall through.
const BODY: [u8; 8] = [0x31, 0xc0, 0x83, 0xc0, 0x01, 0x83, 0xc0, 0x02];

/// Gives a blob with the entry `ret` at 0 and each part at its offset. `int3` fills the
/// free bytes.
fn blob(parts: &[(usize, &[u8])]) -> Vec<u8> {
    let end = parts.iter().map(|(at, b)| at + b.len()).max().unwrap_or(1);
    let mut out = pad(vec![0xc3], end);
    for (at, bytes) in parts {
        out[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    out
}

/// Loads `bytes` as a blob with the entry at 0 and runs the shipped list to completion.
fn analyzed(bytes: &[u8]) -> Program {
    let mut p = load(bytes, 0);
    let _ = analyze(&mut p);
    p
}

/// Gives the blob offsets of the function entries of `p`.
fn entries(p: &Program) -> Vec<u64> {
    p.funcs().iter().map(|v| v.id().0.off - BASE).collect()
}

/// Gives the start reason and the confidence of the function at the blob offset `off`.
fn reason(p: &Program, off: u64) -> Option<(StartReason, u8)> {
    p.func(fid(BASE + off))
        .map(|f| (f.func.start_reason, f.func.confidence))
}

/// Gives the blob offsets of the first addresses of the gap items of `p`.
fn gap_starts(p: &Program) -> Vec<u64> {
    gaps::items(p)
        .iter()
        .map(|g| g.range.first - BASE)
        .collect()
}

/// Gives `jmp rel32` at `at` to `to`, both blob offsets.
fn jmp(at: u64, to: u64) -> Vec<u8> {
    let rel = i64::try_from(to).expect("small") - i64::try_from(at + 5).expect("small");
    let mut out = vec![0xe9];
    out.extend_from_slice(&i32::try_from(rel).expect("near").to_le_bytes());
    out
}

/// Gives `call rel32` at `at` to `to`, both blob offsets.
fn call(at: u64, to: u64) -> Vec<u8> {
    let mut out = jmp(at, to);
    out[0] = 0xe8;
    out
}

/// Gives BODY and then `tail` as one part.
fn body_and(tail: &[u8]) -> Vec<u8> {
    let mut out = BODY.to_vec();
    out.extend_from_slice(tail);
    out
}

#[test]
fn gap_spec() {
    let spec = &gapcomp::SPEC;
    assert_eq!((spec.name, spec.priority), ("GapComponents", 470));
    assert_eq!(spec.id, AnalyzerId::GapComponents);
    for t in [Trigger::Bytes, Trigger::Instructions, Trigger::Functions] {
        assert!(spec.listens(t), "the seed listens to {}", t.name());
    }
    assert!(!spec.listens(Trigger::Signatures), "band 470 is below 800");
    assert_eq!(spec.option("min_insns"), Some(gapcomp::MIN_INSNS));
    assert_eq!((gapcomp::CONFIDENCE, gapcomp::MIN_INSNS), (40, 4));
    assert_eq!(Rule::GapComponent.code(), "R_GAP_COMPONENT");
    assert_eq!(StartReason::GapComponent.name(), "gap_component");
    let i = registry::index(spec.id).expect("the shipped list holds the seed");
    assert_eq!(ANALYZERS[i].name, "GapComponents");
    let after = registry::index(AnalyzerId::AddrTakenSeeds).expect("seed 12");
    assert_eq!(i, after + 1, "seed 13 runs after seed 12");
}

#[test]
fn component_of_two_functions_splits() {
    // Two functions back to back at 0x10 and 0x18, with no padding between them.
    let p = analyzed(&blob(&[(0x10, &FUNC), (0x18, &FUNC)]));
    assert_eq!(entries(&p), [0, 0x10, 0x18]);
    for off in [0x10, 0x18] {
        assert_eq!(reason(&p, off), Some((StartReason::GapComponent, 40)));
        let why = p
            .why(&FactKey::Func(fid(BASE + off)))
            .expect("a why-record");
        assert_eq!(why.rule.as_str(), "R_GAP_COMPONENT");
        assert!(why.premises.is_empty(), "the bytes are the premise");
    }
    assert_eq!(gap_starts(&p), [], "no gap stays");
    let found = p.check_invariants();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn three_insn_component_stays_a_gap() {
    // 0x10: mov eax, 0x1337; xor eax, edi; ret. 0x20: the same with one more instruction.
    let three = [0xb8, 0x37, 0x13, 0, 0, 0x31, 0xf8, 0xc3];
    let four = [0xb8, 0x37, 0x13, 0, 0, 0x31, 0xf8, 0x83, 0xc0, 0x01, 0xc3];
    let p = analyzed(&blob(&[(0x10, &three), (0x20, &four)]));
    assert_eq!(entries(&p), [0, 0x20]);
    assert_eq!(reason(&p, 0x20), Some((StartReason::GapComponent, 40)));
    assert_eq!(gap_starts(&p), [0x10], "three instructions stay a gap");
}

#[test]
fn padding_only_gap_is_no_function() {
    // After the entry: int3, nop forms and 0 bytes. FUNC at 0x20 is the control.
    let padding = [0xcc, 0x90, 0x66, 0x90, 0x00, 0x00, 0x0f, 0x1f, 0x00, 0xcc];
    let p = analyzed(&blob(&[(0x01, &padding), (0x20, &FUNC)]));
    assert_eq!(entries(&p), [0, 0x20]);
    assert_eq!(gap_starts(&p), [], "padding is no gap");
}

#[test]
fn invalid_decode_rejects_component() {
    // 0x10: BODY falls into 0x06, a byte that does not decode in 64-bit mode.
    // 0x20: BODY and a call to an address outside the blob.
    // 0x30: BODY and ret: the control.
    let bad_byte = body_and(&[0x06, 0xc3]);
    let mut far = body_and(&call(0x28, 0x10_0000));
    far.push(0xc3);
    let good = body_and(&[0xc3]);
    let p = analyzed(&blob(&[(0x10, &bad_byte), (0x20, &far), (0x30, &good)]));
    assert_eq!(entries(&p), [0, 0x30]);
    assert_eq!(reason(&p, 0x30), Some((StartReason::GapComponent, 40)));
    assert_eq!(
        gap_starts(&p),
        [0x10, 0x20],
        "the rejected code stays a gap"
    );
}

#[test]
fn component_entry_has_no_inner_predecessor() {
    // 0x10: x: mov eax, 1; ret. 0x16: e: test edi, edi; je x; xor eax, eax; ret.
    // The lowest address 0x10 has a predecessor, so the entry is 0x16.
    let code = [
        0xb8, 0x01, 0, 0, 0, 0xc3, 0x85, 0xff, 0x74, 0xf6, 0x31, 0xc0, 0xc3,
    ];
    let p = analyzed(&blob(&[(0x10, &code)]));
    assert_eq!(entries(&p), [0, 0x16]);
    assert_eq!(reason(&p, 0x16), Some((StartReason::GapComponent, 40)));
    assert_eq!(
        p.owner_of(Address::ram(BASE + 0x10)),
        Some(fid(BASE + 0x16)),
        "the body of the entry holds the branch target"
    );
}

#[test]
fn noreturn_call_ends_a_path() {
    // The entry calls n at 0x30: ud2, so n is noreturn.
    // 0x10: BODY; call n. The path ends at the noreturn call.
    // 0x20: BODY; call r. r at 0x38 returns, so the path falls into int3.
    let entry = call(0, 0x30);
    let ends = body_and(&call(0x18, 0x30));
    let open = body_and(&call(0x28, 0x38));
    let p = analyzed(&blob(&[
        (0, &entry),
        (0x10, &ends),
        (0x20, &open),
        (0x30, &[0x0f, 0x0b]),
        (0x38, &[0xc3]),
    ]));
    assert_eq!(entries(&p), [0, 0x10, 0x30]);
    assert_eq!(reason(&p, 0x10), Some((StartReason::GapComponent, 40)));
    assert!(
        p.func(fid(BASE + 0x20)).is_none(),
        "an open path is no function"
    );
}

#[test]
fn shared_tail_jump_target_starts_its_own_function() {
    // a at 0x10 and b at 0x20 both end in a jump to t at 0x40. Two parts jump to t, so
    // each jump is a tail call and t is the entry of its own component.
    let a = body_and(&jmp(0x18, 0x40));
    let b = body_and(&jmp(0x28, 0x40));
    let t = body_and(&[0xc3]);
    let p = analyzed(&blob(&[(0x10, &a), (0x20, &b), (0x40, &t)]));
    assert_eq!(entries(&p), [0, 0x10, 0x20, 0x40]);
    for off in [0x10, 0x20] {
        assert_eq!(reason(&p, off), Some((StartReason::GapComponent, 40)));
    }
    assert_eq!(gap_starts(&p), []);
}

#[test]
fn jump_table_cases_join_their_switch() {
    // 0x10: s: cmp rdi, 3; ja default; jmp [rdi*8 + table]. Nothing refers to s.
    // Cases 1 and 2 jump to a join block. Cases 3 and 4 return. Each case has four
    // instructions, and so has the join block. Then default: xor eax, eax; ret.
    let mut text = pad(vec![0xc3], 0x10);
    text.extend_from_slice(&[
        0x48, 0x83, 0xff, 0x03, 0x77, 0, 0xff, 0x24, 0xfd, 0, 0, 0, 0,
    ]);
    let join = 0x1d + 16 * 2 + 12 * 2;
    let mut cases = Vec::new();
    for case in 1u8..=4 {
        let here = u64::try_from(text.len()).expect("small");
        cases.push(here);
        text.extend_from_slice(&[0xb8, case, 0, 0, 0, 0x83, 0xc0, 0x01, 0x83, 0xc0, 0x02]);
        if case <= 2 {
            text.extend_from_slice(&jmp(here + 11, join));
        } else {
            text.push(0xc3);
        }
    }
    assert_eq!(text.len(), usize::try_from(join).expect("small"));
    text.extend_from_slice(&[0x83, 0xc0, 0x03, 0x83, 0xc0, 0x04, 0x83, 0xc0, 0x05, 0xc3]);
    let default = u8::try_from(text.len() - 0x16).expect("a short branch");
    text[0x15] = default;
    text.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let mut table = Section::rodata(".rodata", &[0; 32]);
    for (i, at) in (0u64..).zip(&cases) {
        table = table.fixup(i * 8, FixupKind::Abs64, Loc::section(".text", *at));
    }
    let code =
        Section::code(".text", &text).fixup(0x19, FixupKind::Abs32, Loc::section(".rodata", 0));
    let (bytes, layout) = ElfBuilder::exec()
        .section(code)
        .section(table)
        .build_with_layout();
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    let _ = analyze(&mut p);
    let at = layout.section(".text").expect("the section").addr;
    let got: Vec<u64> = p.funcs().iter().map(|v| v.id().0.off - at).collect();
    assert_eq!(
        got,
        [0, 0x10],
        "no case and no join block starts a function"
    );
    assert_eq!(
        p.func(fid(at + 0x10)).map(|f| f.func.start_reason),
        Some(StartReason::GapComponent)
    );
    let jt = p
        .jump_table(JumpTableId(Address::ram(at + 0x16)))
        .expect("method A finds the table");
    assert!(jt.value.resolved);
    for off in cases.into_iter().chain([join]) {
        assert_eq!(p.owner_of(Address::ram(at + off)), Some(fid(at + 0x10)));
    }
}

#[test]
fn hidden_gate_stays_a_gap() {
    assert!(
        registry::index(AnalyzerId::GapComponents).is_some(),
        "the shipped list runs the seed"
    );
    let mut checked = 0;
    for f in fixtures() {
        if f.program != "crackme" {
            continue;
        }
        let t = truth(&f.truth);
        let p = cached(&f.path);
        for g in list(&t, "gaps") {
            let at = hex(g.get("addr").expect("an address"));
            let name = g.get("name").and_then(Value::as_str).expect("a name");
            assert_eq!(name, "hidden_gate");
            assert!(
                p.func(fid(at)).is_none(),
                "{}: {name} is no function",
                f.path
            );
            let items = gaps::items(p);
            assert!(
                items.iter().any(|i| i.range.first == at),
                "{}: {name} is a gap item",
                f.path
            );
            checked += 1;
        }
    }
    assert!(checked >= 8, "the crackme builds: {checked}");
}

#[test]
fn ac_258_gap_precision() {
    let (mut noeh, mut noeh_false) = (0u64, Vec::new());
    for f in fixtures() {
        let t = truth(&f.truth);
        let want: BTreeSet<u64> = truth_funcs(&t).values().copied().collect();
        let p = cached(&f.path);
        for v in &p.funcs() {
            if v.func.start_reason != StartReason::GapComponent {
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
        noeh >= 250,
        "the seed starts functions without .eh_frame: {noeh}"
    );
    let wrong = u64::try_from(noeh_false.len()).expect("a count");
    assert!(
        wrong * 50 <= noeh,
        "{wrong} of {noeh} false: {noeh_false:?}"
    );
}
