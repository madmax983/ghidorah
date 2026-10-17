//! Boundary tests: lengths 1 to 15, cut input, opaque forms, byte registers and
//! RIP-relative targets at the end of a buffer.

use ghidorah_testkit::pbt;
use ghidorah_x86::{
    DecodeError, Insn, InvalidReason, Map, Mnem, Operand, Opts, Reg, decode, length, length_with,
};

use crate::common::{SPEC_ADDR, dec, hex, listings, root, spec_lines};

/// The valid spec vectors.
fn valid_vectors() -> Vec<Vec<u8>> {
    spec_lines()
        .into_iter()
        .filter(|v| !v.is_error())
        .map(|v| v.bytes)
        .collect()
}

/// A sample of fixture instructions: every 7th instruction of each listing.
fn fixture_sample() -> Vec<Vec<u8>> {
    listings()
        .iter()
        .flat_map(|l| l.insns.iter().step_by(7).map(|i| i.bytes.clone()))
        .collect()
}

#[test]
fn ac_062b_length_1_to_15() {
    let mut checked = 0;
    for bytes in valid_vectors().into_iter().chain(fixture_sample()) {
        let n = length(&bytes).unwrap_or_else(|e| panic!("{bytes:02x?}: {e}"));
        assert!((1..=15).contains(&n), "{bytes:02x?} has length {n}");
        checked += 1;
    }
    assert!(checked > 1000, "only {checked} instructions");
    pbt::check("ac_062b_length_1_to_15", 20_000, |g| {
        let bytes = g.bytes(20);
        match length(&bytes) {
            Ok(n) if !(1..=15).contains(&n) => Err(format!("length {n}")),
            Ok(n) if usize::from(n) > bytes.len() => Err(format!("length {n} past the end")),
            _ => Ok(()),
        }
    });
}

#[test]
fn ac_062d_truncated_input() {
    let mut cuts = 0;
    for bytes in valid_vectors().into_iter().chain(fixture_sample()) {
        let n = usize::from(length(&bytes).unwrap_or_else(|e| panic!("{bytes:02x?}: {e}")));
        for k in 0..n {
            match dec(&bytes[..k], SPEC_ADDR) {
                Err(DecodeError::Truncated {
                    have,
                    need_at_least,
                }) => {
                    assert_eq!(usize::from(have), k, "{bytes:02x?} cut at {k}");
                    assert!(
                        usize::from(need_at_least) > k && usize::from(need_at_least) <= n,
                        "{bytes:02x?} cut at {k} needs {need_at_least}"
                    );
                }
                other => panic!("{bytes:02x?} cut at {k} gives {other:?}"),
            }
            assert!(matches!(
                length(&bytes[..k]),
                Err(DecodeError::Truncated { .. })
            ));
            cuts += 1;
        }
    }
    assert!(cuts > 5000, "only {cuts} cuts");
}

/// Reads a `tests/golden/x86_len` file: `(bytes, len, encoding, map)`.
fn len_golden(name: &str) -> Vec<(Vec<u8>, u8, String, String)> {
    let path = root().join("tests/golden/x86_len").join(name);
    let text = std::fs::read_to_string(&path).expect("read the length golden");
    text.lines()
        .skip(1)
        .map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            (
                hex(f[0]),
                f[1].parse().expect("length"),
                f[2].to_owned(),
                f[3].to_owned(),
            )
        })
        .collect()
}

#[test]
fn ac_065_vex_evex_length() {
    let rows = len_golden("vector.txt");
    assert!(rows.len() > 2000, "only {} rows", rows.len());
    let mut failures = Vec::new();
    for (bytes, n, enc, map) in &rows {
        match dec(bytes, SPEC_ADDR) {
            Ok(insn) if insn.is_opaque() && insn.len() == *n && insn.encoding().name() == enc => {}
            other => failures.push(format!(
                "{bytes:02x?} ({enc} map {map}, len {n}): {other:?}"
            )),
        }
    }
    for enc in ["vex2", "vex3", "evex", "rex2"] {
        assert!(rows.iter().any(|r| r.2 == enc), "no {enc} row");
    }
    assert!(
        failures.is_empty(),
        "{} of {} rows fail:\n{}",
        failures.len(),
        rows.len(),
        failures
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn legacy_lengths_match_the_oracle() {
    let rows = len_golden("legacy.txt");
    assert!(rows.len() > 800, "only {} rows", rows.len());
    let mut failures = Vec::new();
    for (bytes, n, _, map) in &rows {
        let got = match dec(bytes, SPEC_ADDR) {
            Ok(insn) => Some(insn.len()),
            Err(DecodeError::Unsupported { len, .. }) => Some(len),
            Err(_) => None,
        };
        if got != Some(*n) || length(bytes) != Ok(*n) {
            failures.push(format!(
                "{bytes:02x?} (map {map}, len {n}): {:?}",
                dec(bytes, 0)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} rows fail:\n{}",
        failures.len(),
        rows.len(),
        failures
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn reg_op(insn: &Insn, i: usize) -> Reg {
    match insn.op(i) {
        Some(Operand::Reg { reg, .. }) => reg,
        other => panic!("operand {i} of {insn:?} is {other:?}"),
    }
}

#[test]
fn rex_byte_regs_spl_dil() {
    let cases: &[(&str, usize, &str)] = &[
        ("40 88 e0", 1, "spl"),
        ("88 e0", 1, "ah"),
        ("40 88 f7", 0, "dil"),
        ("40 88 f7", 1, "sil"),
        ("88 f7", 0, "bh"),
        ("88 f7", 1, "dh"),
        ("40 0f b6 ff", 1, "dil"),
        ("0f b6 ff", 1, "bh"),
        ("40 b5 01", 0, "bpl"),
        ("b5 01", 0, "ch"),
        ("41 88 e0", 0, "r8b"),
        ("41 88 e0", 1, "spl"),
        ("44 88 e0", 1, "r12b"),
        ("40 30 e4", 0, "spl"),
        ("30 e4", 0, "ah"),
    ];
    for &(bytes, i, name) in cases {
        let insn = dec(&hex(bytes), 0).unwrap_or_else(|e| panic!("{bytes}: {e}"));
        let reg = reg_op(&insn, i);
        assert_eq!(reg.name(), name, "{bytes} operand {i}");
        assert_eq!(reg.width_bits(), 8);
        assert_eq!(reg.is_high_byte(), name.ends_with('h') && name.len() == 2);
    }
    let ah = reg_op(&dec(&hex("88 e0"), 0).expect("mov al, ah"), 1);
    assert_eq!(ah.full(), Reg::RAX);
    assert_eq!(ah.bit_range(), (8, 16));
    let spl = reg_op(&dec(&hex("40 88 e0"), 0).expect("mov al, spl"), 1);
    assert_eq!(spl.full(), Reg::RSP);
    assert_eq!(spl.bit_range(), (0, 8));
}

fn rip_target(bytes: &[u8], addr: u64) -> u64 {
    let insn = dec(bytes, addr).unwrap_or_else(|e| panic!("{bytes:02x?}: {e}"));
    let mem = insn
        .mem()
        .unwrap_or_else(|| panic!("{bytes:02x?} has memory"));
    assert!(mem.is_rip_relative(), "{bytes:02x?} is RIP-relative");
    mem.abs_target.expect("a RIP-relative target")
}

#[test]
fn riprel_at_buffer_end() {
    // The target counts the immediate bytes after the displacement.
    let cases: &[(&str, u64)] = &[
        ("c7 05 10 00 00 00 01 00 00 00", 0x1000 + 10 + 0x10),
        ("c6 05 10 00 00 00 01", 0x1000 + 7 + 0x10),
        ("48 8d 05 f0 ff ff ff", 0x1000 + 7 - 0x10),
        ("48 83 3d 10 00 00 00 00", 0x1000 + 8 + 0x10),
        ("66 81 3d 10 00 00 00 34 12", 0x1000 + 9 + 0x10),
        ("ff 25 00 00 00 00", 0x1006),
        ("c5 7d 7f 05 10 00 00 00", 0x1000 + 8 + 0x10),
        ("0f 3a cc 05 10 00 00 00 01", 0x1000 + 9 + 0x10),
    ];
    for &(text, want) in cases {
        let bytes = hex(text);
        assert_eq!(rip_target(&bytes, 0x1000), want, "{text} at the buffer end");
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[0xcc; 8]);
        assert_eq!(
            rip_target(&longer, 0x1000),
            want,
            "{text} with bytes after it"
        );
        let cut = &bytes[..bytes.len() - 1];
        assert!(
            matches!(dec(cut, 0x1000), Err(DecodeError::Truncated { .. })),
            "{text} without its last byte"
        );
    }
    // The address wraps at the top of the address space.
    assert_eq!(rip_target(&hex("8b 05 10 00 00 00"), u64::MAX - 1), 0x14);
    // A 32-bit address (67 prefix) keeps 32 bits.
    assert_eq!(rip_target(&hex("67 8b 05 10 00 00 00"), 0xffff_fff0), 0x7);
}

#[test]
fn branch_size_options() {
    let llvm = Opts::DEFAULT;
    let amd = Opts {
        amd_branch_osz: true,
        ..Opts::DEFAULT
    };
    assert_eq!(length_with(&hex("66 e8 00 00 00 00"), &llvm), Ok(6));
    assert_eq!(length_with(&hex("66 e8 00 00 00 00"), &amd), Ok(4));
    assert_eq!(length_with(&hex("66 e9 00 00 00 00"), &llvm), Ok(4));
    assert_eq!(length_with(&hex("66 0f 84 00 00 00 00"), &llvm), Ok(5));
    assert_eq!(length_with(&hex("66 48 e9 00 00 00 00"), &llvm), Ok(7));
    let jmp16 = decode(&hex("66 e9 00 01"), 0xfff0, &llvm).expect("jmp rel16");
    assert_eq!(jmp16.target(), Some(0x00f4), "the target keeps 16 bits");
    let strict = Opts {
        strict_vex_legacy_prefix: true,
        ..Opts::DEFAULT
    };
    assert!(decode(&hex("66 c5 f8 77"), 0, &llvm).is_ok());
    assert!(matches!(
        decode(&hex("66 c5 f8 77"), 0, &strict),
        Err(DecodeError::Invalid { .. })
    ));
}

#[test]
fn opaque_forms_keep_their_map() {
    let vzu = dec(&hex("c5 f8 77"), 0).expect("vzeroupper");
    assert_eq!(vzu.mnem(), Mnem::Vector);
    let form = vzu.opaque().expect("opaque");
    assert_eq!((form.map, form.opcode, form.len), (Map::M0F, 0x77, 3));
    let shlx = dec(&hex("c4 e2 79 f7 c0"), 0).expect("shlx");
    assert_eq!(shlx.opaque().map(|f| f.map), Some(Map::M0F38));
    assert!(dec(&hex("90"), 0).expect("nop").opaque().is_none());
}

#[test]
fn length_reads_at_most_15_bytes() {
    let mut bytes = vec![0x66; 14];
    bytes.push(0x90);
    assert_eq!(length(&bytes), Ok(15));
    bytes.insert(0, 0x66);
    let too_long = |b: &[u8]| {
        matches!(
            length(b),
            Err(DecodeError::Invalid {
                len_consumed: 15,
                reason: InvalidReason::TooLong
            })
        )
    };
    assert!(too_long(&bytes));
    // The `8F` decision reads one byte past the opcode.
    let mut xop = vec![0x66; 14];
    xop.extend_from_slice(&[0x8f, 0xe8]);
    assert!(too_long(&xop));
    // The immediate takes the length past 15 bytes.
    let mut imm = vec![0x66; 12];
    imm.extend_from_slice(&[0x48, 0x05, 0, 0, 0, 0]);
    assert!(too_long(&imm));
}

#[test]
fn regress_rex2_map1_opcodes_40_to_4f_and_66() {
    // In map 1 the bytes 40 to 4F (cmovcc) and 66, F2 and F3 are opcodes, not prefixes.
    for (text, n) in [
        ("d5 80 4e 49 a5", 5),
        ("d5 80 66 f8", 4),
        ("d5 80 f2 d3", 4),
    ] {
        let insn = dec(&hex(text), 0).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert!(insn.is_opaque(), "{text}");
        assert_eq!(insn.len(), n, "{text}");
    }
    for text in ["d5 00 48 89 c0", "d5 00 66 89 c0", "d5 00 0f 05"] {
        assert!(
            matches!(
                dec(&hex(text), 0),
                Err(DecodeError::Invalid {
                    reason: InvalidReason::BadRex2,
                    ..
                })
            ),
            "{text}"
        );
    }
}

#[test]
fn regress_insertq_memory_form_is_vmread() {
    // The `66` and `F2` forms of `0F 78` need a register. With memory the LLVM rule
    // decodes `vmread` without immediates.
    let insn = dec(&hex("f2 0f 78 4a 8e"), 0).expect("vmread");
    assert_eq!((insn.mnem(), insn.len()), (Mnem::Vmread, 5));
    let insn = dec(&hex("66 0f 78 00"), 0).expect("vmread");
    assert_eq!((insn.mnem(), insn.len()), (Mnem::Vmread, 4));
    let insn = dec(&hex("f2 0f 78 c1 01 02"), 0).expect("insertq");
    assert_eq!((insn.mnem(), insn.len()), (Mnem::Insertq, 6));
}

#[test]
fn regress_jcc_rel32_with_rep_and_66() {
    // The LLVM rule: an `F2` or `F3` prefix keeps the 32-bit displacement of `0F 8x`.
    assert_eq!(length(&hex("66 f3 0f 89 ed c4 2e a5")), Ok(8));
    assert_eq!(length(&hex("66 f2 0f 84 00 00 00 00")), Ok(8));
    assert_eq!(length(&hex("66 0f 84 00 00")), Ok(5));
    assert_eq!(length(&hex("66 f3 e9 00 00")), Ok(5));
}

#[test]
fn regress_movlpd_register_form_is_movhlps() {
    // `66 0F 12` and `66 0F 16` have only a memory form. With a register the LLVM rule
    // decodes the no-prefix form.
    let insn = dec(&hex("66 0f 12 c1"), 0).expect("movhlps");
    assert_eq!((insn.mnem(), insn.len()), (Mnem::Movhlps, 4));
    let insn = dec(&hex("66 0f 16 c1"), 0).expect("movlhps");
    assert_eq!((insn.mnem(), insn.len()), (Mnem::Movlhps, 4));
    let insn = dec(&hex("66 0f 16 00"), 0).expect("movhpd");
    assert_eq!(insn.mnem(), Mnem::Movhpd);
}
