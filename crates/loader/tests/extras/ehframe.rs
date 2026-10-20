//! AC-053, AC-054 and the `.eh_frame` boundary tests.

use ghidorah_base::{DiagCode, Limits};
use ghidorah_loader::ehframe::{EhFrame, Place, parse, parse_bytes};
use ghidorah_loader::{Binary, CfaRow, Fde};
use ghidorah_testkit::elf::{self, ElfBuilder, Fde as BuilderFde, Loc, Malformed, Section, Symbol};

use crate::frames::{self, GoldenFde};
use crate::support::{codes, fixture, fixture_names, golden_body, has_fixture, load_ok};

/// The address of the `.eh_frame` bytes of the hand-made tests.
const VA: u64 = 0x2000;

/// The place of the hand-made tests.
const PLACE: Place = Place {
    va: VA,
    file_off: 0x800,
};

/// A writer of hand-made `.eh_frame` bytes.
#[derive(Default)]
struct Eh {
    buf: Vec<u8>,
}

impl Eh {
    /// Adds a record with a 4-byte length and the CIE ID or pointer `id`. `DW_CFA_nop`
    /// bytes fill the body to a multiple of 4.
    fn record(&mut self, id: u32, body: &[u8]) -> u64 {
        let at = self.buf.len() as u64;
        let mut content = id.to_le_bytes().to_vec();
        content.extend_from_slice(body);
        while !content.len().is_multiple_of(4) {
            content.push(0);
        }
        self.buf
            .extend_from_slice(&u32::try_from(content.len()).expect("len").to_le_bytes());
        self.buf.extend_from_slice(&content);
        at
    }

    /// Adds a CIE: version 1, the augmentation, code factor 1, data factor -8, RA 16.
    fn cie(&mut self, aug: &str, aug_data: &[u8], program: &[u8]) -> u64 {
        let mut body = vec![1];
        body.extend_from_slice(aug.as_bytes());
        body.extend_from_slice(&[0, 1, 0x78, 16]);
        if aug.starts_with('z') {
            body.push(u8::try_from(aug_data.len()).expect("aug len"));
            body.extend_from_slice(aug_data);
        }
        body.extend_from_slice(program);
        self.record(0, &body)
    }

    /// Adds the CIE of GCC: `zR` with `pcrel | sdata4`, CFA `rsp + 8`.
    fn gcc_cie(&mut self) -> u64 {
        self.cie("zR", &[0x1b], &[0x0c, 0x07, 0x08, 0x90, 0x01])
    }

    /// Adds an FDE of a `zR` CIE at `cie` with `pcrel | sdata4` pointers.
    fn fde(&mut self, cie: u64, begin: u64, len: u32, program: &[u8]) -> u64 {
        let at = self.buf.len() as u64;
        let id_field = at + 4;
        let pointer = i64::try_from(id_field + 4 + VA).expect("va");
        let rel = i32::try_from(i64::try_from(begin).expect("begin") - pointer).expect("rel");
        let mut body = rel.to_le_bytes().to_vec();
        body.extend_from_slice(&len.to_le_bytes());
        body.push(0);
        body.extend_from_slice(program);
        self.record(u32::try_from(id_field - cie).expect("cie pointer"), &body)
    }

    /// Adds the zero terminator.
    fn end(&mut self) {
        self.buf.extend_from_slice(&[0; 4]);
    }

    fn parse(&self) -> EhFrame {
        parse_bytes(&self.buf, PLACE, &Limits::DEFAULT)
    }
}

fn row(pc: u64, reg: u16, offset: i64) -> CfaRow {
    CfaRow { pc, reg, offset }
}

fn diag_codes(eh: &EhFrame) -> Vec<DiagCode> {
    eh.diagnostics.iter().map(|d| d.code).collect()
}

/// The `.eh_frame` section of a loaded file.
fn eh_section(b: &Binary) -> Option<&ghidorah_loader::Section> {
    b.sections
        .iter()
        .find(|s| s.name.as_bytes() == b".eh_frame")
}

/// Compares the FDEs of one fixture with its golden.
fn compare(name: &str, b: &Binary, want: &[GoldenFde]) -> Vec<String> {
    let mut problems = Vec::new();
    let base = eh_section(b).map_or(0, |s| s.file_off);
    if b.fdes.len() != want.len() {
        problems.push(format!(
            "{name}: {} FDEs, the golden has {}",
            b.fdes.len(),
            want.len()
        ));
        return problems;
    }
    for (got, w) in b.fdes.iter().zip(want) {
        let range = (got.range.first, got.range.last.wrapping_add(1));
        if range != (w.pc_begin, w.pc_end) {
            problems.push(format!(
                "{name}: FDE {:#x}: range {range:x?}, want {:x?}",
                w.offset,
                (w.pc_begin, w.pc_end)
            ));
        }
        if got.cie.wrapping_sub(base) != w.cie {
            problems.push(format!(
                "{name}: FDE {:#x}: CIE {:#x}, want {:#x}",
                w.offset,
                got.cie.wrapping_sub(base),
                w.cie
            ));
        }
        let rows: Vec<(u64, u16, i64)> = got
            .cfa_rows
            .iter()
            .map(|r| (r.pc, r.reg, r.offset))
            .collect();
        if rows != w.rows {
            problems.push(format!(
                "{name}: FDE {:#x}: rows {rows:x?}, want {:x?}",
                w.offset, w.rows
            ));
        }
    }
    problems
}

#[test]
fn ac_053_eh_frame_golden() {
    let mut checked = 0;
    let mut problems = Vec::new();
    for name in fixture_names() {
        let Some(body) = golden_body("ehframe", &format!("{name}.txt")) else {
            continue;
        };
        checked += 1;
        let want = frames::parse(&body);
        let (b, _) = load_ok(&fixture(&name));
        problems.extend(compare(&name, &b, &want));
        let stopped = want.iter().filter(|f| f.stopped).count();
        let cfa = codes(&b)
            .into_iter()
            .filter(|c| *c == DiagCode::CfaOpcode)
            .count();
        if cfa != stopped {
            problems.push(format!("{name}: {cfa} E_CFA_OPCODE, want {stopped}"));
        }
        for twin in ["stripped", "noshdr"] {
            let twin = format!("{name}.{twin}");
            if has_fixture(&twin) {
                let (t, _) = load_ok(&fixture(&twin));
                if t.fdes != b.fdes {
                    problems.push(format!("{twin}: the FDEs differ from {name}"));
                }
            }
        }
        let noeh = format!("{name}.noeh");
        if has_fixture(&noeh) {
            let (t, _) = load_ok(&fixture(&noeh));
            if !t.fdes.is_empty() || codes(&t).contains(&DiagCode::CfaOpcode) {
                problems.push(format!("{noeh}: {} FDEs", t.fdes.len()));
            }
        }
    }
    assert!(checked >= 60, "only {checked} goldens");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn ac_053_parse_equals_the_load() {
    let (b, map) = load_ok(&fixture("hello.gcc-O2.noshdr"));
    let eh = parse(&b, &map, &Limits::DEFAULT);
    assert_eq!(eh.fdes, b.fdes);
    assert_eq!(eh.fdes.len(), 8);
    assert_eq!(diag_codes(&eh), vec![DiagCode::CfaOpcode], "the PLT FDE");
}

#[test]
fn ac_054_cfa_opcode_variant() {
    let v = elf::malformed_variants()
        .into_iter()
        .find(|v| v.name == "cfa_opcode")
        .expect("the variant");
    let (b, _) = load_ok(&v.bytes);
    assert_eq!(codes(&b), vec![DiagCode::CfaOpcode]);
    assert_eq!(b.fdes.len(), 1, "the FDE keeps its range");
    assert!(b.fdes[0].cfa_rows.is_empty(), "a stopped FDE has no rows");
}

#[test]
fn builder_frame_pointer_rows() {
    let (bytes, layout) = ElfBuilder::exec()
        .section(Section::code(
            ".text",
            &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
        ))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 6))
        .fde(BuilderFde::frame_pointer(Loc::symbol("f"), 6))
        .build_with_layout();
    let f = layout.section(".text").expect(".text").addr;
    for stripped in [false, true] {
        let bytes = if stripped {
            ElfBuilder::exec()
                .section(Section::code(
                    ".text",
                    &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
                ))
                .symbol(Symbol::func("f", Loc::section(".text", 0), 6))
                .fde(BuilderFde::frame_pointer(Loc::symbol("f"), 6))
                .strip_section_headers()
                .build()
        } else {
            bytes.clone()
        };
        let (b, _) = load_ok(&bytes);
        assert!(b.diagnostics.is_empty(), "{:?}", b.diagnostics);
        assert_eq!(b.fdes.len(), 1, "stripped {stripped}");
        let fde: &Fde = &b.fdes[0];
        assert_eq!((fde.range.first, fde.range.last), (f, f + 5));
        assert_eq!(
            fde.cfa_rows,
            vec![row(f, 7, 8), row(f + 1, 7, 16), row(f + 4, 6, 16)]
        );
    }
}

#[test]
fn eh_frame_zero_terminator() {
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    eh.fde(cie, 0x400, 0x10, &[]);
    eh.end();
    eh.fde(cie, 0x500, 0x10, &[]);
    let got = eh.parse();
    assert_eq!(got.fdes.len(), 1, "the walk stops at the terminator");
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(got.fdes[0].range.first, 0x400);
    assert_eq!(got.fdes[0].cie, PLACE.file_off + cie);

    let mut first = Eh::default();
    first.end();
    let cie = first.gcc_cie();
    first.fde(cie, 0x400, 0x10, &[]);
    let got = first.parse();
    assert!(got.fdes.is_empty() && got.diagnostics.is_empty());

    // Without a terminator, the walk stops at the end of the bytes.
    let mut open = Eh::default();
    let cie = open.gcc_cie();
    open.fde(cie, 0x400, 0x10, &[]);
    open.fde(cie, 0x410, 0x10, &[]);
    let got = open.parse();
    assert_eq!(got.fdes.len(), 2);
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);

    // A record that runs past the bytes stops the walk with E_OOB.
    let mut cut = open.buf.clone();
    cut.truncate(cut.len() - 3);
    let got = parse_bytes(&cut, PLACE, &Limits::DEFAULT);
    assert_eq!(got.fdes.len(), 1);
    assert_eq!(diag_codes(&got), vec![DiagCode::Oob]);
}

#[test]
fn header_view_equals_section_view() {
    let build = |strip: bool| {
        let mut b = ElfBuilder::exec()
            .section(Section::code(".text", &[0xc3; 32]))
            .symbol(Symbol::func("f", Loc::section(".text", 0), 16))
            .symbol(Symbol::func("g", Loc::section(".text", 16), 16))
            .fde(BuilderFde::frame_pointer(Loc::symbol("f"), 16))
            .fde(BuilderFde::frame_pointer(Loc::symbol("g"), 16));
        if strip {
            b = b.strip_section_headers();
        }
        b.build()
    };
    let (full, _) = load_ok(&build(false));
    let (bare, _) = load_ok(&build(true));
    assert_eq!(full.fdes.len(), 2);
    assert_eq!(
        bare.fdes, full.fdes,
        "the header view stops at the terminator"
    );
    assert!(bare.diagnostics.is_empty(), "{:?}", bare.diagnostics);
}

#[test]
fn cfa_unknown_opcode_stops_fde() {
    for (opcode, program) in [
        ("unknown 0x3f", vec![0x41, 0x0e, 0x10, 0x3f, 0x0e, 0x18]),
        ("def_cfa_expression", vec![0x41, 0x0f, 0x02, 0x77, 0x08]),
        ("set_loc", vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("restore_state, no state", vec![0x41, 0x0b]),
    ] {
        let mut eh = Eh::default();
        let cie = eh.gcc_cie();
        eh.fde(cie, 0x400, 0x20, &program);
        eh.fde(cie, 0x420, 0x20, &[0x41, 0x0e, 0x10]);
        eh.end();
        let got = eh.parse();
        assert_eq!(diag_codes(&got), vec![DiagCode::CfaOpcode], "{opcode}");
        assert_eq!(got.fdes.len(), 2, "{opcode}: both FDEs keep their ranges");
        assert!(got.fdes[0].cfa_rows.is_empty(), "{opcode}: no rows");
        assert_eq!(
            got.fdes[1].cfa_rows,
            vec![row(0x420, 7, 8), row(0x421, 7, 16)],
            "{opcode}: the next FDE has its rows"
        );
        assert!(got.diagnostics[0].offset.is_some(), "{opcode}");
    }
}

#[test]
fn register_rules_keep_the_cfa() {
    // undefined, same_value, register, expression, val_offset, val_offset_sf,
    // val_expression, GNU_args_size, GNU_negative_offset_extended, offset_extended_sf,
    // offset_extended, restore_extended, restore and offset.
    let program = [
        0x07, 0x10, // undefined r16
        0x08, 0x03, // same_value r3
        0x09, 0x03, 0x06, // register r3, r6
        0x10, 0x05, 0x02, 0x77, 0x08, // expression r5, 2 bytes
        0x14, 0x03, 0x02, // val_offset r3, 2
        0x15, 0x03, 0x7e, // val_offset_sf r3, -2
        0x16, 0x03, 0x01, 0x30, // val_expression r3, 1 byte
        0x2e, 0x10, // GNU_args_size 16
        0x2f, 0x03, 0x02, // GNU_negative_offset_extended r3, 2
        0x11, 0x03, 0x7e, // offset_extended_sf r3, -2
        0x05, 0x03, 0x02, // offset_extended r3, 2
        0x06, 0x03, // restore_extended r3
        0xc3, // restore r3
        0x83, 0x02, // offset r3, 2
        0x41, 0x0e, 0x10, // advance_loc 1, def_cfa_offset 16
    ];
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    eh.fde(cie, 0x400, 0x20, &program);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(
        got.fdes[0].cfa_rows,
        vec![row(0x400, 7, 8), row(0x401, 7, 16)]
    );
}

#[test]
fn cfa_rows_forms() {
    let cases: Vec<(&str, Vec<u8>, Vec<CfaRow>)> = vec![
        (
            "advance_loc1, 2 and 4",
            vec![
                0x02, 0x10, 0x0e, 0x10, 0x03, 0x00, 0x01, 0x0e, 0x18, 0x04, 0x00, 0x01, 0, 0,
            ],
            vec![row(0x400, 7, 8), row(0x410, 7, 16)],
        ),
        (
            "def_cfa, def_cfa_register",
            vec![0x41, 0x0c, 0x06, 0x10, 0x41, 0x0d, 0x03],
            vec![row(0x400, 7, 8), row(0x401, 6, 16), row(0x402, 3, 16)],
        ),
        (
            "def_cfa_sf and def_cfa_offset_sf use the data factor",
            vec![0x41, 0x12, 0x07, 0x7e, 0x41, 0x13, 0x7d],
            vec![row(0x400, 7, 8), row(0x401, 7, 16), row(0x402, 7, 24)],
        ),
        (
            "remember_state and restore_state",
            vec![
                0x41, 0x0e, 0x10, 0x0a, 0x41, 0x0e, 0x08, 0x41, 0x0b, 0x41, 0x0e, 0x20,
            ],
            vec![
                row(0x400, 7, 8),
                row(0x401, 7, 16),
                row(0x402, 7, 8),
                row(0x403, 7, 16),
                row(0x404, 7, 32),
            ],
        ),
        (
            "a change back to the rule before gives no row",
            vec![0x41, 0x0e, 0x10, 0x0e, 0x08, 0x42, 0x0e, 0x10],
            vec![row(0x400, 7, 8), row(0x403, 7, 16)],
        ),
        (
            "rows at or after the end are not kept",
            vec![0x41, 0x0e, 0x10, 0x5f, 0x0e, 0x18, 0x41, 0x0e, 0x20],
            vec![row(0x400, 7, 8), row(0x401, 7, 16)],
        ),
    ];
    for (what, program, want) in cases {
        let mut eh = Eh::default();
        let cie = eh.gcc_cie();
        eh.fde(cie, 0x400, 0x20, &program);
        let got = eh.parse();
        assert!(got.diagnostics.is_empty(), "{what}: {:?}", got.diagnostics);
        assert_eq!(got.fdes[0].cfa_rows, want, "{what}");
    }
}

#[test]
fn cie_forms() {
    // Version 3 has a LEB128 return register. zPLR has a personality and an LSDA.
    let mut eh = Eh::default();
    let mut body = vec![3];
    body.extend_from_slice(b"zPLR\0");
    body.extend_from_slice(&[1, 0x78, 0x10]);
    body.extend_from_slice(&[7, 0x9b, 0x10, 0, 0, 0, 0x1b, 0x1b]);
    body.extend_from_slice(&[0x0c, 0x07, 0x08]);
    let cie = eh.record(0, &body);
    let at = eh.buf.len() as u64;
    let id_field = at + 4;
    let rel = 0x400 - i64::try_from(id_field + 4 + VA).expect("va");
    let mut fde = i32::try_from(rel).expect("rel").to_le_bytes().to_vec();
    fde.extend_from_slice(&0x10u32.to_le_bytes());
    fde.extend_from_slice(&[4, 0, 0, 0, 0, 0x41, 0x0e, 0x10]);
    eh.record(u32::try_from(id_field - cie).expect("ptr"), &fde);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(got.fdes.len(), 1);
    assert_eq!(
        got.fdes[0].cfa_rows,
        vec![row(0x400, 7, 8), row(0x401, 7, 16)]
    );

    // An empty augmentation uses absolute 8-byte pointers.
    let mut eh = Eh::default();
    let cie = eh.cie("", &[], &[0x0c, 0x07, 0x08]);
    let id_field = eh.buf.len() as u64 + 4;
    let mut fde = 0x1234u64.to_le_bytes().to_vec();
    fde.extend_from_slice(&0x20u64.to_le_bytes());
    eh.record(u32::try_from(id_field - cie).expect("ptr"), &fde);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(
        (got.fdes[0].range.first, got.fdes[0].range.last),
        (0x1234, 0x1253)
    );
}

/// One bad record case: name, writer, expected code and expected FDE count.
type BadCase = (&'static str, Box<dyn Fn(&mut Eh)>, DiagCode, usize);

#[test]
fn bad_records_give_diagnostics() {
    let cases: Vec<BadCase> = vec![
        (
            "CIE version 2",
            Box::new(|eh: &mut Eh| {
                let cie = eh.record(0, &[2, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]);
                eh.fde(cie, 0x400, 0x10, &[]);
            }),
            DiagCode::BadMagic,
            0,
        ),
        (
            "unknown augmentation",
            Box::new(|eh: &mut Eh| {
                let cie = eh.cie("eh", &[], &[]);
                eh.fde(cie, 0x400, 0x10, &[]);
            }),
            DiagCode::BadMagic,
            0,
        ),
        (
            "textrel FDE encoding",
            Box::new(|eh: &mut Eh| {
                let cie = eh.cie("zR", &[0x23], &[]);
                eh.fde(cie, 0x400, 0x10, &[]);
            }),
            DiagCode::BadMagic,
            0,
        ),
        (
            "CIE pointer before the bytes",
            Box::new(|eh: &mut Eh| {
                eh.record(0x100, &[0; 12]);
            }),
            DiagCode::Oob,
            0,
        ),
        (
            "CIE pointer to an FDE",
            Box::new(|eh: &mut Eh| {
                let cie = eh.gcc_cie();
                let fde = eh.fde(cie, 0x400, 0x10, &[]);
                let id_field = eh.buf.len() as u64 + 4;
                eh.record(u32::try_from(id_field - fde).expect("ptr"), &[0; 12]);
            }),
            DiagCode::BadMagic,
            1,
        ),
        (
            "range past the 64-bit space",
            Box::new(|eh: &mut Eh| {
                let cie = eh.cie("", &[], &[]);
                let id_field = eh.buf.len() as u64 + 4;
                let mut body = (u64::MAX - 4).to_le_bytes().to_vec();
                body.extend_from_slice(&0x10u64.to_le_bytes());
                eh.record(u32::try_from(id_field - cie).expect("ptr"), &body);
            }),
            DiagCode::Overflow,
            0,
        ),
        (
            "a record shorter than its ID",
            Box::new(|eh: &mut Eh| {
                eh.buf.extend_from_slice(&[2, 0, 0, 0, 0, 0]);
                let cie = eh.gcc_cie();
                eh.fde(cie, 0x400, 0x10, &[]);
            }),
            DiagCode::Oob,
            1,
        ),
    ];
    for (what, make, code, fdes) in cases {
        let mut eh = Eh::default();
        make(&mut eh);
        let got = eh.parse();
        assert_eq!(diag_codes(&got), vec![code], "{what}");
        assert_eq!(got.fdes.len(), fdes, "{what}");
    }
}

#[test]
fn zero_range_fde_gives_no_record() {
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    eh.fde(cie, 0x400, 0, &[]);
    eh.fde(cie, 0x410, 4, &[]);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(got.fdes.len(), 1);
    assert_eq!(got.fdes[0].range.first, 0x410);
}

#[test]
fn eight_byte_length_records() {
    let mut eh = Eh::default();
    // A CIE with the 8-byte length form. The CIE ID keeps 4 bytes in `.eh_frame`.
    let mut cie = vec![0u8; 4];
    cie.extend_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 0x07, 0x08]);
    eh.buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    eh.buf
        .extend_from_slice(&u64::try_from(cie.len()).expect("len").to_le_bytes());
    eh.buf.extend_from_slice(&cie);
    let at = eh.buf.len() as u64;
    let id_field = at + 12;
    let rel = 0x400 - i64::try_from(id_field + 4 + VA).expect("va");
    let mut fde = u32::try_from(id_field)
        .expect("an offset")
        .to_le_bytes()
        .to_vec();
    fde.extend_from_slice(&i32::try_from(rel).expect("rel").to_le_bytes());
    fde.extend_from_slice(&0x10u32.to_le_bytes());
    fde.push(0);
    eh.buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    eh.buf
        .extend_from_slice(&u64::try_from(fde.len()).expect("len").to_le_bytes());
    eh.buf.extend_from_slice(&fde);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(got.fdes.len(), 1);
    assert_eq!(got.fdes[0].range.first, 0x400);
    assert_eq!(got.fdes[0].cfa_rows, vec![row(0x400, 7, 8)]);
}

#[test]
fn limits_stop_the_walk() {
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    for i in 0..5 {
        eh.fde(cie, 0x400 + 0x10 * i, 0x10, &[]);
    }
    let limits = Limits {
        fdes: 3,
        ..Limits::DEFAULT
    };
    let got = parse_bytes(&eh.buf, PLACE, &limits);
    assert_eq!(got.fdes.len(), 3);
    assert_eq!(diag_codes(&got), vec![DiagCode::Limit]);

    let mut long = Eh::default();
    let cie = long.gcc_cie();
    long.fde(cie, 0x400, 0x100, &[0x41; 40]);
    let limits = Limits {
        cfa_insns_per_fde: 16,
        ..Limits::DEFAULT
    };
    let got = parse_bytes(&long.buf, PLACE, &limits);
    assert_eq!(diag_codes(&got), vec![DiagCode::Limit]);
    assert_eq!(got.fdes.len(), 1);
    assert!(got.fdes[0].cfa_rows.is_empty());
}

#[test]
fn header_view_errors() {
    let base = || {
        ElfBuilder::exec()
            .section(Section::code(".text", &[0xc3; 16]))
            .symbol(Symbol::func("f", Loc::section(".text", 0), 16))
            .fde(BuilderFde::frame_pointer(Loc::symbol("f"), 16))
            .strip_section_headers()
    };
    let (_, layout) = base().build_with_layout();
    let hdr = layout
        .section(".eh_frame_hdr")
        .expect(".eh_frame_hdr")
        .offset;
    let patch = |at: u64, bytes: Vec<u8>| {
        let file = base().malformed(Malformed::Patch(hdr + at, bytes)).build();
        load_ok(&file).0
    };
    let b = patch(0, vec![2]);
    assert_eq!(codes(&b), vec![DiagCode::BadMagic], "version 2");
    assert!(b.fdes.is_empty());
    let b = patch(1, vec![0x23]);
    assert_eq!(
        codes(&b),
        vec![DiagCode::BadMagic],
        "a textrel eh_frame_ptr"
    );
    let b = patch(1, vec![0xff]);
    assert!(
        b.fdes.is_empty() && b.diagnostics.is_empty(),
        "an omitted eh_frame_ptr"
    );
    let b = patch(4, 0x4000_0000i32.to_le_bytes().to_vec());
    assert_eq!(codes(&b), vec![DiagCode::Oob], "an unmapped eh_frame_ptr");
    assert!(b.fdes.is_empty());
}

#[test]
fn cie_errors() {
    let cases: Vec<(&str, Vec<u8>, DiagCode)> = vec![
        ("no version", vec![], DiagCode::Oob),
        (
            "augmentation with no end",
            vec![1, b'z', b'R', b'x'],
            DiagCode::Oob,
        ),
        ("cut header", vec![1, 0, 1, 0x78], DiagCode::Oob),
        (
            "augmentation data past the CIE",
            vec![1, b'z', b'R', 0, 1, 0x78, 16, 0x20, 0x1b],
            DiagCode::Oob,
        ),
        (
            "personality encoding",
            vec![
                1, b'z', b'P', b'R', 0, 1, 0x78, 16, 6, 0x23, 0, 0, 0, 0, 0x1b,
            ],
            DiagCode::BadMagic,
        ),
        (
            "omitted FDE encoding",
            vec![1, b'z', b'R', 0, 1, 0x78, 16, 1, 0xff],
            DiagCode::BadMagic,
        ),
    ];
    for (what, body, code) in cases {
        let mut eh = Eh::default();
        let cie = eh.record(0, &body);
        eh.fde(cie, 0x400, 0x10, &[0x41, 0x0e, 0x10]);
        let got = eh.parse();
        assert_eq!(diag_codes(&got), vec![code], "{what}");
        assert!(got.fdes.is_empty(), "{what}");
    }
}

#[test]
fn cie_program_stop_keeps_the_ranges() {
    let mut eh = Eh::default();
    let cie = eh.cie("zR", &[0x1b], &[0x0f, 0x01, 0x30]);
    eh.fde(cie, 0x400, 0x10, &[0x41, 0x0e, 0x10]);
    eh.fde(cie, 0x410, 0x10, &[]);
    let got = eh.parse();
    assert_eq!(
        diag_codes(&got),
        vec![DiagCode::CfaOpcode],
        "one diagnostic for the CIE"
    );
    assert_eq!(got.fdes.len(), 2);
    assert!(got.fdes.iter().all(|f| f.cfa_rows.is_empty()));
}

#[test]
fn cie_version_4() {
    let mut eh = Eh::default();
    let body = [
        4, b'z', b'R', 0, 8, 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 0x07, 0x08,
    ];
    let cie = eh.record(0, &body);
    eh.fde(cie, 0x400, 0x10, &[0x41, 0x0e, 0x10]);
    let got = eh.parse();
    assert!(got.diagnostics.is_empty(), "{:?}", got.diagnostics);
    assert_eq!(
        got.fdes[0].cfa_rows,
        vec![row(0x400, 7, 8), row(0x401, 7, 16)]
    );
}

#[test]
fn fde_errors() {
    // The PC range field is cut.
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    let id_field = eh.buf.len() as u64 + 4;
    eh.record(u32::try_from(id_field - cie).expect("ptr"), &[0x10, 0]);
    let got = eh.parse();
    assert_eq!(diag_codes(&got), vec![DiagCode::Oob], "a cut range");
    assert!(got.fdes.is_empty());
    // The augmentation data runs past the FDE.
    let mut eh = Eh::default();
    let cie = eh.gcc_cie();
    let id_field = eh.buf.len() as u64 + 4;
    let mut body = 0x10u32.to_le_bytes().to_vec();
    body.extend_from_slice(&0x10u32.to_le_bytes());
    body.push(0x40);
    eh.record(u32::try_from(id_field - cie).expect("ptr"), &body);
    let got = eh.parse();
    assert_eq!(
        diag_codes(&got),
        vec![DiagCode::Oob],
        "long augmentation data"
    );
    // The indirect form of a pointer has no memory in a byte walk.
    let mut eh = Eh::default();
    let cie = eh.cie("zR", &[0x9b], &[]);
    eh.fde(cie, 0x400, 0x10, &[]);
    let got = eh.parse();
    assert_eq!(diag_codes(&got), vec![DiagCode::Oob], "an indirect pointer");
}
