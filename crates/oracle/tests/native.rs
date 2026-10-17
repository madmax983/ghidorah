//! Tier-1 checks of the native form table. These tests run no form.

#![cfg(target_arch = "x86_64")]

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_oracle::native::{self, Form, Kind, MEM, R, Vector};

const FILES: &[&str] = &[
    "alu2", "alu1", "mov", "movx", "lea", "cmov", "setcc", "branch", "shift", "muldiv", "stack",
    "string", "sse_move", "sse_zero", "single",
];

fn all() -> Vec<&'static Form> {
    native::forms().collect()
}

#[test]
fn forms_have_unique_names_and_known_files() {
    let forms = all();
    assert!(forms.len() >= 300, "only {} forms", forms.len());
    let mut names = BTreeSet::new();
    for f in &forms {
        assert!(names.insert(f.name), "{} twice", f.name);
        assert!(FILES.contains(&f.file), "{}: file {}", f.name, f.file);
        assert!(!f.bytes.is_empty() && f.bytes.len() <= 15, "{}", f.name);
        assert!(
            f.regs.contains(&R::Flags) || f.kind != Kind::Plain,
            "{}: flags",
            f.name
        );
        assert!(
            !f.regs.contains(&R::R14),
            "{}: r14 is the scratch register",
            f.name
        );
        assert_eq!(native::find(f.name).map(|g| g.name), Some(f.name));
    }
    assert!(native::find("no such form").is_none());
    for file in FILES {
        assert!(forms.iter().any(|f| f.file == *file), "{file} has forms");
    }
}

#[test]
fn every_row_width_has_64_vectors() {
    let mut counts: BTreeMap<(&str, u16), u32> = BTreeMap::new();
    for f in all() {
        *counts.entry((f.row, f.w)).or_default() += u32::from(f.cases);
    }
    let small: Vec<_> = counts.iter().filter(|(_, n)| **n < 64).collect();
    assert!(small.is_empty(), "{small:?}");
}

#[test]
fn pointers_fit_the_buffer() {
    for f in all() {
        assert!(usize::from(f.mem) <= MEM, "{}", f.name);
        for (reg, off) in f.ptrs {
            assert!(reg.gpr().is_some(), "{}: a general register", f.name);
            assert!(usize::from(*off) < MEM, "{}: offset {off}", f.name);
            assert!(f.regs.contains(reg), "{}: {} is listed", f.name, reg.name());
        }
        let needs_mem = !f.ptrs.is_empty();
        assert_eq!(
            needs_mem,
            f.mem > 0,
            "{}: a buffer for each pointer form",
            f.name
        );
    }
}

#[test]
fn flow_forms_list_the_next_address() {
    for f in all() {
        let has_pc = f.regs.contains(&R::Pc);
        match f.kind {
            Kind::Branch | Kind::Call => assert!(has_pc, "{}", f.name),
            Kind::Plain | Kind::Ret => assert!(!has_pc, "{}", f.name),
        }
        if f.kind == Kind::Branch {
            // Each branch jumps 4 bytes forward, over the tail.
            let rel = f.bytes.ends_with(&[4]) || f.bytes.ends_with(&[4, 0, 0, 0]);
            assert!(rel, "{}: a displacement of 4", f.name);
        }
    }
}

#[test]
fn header_and_vector_lines() {
    let f = native::find("add eax, ecx").expect("a form");
    assert_eq!(
        f.header_line(),
        concat!(
            r#"{"form":"add eax, ecx","row":"add","w":32,"bytes":"01c8","kind":"plain","#,
            r#""regs":["rax","rcx","flags"],"ptrs":[],"mem":0,"cases":64,"#,
            r#""ip":"0x1000","base":"0x10000","fill":"0x5a5a5a5a00000000"}"#
        )
    );
    let v = Vector {
        inputs: vec![1, 0xff, 0x2],
        outputs: vec![0x100, 0xff, 0x10],
        mem_in: Vec::new(),
        mem_out: Vec::new(),
    };
    assert_eq!(
        f.vector_line(&v),
        r#"{"in":["0x1","0xff","0x2"],"out":["0x100","0xff","0x10"]}"#
    );
    let g = native::find("push rax").expect("a form");
    assert!(
        g.header_line().contains(r#""ptrs":[["rsp",32]],"mem":64"#),
        "{}",
        g.header_line()
    );
    let w = Vector {
        inputs: vec![7, 0x10020, 2],
        outputs: vec![7, 0x10018, 2],
        mem_in: vec![0xab; 64],
        mem_out: vec![0xcd; 64],
    };
    let line = g.vector_line(&w);
    assert!(
        line.starts_with(
            r#"{"in":["0x7","0x10020","0x2"],"out":["0x7","0x10018","0x2"],"mem_in":"abab"#
        ),
        "{line}"
    );
    assert!(line.ends_with(r#"cdcd"}"#), "{line}");
}
