//! The feature stream: keys, buckets, op tokens, CFG shape, WL labels, constants, strings,
//! imports and callees.

use std::collections::BTreeSet;

use ghidorah_analysis::similar::{Kind, bucket, feature_key, token};
use ghidorah_base::{OpId, fnv1a64};
use ghidorah_ir::arena::op_at;
use ghidorah_ir::{Arg, Loc, Opc, Val};

use crate::support::{BASE, blob, entry_of, fixture, stream, texts};

/// A loop: `xor eax, eax; inc eax; cmp eax, 10; jne -7; ret`. Three blocks, three edges and
/// one loop.
pub const LOOP: [u8; 10] = [0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x0a, 0x75, 0xf9, 0xc3];

/// Constants: `mov eax, 0x12345678; mov eax, 0x10; mov eax, 0x400010;
/// mov rax, [0x7fff0000]; lea rax, [rip+0x1000]; add rsp, -0x1000; ret`. One block.
pub const CONSTS: [u8; 38] = [
    0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
    0xb8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
    0xb8, 0x10, 0x00, 0x40, 0x00, // mov eax, 0x400010 (in the blob)
    0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0xff, 0x7f, // mov rax, [0x7fff0000]
    0x48, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, // lea rax, [rip+0x1000]
    0x48, 0x81, 0xc4, 0x00, 0xf0, 0xff, 0xff, // add rsp, -0x1000
    0xc3, // ret
];

#[test]
fn feature_key_layout() {
    let mut bytes = vec![Kind::Opcode.code(), 0];
    bytes.extend_from_slice(b"op1:Add.64");
    assert_eq!(feature_key(Kind::Opcode, "op1:Add.64"), fnv1a64(&bytes));
    let mut bytes = vec![Kind::Import.code(), 0];
    bytes.extend_from_slice(b"puts");
    assert_eq!(feature_key(Kind::Import, "puts"), fnv1a64(&bytes));
    assert_ne!(
        feature_key(Kind::Cfg, "x"),
        feature_key(Kind::Const, "x"),
        "the kind is part of the key"
    );
    let names: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(
        names,
        [
            "opcode", "cfg", "wl", "const", "string", "import", "callees"
        ]
    );
}

#[test]
fn bucket_values() {
    let cases = [
        (0, 0),
        (1, 1),
        (2, 1),
        (3, 2),
        (6, 2),
        (7, 3),
        (8, 3),
        (1_000, 9),
        (u64::MAX, 64),
    ];
    for (x, b) in cases {
        assert_eq!(bucket(x), b, "bucket({x})");
    }
}

#[test]
fn tokens_abstract_registers_and_constants() {
    let id = OpId {
        addr: 0x1000,
        seq: 0,
    };
    let v = Arg::V(Val(1));
    let cases = [
        (
            op_at(id, Opc::Get, 64, 0, [Arg::L(Loc::RAX), Arg::Nil, Arg::Nil]),
            Some("Get.gpr"),
        ),
        (
            op_at(
                id,
                Opc::Get,
                128,
                0,
                [Arg::L(Loc::Reg(33)), Arg::Nil, Arg::Nil],
            ),
            Some("Get.xmm"),
        ),
        (
            op_at(id, Opc::Put, 16, 0, [Arg::L(Loc::Flags), v, Arg::Nil]),
            Some("Put.flags"),
        ),
        (
            op_at(id, Opc::Put, 64, 0, [Arg::L(Loc::Stack(-8)), v, Arg::Nil]),
            Some("Put.stack"),
        ),
        (
            op_at(
                id,
                Opc::Get,
                64,
                0,
                [Arg::L(Loc::FS_BASE), Arg::Nil, Arg::Nil],
            ),
            Some("Get.seg"),
        ),
        (
            op_at(id, Opc::Put, 64, 0, [Arg::L(Loc::RDI), Arg::k(7), Arg::Nil]),
            Some("Put.gpr.k"),
        ),
        (
            op_at(id, Opc::Add, 64, 0, [v, Arg::k(5), Arg::Nil]),
            Some("Add.64.k"),
        ),
        (
            op_at(id, Opc::Sub, 32, 0, [v, Arg::V(Val(2)), Arg::Nil]),
            Some("Sub.32"),
        ),
        (op_at(id, Opc::Ret, 0, 0, [Arg::Nil; 3]), Some("Ret.0")),
        (op_at(id, Opc::Nop, 0, 0, [Arg::Nil; 3]), None),
    ];
    for (op, want) in cases {
        assert_eq!(token(&op).as_deref(), want, "{op}");
    }
}

#[test]
fn stream_of_a_loop_function() {
    let p = blob(&LOOP, 0);
    let f = stream(&p, BASE);
    let cfg: BTreeSet<String> = texts(&f, Kind::Cfg).into_iter().collect();
    let want: BTreeSet<String> = ["cfg:blocks=2", "cfg:edges=2", "cfg:loops=1", "cfg:depth=1"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(cfg, want);
    let wl = texts(&f, Kind::Wl);
    assert_eq!(wl.len(), 6, "one label per block and round: {wl:?}");
    for t in &wl {
        let hex = t
            .strip_prefix("wl1:")
            .or_else(|| t.strip_prefix("wl2:"))
            .unwrap_or_else(|| panic!("a wl text: {t}"));
        assert_eq!(hex.len(), 16, "{t}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{t}");
    }
    assert_eq!(texts(&f, Kind::Callees), ["callees=0"]);
    let ops = texts(&f, Kind::Opcode);
    for n in ["op1:", "op2:", "op3:"] {
        assert!(ops.iter().any(|t| t.starts_with(n)), "{n} in {ops:?}");
    }
    for t in &ops {
        let (_, body) = t.split_once(':').expect("an n-gram text");
        for tok in body.split(',') {
            let mut parts = tok.split('.');
            let name = parts.next().unwrap_or_default();
            assert!(
                Opc::ALL.iter().any(|o| o.name() == name),
                "a token starts with an opcode name: {t}"
            );
            assert!(!tok.contains("rax") && !tok.contains("0x"), "{t}");
        }
    }
    assert!(texts(&f, Kind::Import).is_empty());
    assert!(texts(&f, Kind::String).is_empty());
}

#[test]
fn constants_skip_small_and_image_addresses() {
    let p = blob(&CONSTS, 0);
    let f = stream(&p, BASE);
    let got: BTreeSet<String> = texts(&f, Kind::Const).into_iter().collect();
    let want: BTreeSet<String> = ["const:0x12345678", "const:0x7fff0000", "const:-0x1000"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(got, want);
}

#[test]
fn one_block_function_shape() {
    let p = blob(&CONSTS, 0);
    let f = stream(&p, BASE);
    let cfg: BTreeSet<String> = texts(&f, Kind::Cfg).into_iter().collect();
    let want: BTreeSet<String> = ["cfg:blocks=1", "cfg:edges=0", "cfg:loops=0", "cfg:depth=0"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(cfg, want);
    assert_eq!(texts(&f, Kind::Wl).len(), 2);
}

#[test]
fn strings_and_imports_key_by_content() {
    let p = fixture("fixtures/bin/hello.gcc-O2");
    let at = entry_of(p, "finish");
    let f = stream(p, at);
    let imports: Vec<&ghidorah_analysis::similar::Feature> =
        f.iter().filter(|x| x.kind == Kind::Import).collect();
    assert_eq!(imports.len(), 1, "{f:?}");
    assert_eq!(imports[0].text, "imp:puts");
    assert_eq!(imports[0].key, feature_key(Kind::Import, "puts"));
    let strings: Vec<&ghidorah_analysis::similar::Feature> =
        f.iter().filter(|x| x.kind == Kind::String).collect();
    assert_eq!(strings.len(), 1, "{f:?}");
    assert!(strings[0].text.starts_with("str:0x"), "{}", strings[0].text);
    let hex = format!("{:016x}", fnv1a64(b"Goodbye."));
    assert_eq!(strings[0].key, feature_key(Kind::String, &hex));
    assert_eq!(texts(&f, Kind::Callees), ["callees=1"]);
}

#[test]
fn no_decodable_instruction_gives_no_feature() {
    // 0x06 is not a valid opcode in 64-bit mode, so the entry does not decode.
    let p = blob(&[0x06, 0xc3], 0);
    assert!(stream(&p, BASE).is_empty());
}

/// The import features of the function at `addr` of the PE fixture `pe_main.exe`, as
/// `(text, key)` pairs in stream order.
fn pe_imports(addr: u64) -> Vec<(String, u64)> {
    let p = fixture("fixtures/bin/pe/pe_main.exe");
    stream(p, addr)
        .into_iter()
        .filter(|x| x.kind == Kind::Import)
        .map(|x| (x.text, x.key))
        .collect()
}

#[test]
fn regress_similar_pe_thunk_calls_key_imports() {
    // `dispatch` calls Sleep through its IAT thunk and GetTickCount through the IAT slot.
    let dispatch = pe_imports(0x1_4000_10b0);
    let want = [
        ("imp:kernel32.dll!Sleep", "Sleep"),
        ("imp:kernel32.dll!GetTickCount", "GetTickCount"),
    ];
    for (text, name) in want {
        assert!(
            dispatch.contains(&(text.to_owned(), feature_key(Kind::Import, name))),
            "dispatch: {text} in {dispatch:?}"
        );
    }
    // `imports` calls alpha_named through its thunk, and the ordinal and delay imports
    // through their slots.
    let imports = pe_imports(0x1_4000_10e0);
    let want = [
        ("imp:alpha.dll!#5", "#5"),
        ("imp:alpha.dll!alpha_named", "alpha_named"),
        ("imp:beta.dll!beta_delayed", "beta_delayed"),
    ];
    for (text, name) in want {
        assert!(
            imports.contains(&(text.to_owned(), feature_key(Kind::Import, name))),
            "imports: {text} in {imports:?}"
        );
    }
}
