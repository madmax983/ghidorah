//! AC-112a: SysV layouts of records built through the `TypeStore` API (design Section 9.3).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use ghidorah_base::DiagCode;
use ghidorah_testkit::golden::{self, Header};
use ghidorah_types::layout::{self, render};
use ghidorah_types::{
    DataModel, Enumerator, Field, LayoutError, Prim, RecordKind, StoreError, TagKind, Type, TypeId,
    TypeStore, parse_type,
};

use crate::support::{assert_diag, offset, root, store, ty};

use RecordKind::{Struct, Union};

/// One layout case: the kind, the tag and each field name with its type text.
type Case = (
    RecordKind,
    &'static str,
    &'static [(&'static str, &'static str)],
);

/// The cases of the golden in golden order. A case without fields and with a prelude tag
/// uses the prelude record.
const CASES: &[Case] = &[
    (Struct, "s_char_int", &[("a", "char"), ("b", "int")]),
    (Struct, "s_int_char", &[("a", "int"), ("b", "char")]),
    (
        Struct,
        "s_mixed",
        &[("a", "char"), ("b", "double"), ("c", "short")],
    ),
    (
        Struct,
        "s_ll",
        &[("a", "char"), ("b", "long long"), ("c", "float")],
    ),
    (Struct, "s_ld", &[("a", "char"), ("b", "long double")]),
    (
        Struct,
        "s_i128",
        &[("a", "char"), ("b", "__int128"), ("c", "unsigned __int128")],
    ),
    (
        Struct,
        "s_bool",
        &[("a", "_Bool"), ("b", "short"), ("c", "_Bool")],
    ),
    (
        Struct,
        "s_ptr",
        &[("a", "char"), ("p", "void *"), ("b", "char")],
    ),
    (
        Struct,
        "s_arrays",
        &[("a", "char[3]"), ("b", "short[3]"), ("m", "int[2][3]")],
    ),
    (
        Struct,
        "s_nested",
        &[("a", "char"), ("b", "struct s_char_int"), ("c", "char")],
    ),
    (
        Struct,
        "s_quals",
        &[
            ("a", "const char"),
            ("b", "volatile int"),
            ("c", "const volatile long"),
            ("d", "char *const"),
        ],
    ),
    (
        Struct,
        "s_enum",
        &[("a", "char"), ("b", "enum e_small"), ("c", "char")],
    ),
    (Struct, "s_enum_big", &[("a", "char"), ("b", "enum e_big")]),
    (
        Union,
        "u_basic",
        &[("a", "char"), ("b", "int"), ("c", "double")],
    ),
    (Union, "u_arr", &[("a", "char[5]"), ("b", "int")]),
    (
        Union,
        "u_ld",
        &[("s", "struct s_char_int"), ("d", "long double")],
    ),
    (
        Struct,
        "s_union_member",
        &[("tag", "char"), ("v", "union u_basic")],
    ),
    (Struct, "s_fam", &[("n", "int"), ("data", "char[]")]),
    (Struct, "s_fam_align", &[("c", "char"), ("d", "double[]")]),
    (Struct, "s_empty", &[]),
    (Struct, "s_big", &[("big", "char[4096]"), ("x", "int")]),
    (
        Struct,
        "s_fnptr",
        &[
            ("a", "char"),
            ("cb", "void (*)(int)"),
            ("table", "int (*[2])(void)"),
        ],
    ),
    (
        Struct,
        "s_typedefs",
        &[
            ("a", "uint8_t"),
            ("b", "uint64_t"),
            ("c", "size_t"),
            ("d", "pid_t"),
        ],
    ),
    (Struct, "s_wchar", &[("a", "char"), ("w", "wchar_t")]),
    (
        Struct,
        "s_float",
        &[
            ("f", "float"),
            ("d", "double"),
            ("c", "char"),
            ("ld", "long double"),
        ],
    ),
    (Struct, "in_addr", &[]),
    (Struct, "sockaddr", &[]),
    (Struct, "sockaddr_in", &[]),
    (Struct, "timespec", &[]),
];

/// The prelude records of the cases.
const PRELUDE_TAGS: &[&str] = &["in_addr", "sockaddr", "sockaddr_in", "timespec"];

fn golden_path() -> PathBuf {
    root().join("tests/golden/types/sysv_layout.txt")
}

fn golden_header() -> Header {
    Header::new("ghidorah-types", "1")
        .with("gcc", "13.3.0")
        .with("clang", "18.1.3")
}

/// Builds the case records and gives their IDs in case order.
fn build(s: &mut TypeStore) -> Vec<TypeId> {
    let small = vec![
        Enumerator {
            name: "E_A".to_string(),
            value: 0,
        },
        Enumerator {
            name: "E_B".to_string(),
            value: 5,
        },
    ];
    s.define_enum(Some("e_small"), small).expect("e_small");
    let big = vec![Enumerator {
        name: "E_BIG".to_string(),
        value: 0x1_0000_0000,
    }];
    s.define_enum(Some("e_big"), big).expect("e_big");
    CASES
        .iter()
        .map(|(kind, tag, fields)| {
            if PRELUDE_TAGS.contains(tag) {
                return s.lookup_tag(tag).expect("prelude record");
            }
            let fields: Vec<Field> = fields
                .iter()
                .map(|(name, text)| Field::new(name, ty(s, text)))
                .collect();
            s.define_record(*kind, Some(tag), fields)
                .unwrap_or_else(|e| panic!("{tag}: {e}"))
        })
        .collect()
}

/// Gives the golden body: the layout text of each case and a blank line after it.
fn layout_text(s: &TypeStore, ids: &[TypeId]) -> String {
    let mut out = String::new();
    for id in ids {
        let l = layout::sysv(s, *id, &DataModel::X86_64_SYSV)
            .unwrap_or_else(|e| panic!("layout of {id:?}: {e}"));
        out.push_str(&render(s, *id, &l).expect("render"));
        out.push('\n');
    }
    out
}

#[test]
fn ac_112a_sysv_layout() {
    let mut s = store();
    let ids = build(&mut s);
    golden::assert_text(&golden_path(), &golden_header(), &layout_text(&s, &ids));
}

#[test]
fn layout_fields_give_offsets_and_sizes() {
    let mut s = store();
    let ids = build(&mut s);
    let fam = ids[17];
    let l = layout::sysv(&s, fam, &DataModel::X86_64_SYSV).expect("layout");
    assert_eq!((l.size, l.align), (4, 4));
    assert_eq!(l.fields.len(), 2);
    assert_eq!(
        (
            l.fields[1].name.as_str(),
            l.fields[1].offset,
            l.fields[1].size
        ),
        ("data", 4, 0)
    );
    let sin = s.lookup_tag("sockaddr_in").expect("tag");
    let l = layout::sysv(&s, sin, &DataModel::X86_64_SYSV).expect("layout");
    let sizes: Vec<u64> = l.fields.iter().map(|f| f.size).collect();
    assert_eq!(sizes, vec![2, 2, 4, 8]);
    let int = s.prim(Prim::Int);
    let l = layout::sysv(&s, int, &DataModel::X86_64_SYSV).expect("int");
    assert_eq!((l.size, l.align, l.fields.len()), (4, 4, 0));
}

#[test]
fn flexible_array_last_only() {
    let mut s = store();
    let int = s.prim(Prim::Int);
    let flex = ty(&mut s, "char[]");
    let ok = s
        .define_record(
            Struct,
            Some("ok"),
            vec![Field::new("n", int), Field::new("data", flex)],
        )
        .expect("a flexible member last");
    let l = layout::sysv(&s, ok, &DataModel::X86_64_SYSV).expect("layout");
    assert_eq!(l.size, 4);

    let before = s.clone();
    let err = s
        .define_record(
            Struct,
            Some("bad"),
            vec![Field::new("data", flex), Field::new("n", int)],
        )
        .expect_err("a flexible member first");
    assert_eq!(err, StoreError::FlexibleNotLast("data".to_string()));
    assert_eq!(err.diag(), DiagCode::IncompleteByValue);
    assert_eq!(s, before, "the store does not change");

    let err = s
        .define_record(Struct, Some("alone"), vec![Field::new("data", flex)])
        .expect_err("a flexible member alone");
    assert_eq!(err, StoreError::FlexibleNotLast("data".to_string()));
    let err = s
        .define_record(
            Union,
            Some("u"),
            vec![Field::new("n", int), Field::new("data", flex)],
        )
        .expect_err("a flexible member in a union");
    assert_eq!(err, StoreError::FlexibleNotLast("data".to_string()));

    let text = "struct { char d[]; int n; }";
    let err = parse_type(&mut s, text).expect_err("parsed flexible member first");
    assert_diag(text, &err, DiagCode::IncompleteByValue, offset(text, "d[]"));
    let text = "struct { int n; char d[]; }";
    let id = ty(&mut s, text);
    let l = layout::sysv(&s, id, &DataModel::X86_64_SYSV).expect("layout");
    assert_eq!((l.size, l.fields[1].offset), (4, 4));
    let err = layout::sysv(&s, flex, &DataModel::X86_64_SYSV).expect_err("bare []");
    assert_eq!(err, LayoutError::Incomplete(flex));
}

#[test]
fn cycle_by_value_rejected() {
    let mut s = store();
    let node = s.declare(TagKind::Struct, "node").expect("declare");
    let by_ptr = s.ptr(node).expect("pointer");
    let alias = s.typedef("node_t", node).expect("typedef");
    let arr = s.array(alias, Some(2));
    assert_eq!(
        arr,
        Err(StoreError::IncompleteElement(alias)),
        "an array of an incomplete record"
    );
    let before = s.clone();
    for (field, ty) in [("self", node), ("alias", alias)] {
        let err = s
            .define_record(Struct, Some("node"), vec![Field::new(field, ty)])
            .expect_err(field);
        assert_eq!(
            err,
            StoreError::IncompleteByValue {
                field: field.to_string(),
                ty
            }
        );
        assert_eq!(err.diag(), DiagCode::IncompleteByValue);
        assert_eq!(s, before, "the store does not change");
    }
    let id = s
        .define_record(Struct, Some("node"), vec![Field::new("next", by_ptr)])
        .expect("a pointer to itself");
    assert_eq!(id, node);
    let l = layout::sysv(&s, node, &DataModel::X86_64_SYSV).expect("layout");
    assert_eq!(l.size, 8);

    let text = "struct list { struct list next; }";
    let before = s.clone();
    let err = parse_type(&mut s, text).expect_err("parsed self by value");
    assert_diag(
        text,
        &err,
        DiagCode::IncompleteByValue,
        offset(text, "next"),
    );
    assert_eq!(s, before);
    let text = "struct a { struct b { struct a x; } y; }";
    let err = parse_type(&mut s, text).expect_err("parsed mutual cycle");
    assert_diag(text, &err, DiagCode::IncompleteByValue, offset(text, "x;"));
    let text = "struct c { struct c v[2]; }";
    let err = parse_type(&mut s, text).expect_err("parsed array of itself");
    assert_diag(text, &err, DiagCode::IncompleteByValue, offset(text, "[2]"));
}

#[test]
fn layout_errors() {
    let mut s = store();
    let m = DataModel::X86_64_SYSV;
    let void = s.prim(Prim::Void);
    assert_eq!(
        layout::sysv(&s, void, &m),
        Err(LayoutError::Incomplete(void))
    );
    let stat = s.lookup_tag("stat").expect("opaque tag");
    assert_eq!(
        layout::sysv(&s, stat, &m),
        Err(LayoutError::Incomplete(stat))
    );
    let f = ty(&mut s, "int (int)");
    assert_eq!(layout::sysv(&s, f, &m), Err(LayoutError::NotObject(f)));
    let big = ty(&mut s, "long[0x1000000000000000]");
    assert_eq!(layout::sysv(&s, big, &m), Err(LayoutError::Overflow(big)));
    let unknown = TypeId::from_index(u32::MAX);
    assert_eq!(
        layout::sysv(&s, unknown, &m),
        Err(LayoutError::UnknownId(unknown))
    );
    let inner = ty(&mut s, "long[0x100000000]");
    let outer = s.array(inner, Some(0x1000_0000)).expect("array");
    assert_eq!(
        layout::sysv(&s, outer, &m),
        Err(LayoutError::Overflow(outer))
    );
}

#[test]
fn layout_error_text_and_codes() {
    let e = LayoutError::Incomplete(TypeId::from_index(3));
    assert!(e.to_string().contains("incomplete"), "{e}");
    assert_eq!(e.code(), ghidorah_base::ErrorCode::InvalidArgument);
    for e in [
        LayoutError::UnknownId(TypeId::from_index(1)),
        LayoutError::NotObject(TypeId::from_index(1)),
        LayoutError::Overflow(TypeId::from_index(1)),
        LayoutError::Depth,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn layout_of_deep_typedef_chains_stops() {
    let mut s = TypeStore::new();
    let mut id = s.prim(Prim::Int);
    for i in 0..300 {
        id = s.typedef(&format!("t{i}"), id).expect("typedef");
    }
    assert_eq!(
        layout::sysv(&s, id, &DataModel::X86_64_SYSV),
        Err(LayoutError::Depth)
    );
    assert_eq!(s.resolve(id), Err(StoreError::Depth));
}

#[test]
fn layout_memo_handles_wide_records() {
    let mut s = TypeStore::new();
    let mut id = s.prim(Prim::Char);
    for i in 0..40 {
        let fields = (0..8).map(|k| Field::new(&format!("f{k}"), id)).collect();
        id = s
            .define_record(Struct, Some(&format!("w{i}")), fields)
            .expect("record");
    }
    let err = layout::sysv(&s, id, &DataModel::X86_64_SYSV).expect_err("8^40 bytes");
    let first_too_big = s.lookup_tag("w20").expect("tag");
    assert_eq!(err, LayoutError::Overflow(first_too_big));
    let small = s.lookup_tag("w5").expect("tag");
    let l = layout::sysv(&s, small, &DataModel::X86_64_SYSV).expect("8^6 bytes");
    assert_eq!(l.size, 8u64.pow(6));
}

/// Writes the C declarations that the type `id` needs, in dependency order.
fn emit_deps(s: &TypeStore, id: TypeId, seen: &mut BTreeSet<TypeId>, out: &mut String) {
    if !seen.insert(id) {
        return;
    }
    match s.get(id).expect("type") {
        Type::Prim(_) => {}
        Type::Ptr(to) => {
            if let Some(Type::Record(r)) = s.get(*to)
                && let Some(tag) = &r.name
            {
                out.push_str(&format!("{} {tag};\n", r.kind.keyword()));
            } else {
                emit_deps(s, *to, seen, out);
            }
        }
        Type::Array { elem, .. } => emit_deps(s, *elem, seen, out),
        Type::Qual { inner, .. } => emit_deps(s, *inner, seen, out),
        Type::Typedef { target, .. } => {
            emit_deps(s, *target, seen, out);
            out.push_str(&s.c_definition(id).expect("definition"));
            out.push('\n');
        }
        Type::Record(r) => {
            for f in &r.fields {
                emit_deps(s, f.ty, seen, out);
            }
            if r.name.is_some() {
                out.push_str(&s.c_definition(id).expect("definition"));
                out.push('\n');
            }
        }
        Type::Enum(e) => {
            if e.name.is_some() {
                out.push_str(&s.c_definition(id).expect("definition"));
                out.push('\n');
            }
        }
        Type::Func(sig) => {
            emit_deps(s, sig.ret, seen, out);
            for p in &sig.params {
                emit_deps(s, p.ty, seen, out);
            }
        }
    }
}

/// Makes a C program that prints the golden body with `sizeof`, `_Alignof` and `offsetof`.
fn oracle_program(s: &TypeStore, ids: &[TypeId]) -> String {
    let mut out = String::from("int printf(const char *, ...);\ntypedef int wchar_t;\n");
    let mut seen = BTreeSet::new();
    for id in ids {
        emit_deps(s, *id, &mut seen, &mut out);
    }
    out.push_str("int main(void) {\n");
    for id in ids {
        let t = s.c_text(*id).expect("text");
        out.push_str(&format!(
            "  printf(\"{t} size=%zu align=%zu\\n\", sizeof({t}), _Alignof({t}));\n"
        ));
        if let Some(Type::Record(r)) = s.get(*id) {
            for f in &r.fields {
                let decl = s.c_decl(f.ty, &f.name).expect("decl");
                out.push_str(&format!(
                    "  printf(\"+0x%zx {decl}\\n\", __builtin_offsetof({t}, {}));\n",
                    f.name
                ));
            }
        }
        out.push_str("  printf(\"\\n\");\n");
    }
    out.push_str("  return 0;\n}\n");
    out
}

fn run_oracle(compiler: &str, program: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ghidorah-layout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("layout.c");
    let exe = dir.join(format!("layout-{compiler}"));
    std::fs::write(&src, program).expect("write the program");
    let status = Command::new(compiler)
        .args(["-std=gnu11", "-w", "-o"])
        .arg(&exe)
        .arg(&src)
        .status()
        .expect("the compiler runs");
    assert!(status.success(), "{compiler} compiles the oracle program");
    let out = Command::new(&exe).output().expect("the oracle runs");
    String::from_utf8(out.stdout).expect("text")
}

#[test]
#[ignore = "tier2"]
fn ac_112a_layout_oracle_gcc_clang() {
    let mut s = store();
    let ids = build(&mut s);
    let program = oracle_program(&s, &ids);
    let (_, body) = golden::read(&golden_path()).expect("golden");
    for compiler in ["gcc", "clang"] {
        assert_eq!(run_oracle(compiler, &program), body, "{compiler}");
    }
}
