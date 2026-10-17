//! The type store, the canonical C text and the type references (design Section 9.1).

use ghidorah_base::{DiagCode, ErrorCode, TypeRef, fnv1a64};
use ghidorah_types::prelude;
use ghidorah_types::{
    Enumerator, Field, Param, Prim, Quals, RecordKind, Sig, StoreError, TagKind, Type, TypeId,
    TypeStore, cc,
};

use crate::support::{store, ty};

#[test]
fn new_store_holds_the_primitive_types() {
    let s = TypeStore::new();
    assert_eq!(s.len(), Prim::ALL.len());
    assert!(!s.is_empty());
    for (i, prim) in Prim::ALL.into_iter().enumerate() {
        let id = s.prim(prim);
        assert_eq!(id.index() as usize, i);
        assert_eq!(s.get(id), Some(&Type::Prim(prim)));
        assert_eq!(Prim::from_c_name(prim.c_name()), Some(prim));
    }
    assert_eq!(s.ids().count(), s.len());
    assert_eq!(TypeStore::default(), s);
    assert!(s.get(TypeId::from_index(999)).is_none());
}

#[test]
fn derived_types_get_one_id() {
    let mut s = TypeStore::new();
    let int = s.prim(Prim::Int);
    let p1 = s.ptr(int).expect("ptr");
    let p2 = s.ptr(int).expect("ptr again");
    assert_eq!(p1, p2);
    let a1 = s.array(int, Some(4)).expect("array");
    assert_eq!(s.array(int, Some(4)), Ok(a1));
    assert_ne!(s.array(int, Some(5)), Ok(a1));
    let c = s.qual(Quals::CONST, int).expect("const");
    assert_eq!(s.qual(Quals::NONE, int), Ok(int));
    let volatile = Quals {
        is_volatile: true,
        ..Quals::NONE
    };
    let cv = s.qual(volatile, c).expect("const volatile");
    assert_eq!(
        s.get(cv),
        Some(&Type::Qual {
            quals: Quals::CONST.union(volatile),
            inner: int
        })
    );
    let sig = Sig {
        ret: int,
        params: vec![Param { name: None, ty: p1 }],
        variadic: false,
        cc: None,
        noreturn: false,
    };
    let f1 = s.func(sig.clone()).expect("func");
    assert_eq!(s.func(sig), Ok(f1));
}

#[test]
fn store_rejects_bad_parts() {
    let mut s = TypeStore::new();
    let int = s.prim(Prim::Int);
    let void = s.prim(Prim::Void);
    let bad = TypeId::from_index(77_777);
    assert_eq!(s.ptr(bad), Err(StoreError::UnknownId(bad)));
    assert_eq!(s.array(bad, None), Err(StoreError::UnknownId(bad)));
    assert_eq!(s.qual(Quals::CONST, bad), Err(StoreError::UnknownId(bad)));
    assert_eq!(s.typedef("x", bad), Err(StoreError::UnknownId(bad)));
    assert_eq!(
        s.array(void, Some(1)),
        Err(StoreError::IncompleteElement(void))
    );
    let open = s.array(int, None).expect("int []");
    assert_eq!(
        s.array(open, Some(2)),
        Err(StoreError::IncompleteElement(open))
    );
    let sig = |ret, params: Vec<TypeId>| Sig {
        ret,
        params: params
            .into_iter()
            .map(|ty| Param { name: None, ty })
            .collect(),
        variadic: false,
        cc: None,
        noreturn: false,
    };
    let f = s.func(sig(int, vec![])).expect("int (void)");
    assert_eq!(s.array(f, Some(2)), Err(StoreError::BadPart(f)));
    let arr = s.array(int, Some(2)).expect("int [2]");
    assert_eq!(s.func(sig(arr, vec![])), Err(StoreError::BadPart(arr)));
    assert_eq!(s.func(sig(f, vec![])), Err(StoreError::BadPart(f)));
    assert_eq!(s.func(sig(int, vec![void])), Err(StoreError::BadPart(void)));
    assert_eq!(s.func(sig(bad, vec![])), Err(StoreError::UnknownId(bad)));
    let named = Sig {
        ret: int,
        params: vec![
            Param {
                name: Some("a".to_string()),
                ty: int,
            },
            Param {
                name: Some("a".to_string()),
                ty: int,
            },
        ],
        variadic: false,
        cc: None,
        noreturn: false,
    };
    assert_eq!(
        s.func(named),
        Err(StoreError::DuplicateMember("a".to_string()))
    );
    let many = sig(int, vec![int; ghidorah_types::store::MAX_MEMBERS + 1]);
    assert_eq!(s.func(many), Err(StoreError::TooManyMembers));
}

#[test]
fn names_and_tags() {
    let mut s = TypeStore::new();
    let int = s.prim(Prim::Int);
    let long = s.prim(Prim::Long);
    let t = s.typedef("myint", int).expect("typedef");
    assert_eq!(s.typedef("myint", int), Ok(t));
    assert_eq!(
        s.typedef("myint", long),
        Err(StoreError::Duplicate("myint".to_string()))
    );
    for bad in ["", "1x", "a b", "a-b", &"x".repeat(1025)] {
        assert_eq!(
            s.typedef(bad, int),
            Err(StoreError::BadName(bad.to_string())),
            "{bad:?}"
        );
    }
    assert_eq!(s.lookup_typedef("myint"), Some(t));
    let st = s.declare(TagKind::Struct, "pt").expect("declare");
    assert_eq!(s.declare(TagKind::Struct, "pt"), Ok(st));
    assert_eq!(
        s.declare(TagKind::Union, "pt"),
        Err(StoreError::KindMismatch {
            name: "pt".to_string(),
            have: TagKind::Struct
        })
    );
    assert!(!s.is_complete(st));
    let fields = vec![Field::new("x", int), Field::new("y", int)];
    let done = s
        .define_record(RecordKind::Struct, Some("pt"), fields.clone())
        .expect("define");
    assert_eq!(done, st, "the definition completes the declared tag");
    assert!(s.is_complete(st));
    assert_eq!(
        s.define_record(RecordKind::Struct, Some("pt"), fields),
        Ok(st)
    );
    assert_eq!(
        s.define_record(RecordKind::Struct, Some("pt"), vec![Field::new("x", int)]),
        Err(StoreError::Duplicate("pt".to_string()))
    );
    assert_eq!(
        s.define_record(RecordKind::Union, Some("pt"), vec![]),
        Err(StoreError::KindMismatch {
            name: "pt".to_string(),
            have: TagKind::Struct
        })
    );
    assert_eq!(
        s.define_record(
            RecordKind::Struct,
            Some("dup"),
            vec![Field::new("x", int), Field::new("x", int)]
        ),
        Err(StoreError::DuplicateMember("x".to_string()))
    );
    assert_eq!(
        s.define_record(
            RecordKind::Struct,
            Some("nameless"),
            vec![Field::new("", int)]
        ),
        Err(StoreError::BadName(String::new()))
    );
    let e = s.declare(TagKind::Enum, "color").expect("enum");
    let items = vec![Enumerator {
        name: "RED".to_string(),
        value: 1,
    }];
    assert_eq!(s.define_enum(Some("color"), items.clone()), Ok(e));
    assert_eq!(s.define_enum(Some("color"), items), Ok(e));
    assert_eq!(
        s.define_enum(Some("color"), vec![]),
        Err(StoreError::Duplicate("color".to_string()))
    );
    assert_eq!(
        s.define_enum(Some("pt"), vec![]),
        Err(StoreError::KindMismatch {
            name: "pt".to_string(),
            have: TagKind::Struct
        })
    );
    let twice = vec![
        Enumerator {
            name: "A".to_string(),
            value: 0,
        },
        Enumerator {
            name: "A".to_string(),
            value: 1,
        },
    ];
    assert_eq!(
        s.define_enum(None, twice),
        Err(StoreError::DuplicateMember("A".to_string()))
    );
    let anon1 = s
        .define_record(RecordKind::Union, None, vec![Field::new("i", int)])
        .expect("anonymous");
    let anon2 = s
        .define_record(RecordKind::Union, None, vec![Field::new("i", int)])
        .expect("anonymous again");
    assert_eq!(
        anon1, anon2,
        "records without a tag and with equal fields share an ID"
    );
    let tags: Vec<&str> = s.tag_names().collect();
    assert_eq!(tags, vec!["color", "pt"]);
    let defs: Vec<&str> = s.typedef_names().collect();
    assert_eq!(defs, vec!["myint"]);
    assert_eq!(s.lookup_tag("pt"), Some(st));
    assert_eq!(s.lookup_tag("nope"), None);
}

#[test]
fn resolve_and_completeness() {
    let mut s = store();
    let size_t = s.lookup_typedef("size_t").expect("size_t");
    assert_eq!(s.resolve(size_t), Ok(s.prim(Prim::ULong)));
    let c = ty(&mut s, "const size_t");
    assert_eq!(s.resolve(c), Ok(s.prim(Prim::ULong)));
    for (text, complete) in [
        ("int", true),
        ("void", false),
        ("int []", false),
        ("int [2]", true),
        ("struct stat", false),
        ("struct stat *", true),
        ("FILE", false),
        ("va_list", true),
        ("int (int)", false),
        ("enum { A }", true),
    ] {
        let id = ty(&mut s, text);
        assert_eq!(s.is_complete(id), complete, "{text}");
    }
    let bad = TypeId::from_index(1 << 30);
    assert!(!s.is_complete(bad));
    assert_eq!(s.resolve(bad), Err(StoreError::UnknownId(bad)));
}

#[test]
fn type_refs_round_trip() {
    let mut s = store();
    for text in [
        "int",
        "unsigned long",
        "size_t",
        "struct sockaddr_in",
        "struct sockaddr_in *",
        "const char *",
        "int (*)(void)",
        "union { int a; }",
        "FILE",
        "enum { Q = 3 }",
    ] {
        let id = ty(&mut s, text);
        let r = s.type_ref(id).expect("ref");
        let got = s.by_ref(&r).expect("found");
        assert_eq!(
            s.c_text(got).expect("text"),
            s.c_text(id).expect("text"),
            "{text}"
        );
    }
    let sin = s.lookup_tag("sockaddr_in").expect("tag");
    assert_eq!(s.type_ref(sin).expect("ref").to_string(), "t:sockaddr_in");
    let int = s.prim(Prim::Int);
    assert_eq!(s.type_ref(int).expect("ref").to_string(), "t:int");
    let p = ty(&mut s, "const char *");
    let want = TypeRef::anon(fnv1a64(b"const char *"));
    assert_eq!(s.type_ref(p), Ok(want.clone()));
    assert_eq!(s.by_ref(&want), Some(p));
    assert_eq!(s.by_ref(&TypeRef::anon(1)), None);
    assert_eq!(s.by_ref(&TypeRef::named("nothing").expect("name")), None);
    let fd_set = s.lookup_typedef("fd_set").expect("fd_set");
    assert_eq!(
        s.by_ref(&TypeRef::named("fd_set").expect("name")),
        Some(fd_set)
    );
    let bad = TypeId::from_index(u32::MAX);
    assert_eq!(s.type_ref(bad), Err(StoreError::UnknownId(bad)));
}

#[test]
fn c_text_declarations_and_definitions() {
    let mut s = store();
    let cases = [
        ("char *[]", "argv", "char *argv[]"),
        ("int", "x", "int x"),
        ("void (*)(int)", "handler", "void (*handler)(int)"),
        ("int (*)[4]", "rows", "int (*rows)[4]"),
        ("const char *const", "p", "const char *const p"),
    ];
    for (text, name, want) in cases {
        let id = ty(&mut s, text);
        assert_eq!(s.c_decl(id, name).expect("decl"), want);
    }
    let size_t = s.lookup_typedef("size_t").expect("size_t");
    assert_eq!(
        s.c_definition(size_t).expect("def"),
        "typedef unsigned long size_t;"
    );
    let handler = s.lookup_typedef("sighandler_t").expect("typedef");
    assert_eq!(
        s.c_definition(handler).expect("def"),
        "typedef __sighandler_t sighandler_t;"
    );
    let jb = s.lookup_typedef("jmp_buf").expect("jmp_buf");
    assert_eq!(
        s.c_definition(jb).expect("def"),
        "typedef struct __jmp_buf_tag jmp_buf[1];"
    );
    let stat = s.lookup_tag("stat").expect("stat");
    assert_eq!(s.c_definition(stat).expect("def"), "struct stat;");
    let int = s.prim(Prim::Int);
    assert_eq!(s.c_definition(int).expect("def"), "int;");
    let e = ty(&mut s, "enum { A, B }");
    assert_eq!(s.c_definition(e).expect("def"), "enum { A = 0, B = 1 };");
    let empty = ty(&mut s, "struct empty_rec { }");
    assert_eq!(s.c_text(empty).expect("text"), "struct empty_rec");
    assert_eq!(s.c_definition(empty).expect("def"), "struct empty_rec { };");
    let f = s
        .func(Sig {
            ret: int,
            params: vec![],
            variadic: true,
            cc: Some(&cc::SYSV_X86_64),
            noreturn: true,
        })
        .expect("func");
    assert_eq!(s.c_text(f).expect("text"), "_Noreturn int (...)");
}

#[test]
fn c_text_limits() {
    let mut s = TypeStore::new();
    let mut id = s.prim(Prim::Char);
    for _ in 0..300 {
        id = s.array(id, Some(1)).expect("array");
    }
    assert_eq!(s.c_text(id), Err(StoreError::Depth));
    let mut wide = s.prim(Prim::Char);
    for _ in 0..30 {
        let fields = vec![Field::new("a", wide), Field::new("b", wide)];
        wide = s
            .define_record(RecordKind::Struct, None, fields)
            .expect("record");
    }
    assert_eq!(s.c_text(wide), Err(StoreError::TextLimit));
    assert!(s.type_ref(wide).is_err());
}

#[test]
fn store_error_codes_and_text() {
    let id = TypeId::from_index(4);
    let cases = [
        (
            StoreError::UnknownId(id),
            DiagCode::UnknownType,
            ErrorCode::NotFound,
        ),
        (StoreError::Full, DiagCode::Limit, ErrorCode::LimitExceeded),
        (
            StoreError::BadName("1".to_string()),
            DiagCode::Syntax,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::Duplicate("x".to_string()),
            DiagCode::Syntax,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::KindMismatch {
                name: "x".to_string(),
                have: TagKind::Enum,
            },
            DiagCode::UnknownType,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::DuplicateMember("x".to_string()),
            DiagCode::Syntax,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::IncompleteByValue {
                field: "x".to_string(),
                ty: id,
            },
            DiagCode::IncompleteByValue,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::FlexibleNotLast("x".to_string()),
            DiagCode::IncompleteByValue,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::IncompleteElement(id),
            DiagCode::IncompleteByValue,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::BadPart(id),
            DiagCode::Syntax,
            ErrorCode::InvalidArgument,
        ),
        (
            StoreError::TooManyMembers,
            DiagCode::Limit,
            ErrorCode::LimitExceeded,
        ),
        (StoreError::Depth, DiagCode::Limit, ErrorCode::LimitExceeded),
        (
            StoreError::TextLimit,
            DiagCode::Limit,
            ErrorCode::LimitExceeded,
        ),
    ];
    for (e, diag, code) in cases {
        assert_eq!(e.diag(), diag, "{e:?}");
        assert_eq!(e.code(), code, "{e:?}");
        let text = e.to_string();
        assert!(!text.is_empty() && !text.contains("StoreError"), "{text}");
    }
}

#[test]
fn prelude_installs_every_item() {
    let s = store();
    let names: Vec<&str> = prelude::names().collect();
    assert!(names.len() >= 60, "{} prelude names", names.len());
    for name in &names {
        assert!(
            s.lookup_typedef(name).is_some() || s.lookup_tag(name).is_some(),
            "{name}"
        );
    }
    for name in [
        "uint8_t",
        "int64_t",
        "size_t",
        "ssize_t",
        "off_t",
        "FILE",
        "pid_t",
        "socklen_t",
        "va_list",
    ] {
        assert!(s.lookup_typedef(name).is_some(), "{name}");
    }
    for tag in ["sockaddr", "sockaddr_in", "in_addr", "timespec"] {
        let id = s.lookup_tag(tag).expect(tag);
        assert!(s.is_complete(id), "{tag}");
    }
    let file = s.lookup_typedef("FILE").expect("FILE");
    assert!(!s.is_complete(file), "FILE is opaque");
    let mut again = s.clone();
    assert_eq!(
        prelude::install(&mut again),
        Ok(()),
        "a second install is a no-op"
    );
    assert_eq!(again, s);
    let mut clash = TypeStore::new();
    let int = clash.prim(Prim::Int);
    clash.typedef("size_t", int).expect("typedef");
    let err = prelude::install(&mut clash).expect_err("size_t clash");
    assert!(err.to_string().contains("size_t"), "{err}");
}
