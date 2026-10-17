//! AC-109: the Tier-0 prototypes (design Section 9.4).

use std::collections::BTreeSet;

use ghidorah_types::proto::builtin;
use ghidorah_types::{
    Category, Effect, Fmt, FmtKind, Prim, Tier0, Tier0Error, Type, TypeStore, parse_sig,
};

use crate::support::store;

/// Tells if the parameter `index` (from 1) of `proto` is a pointer.
fn is_pointer(store: &TypeStore, ty: ghidorah_types::TypeId) -> bool {
    let id = store.resolve(ty).expect("resolve");
    matches!(store.get(id), Some(Type::Ptr(_)))
}

#[test]
fn ac_109_tier0_parse() {
    let db = builtin().unwrap_or_else(|e| panic!("tier0.h: {e}"));
    assert!(db.len() >= 150, "{} prototypes", db.len());
    let mut names = BTreeSet::new();
    for proto in db.protos() {
        assert!(names.insert(proto.name.clone()), "{} twice", proto.name);
        let mut s = store();
        let parsed = parse_sig(&mut s, &proto.text)
            .unwrap_or_else(|e| panic!("`{}` does not parse in sig mode: {e}", proto.text));
        assert_eq!(parsed.name, proto.name);
        assert_eq!(
            s.c_text(parsed.ty).expect("text"),
            db.store().c_text(proto.ty).expect("text"),
            "{}",
            proto.name
        );
        assert_eq!(parsed.sig.params.len(), proto.sig.params.len());
        assert_eq!(db.get(&proto.name), Some(proto));
        for alias in &proto.aliases {
            assert_eq!(db.get(alias).map(|p| &p.name), Some(&proto.name), "{alias}");
        }
    }
}

#[test]
fn tier0_attributes_name_real_parameters() {
    let db = builtin().expect("tier0");
    let s = db.store();
    for proto in db.protos() {
        let n = proto.sig.params.len();
        let param = |i: u16| {
            let k = usize::from(i);
            assert!(k >= 1 && k <= n, "{}: parameter {i} of {n}", proto.name);
            proto.sig.params[k - 1].ty
        };
        if let Some(fmt) = proto.attrs.fmt {
            assert!(is_pointer(s, param(fmt.index)), "{} fmt", proto.name);
        }
        for i in &proto.attrs.nonnull {
            assert!(is_pointer(s, param(*i)), "{} nonnull({i})", proto.name);
        }
        for e in &proto.attrs.effects {
            match *e {
                Effect::ReadsStr(i) => assert!(is_pointer(s, param(i)), "{}", proto.name),
                Effect::Writes { arg, len_arg } => {
                    assert!(is_pointer(s, param(arg)), "{}", proto.name);
                    if let Some(l) = len_arg {
                        let id = s.resolve(param(l)).expect("resolve");
                        assert!(
                            matches!(s.get(id), Some(Type::Prim(p)) if p.is_integer()),
                            "{} writes length",
                            proto.name
                        );
                    }
                }
                Effect::ReturnsArg(i) => {
                    param(i);
                }
                Effect::Allocates => {
                    assert!(is_pointer(s, proto.sig.ret) || n > 0, "{}", proto.name);
                }
            }
        }
        assert_eq!(proto.attrs.noreturn, proto.sig.noreturn, "{}", proto.name);
    }
}

#[test]
fn tier0_lookup_by_linked_name() {
    let db = builtin().expect("tier0");
    let puts = db.get("puts").expect("puts");
    assert_eq!(puts.category, Category::Io);
    assert_eq!(db.get("puts@GLIBC_2.2.5"), Some(puts));
    assert_eq!(db.get("puts@@GLIBC_2.2.5"), Some(puts));
    assert_eq!(
        db.get("__isoc23_scanf").map(|p| p.name.as_str()),
        Some("scanf")
    );
    assert_eq!(
        db.get("__isoc99_sscanf").map(|p| p.name.as_str()),
        Some("sscanf")
    );
    assert_eq!(db.get("open64").map(|p| p.name.as_str()), Some("open"));
    assert_eq!(db.get("fopen64").map(|p| p.name.as_str()), Some("fopen"));
    let chk = db.get("__printf_chk").expect("__printf_chk");
    assert_eq!(chk.sig.params.len(), 2);
    assert_eq!(
        chk.attrs.fmt,
        Some(Fmt {
            kind: FmtKind::Printf,
            index: 2
        })
    );
    assert!(db.get("no_such_function").is_none());
    assert!(db.get("").is_none());
    assert_eq!(
        db.get("ptrace").map(|p| p.category),
        Some(Category::AntiDebug)
    );
    let exit = db.get("exit").expect("exit");
    assert!(exit.attrs.noreturn && exit.sig.noreturn);
    let memcpy = db.get("memcpy").expect("memcpy");
    assert_eq!(memcpy.attrs.nonnull, vec![1, 2]);
    assert_eq!(
        memcpy.attrs.effects,
        vec![
            Effect::Writes {
                arg: 1,
                len_arg: Some(3)
            },
            Effect::ReturnsArg(1)
        ]
    );
    let malloc = db.get("malloc").expect("malloc");
    assert_eq!(malloc.attrs.effects, vec![Effect::Allocates]);
    let names: Vec<&str> = db.names().collect();
    assert!(names.windows(2).all(|w| w[0] < w[1]), "names in byte order");
    assert!(names.contains(&"__isoc23_fscanf"));
    let used: BTreeSet<Category> = db.protos().iter().map(|p| p.category).collect();
    assert_eq!(
        used.len(),
        Category::ALL.len(),
        "every category has a prototype"
    );
}

#[test]
fn tier0_complex_declarators() {
    let db = builtin().expect("tier0");
    let s = db.store();
    let signal = db.get("signal").expect("signal");
    assert_eq!(
        s.c_text(signal.sig.ret).expect("text"),
        "void (*)(int)",
        "signal returns a handler"
    );
    let start = db.get("__libc_start_main").expect("start");
    assert_eq!(start.sig.params.len(), 7);
    assert_eq!(
        s.c_text(start.sig.params[0].ty).expect("text"),
        "int (*)(int, char **, char **)"
    );
    let inet_ntoa = db.get("inet_ntoa").expect("inet_ntoa");
    assert_eq!(
        s.c_text(inet_ntoa.sig.params[0].ty).expect("text"),
        "struct in_addr"
    );
    let longjmp = db.get("longjmp").expect("longjmp");
    assert_eq!(
        s.c_text(longjmp.sig.params[0].ty).expect("text"),
        "struct __jmp_buf_tag *"
    );
    let getchar = db.get("getchar").expect("getchar");
    assert_eq!(getchar.sig.ret, s.prim(Prim::Int));
    assert!(getchar.sig.params.is_empty());
}

#[test]
fn category_names_round_trip() {
    for c in Category::ALL {
        assert_eq!(Category::from_name(c.name()), Some(c));
    }
    assert_eq!(Category::from_name("disk"), None);
}

/// Bad Tier-0 texts and the error line.
#[test]
fn tier0_errors() {
    let bad_c = "int puts(const chr *s); // io\n";
    match Tier0::parse(bad_c) {
        Err(Tier0Error::Parse { line: 1, error }) => {
            assert!(error.to_string().contains("E_UNKNOWN_TYPE"), "{error}");
        }
        other => panic!("{other:?}"),
    }
    let cases: &[(&str, u32)] = &[
        ("int puts(const char *s); // disk\n", 1),
        ("/* header\n */\nint puts(const char *s);\n", 3),
        ("int puts(const char *s) // io\n", 1),
        ("int puts(const char *s); // io fmt(printf,2)\n", 1),
        ("int puts(const char *s); // io fmt(pascal,1)\n", 1),
        ("int puts(const char *s); // io nonnull(0)\n", 1),
        ("int puts(const char *s); // io writes(1,2)\n", 1),
        ("int puts(const char *s); // io reads_str(x)\n", 1),
        ("int puts(const char *s); // io colour\n", 1),
        ("int puts(const char *s); // io io\n", 1),
        ("int puts(const char *s); // io alias(\n", 1),
        ("int puts(const char *s); // io noreturn\n", 1),
    ];
    for (text, line) in cases {
        match Tier0::parse(text) {
            Err(Tier0Error::Attr { line: l, .. }) => assert_eq!(l, *line, "{text}"),
            other => panic!("`{text}`: {other:?}"),
        }
    }
    let dup = "int puts(const char *s); // io\nint puts(const char *s); // io\n";
    assert!(matches!(
        Tier0::parse(dup),
        Err(Tier0Error::Duplicate { line: 2, .. })
    ));
    let dup_alias = "int puts(const char *s); // io alias(putz)\nint putz(int c); // io\n";
    assert!(matches!(
        Tier0::parse(dup_alias),
        Err(Tier0Error::Duplicate { line: 2, .. })
    ));
    let one = Tier0::parse("_Noreturn void f(void); // process noreturn\n").expect("one");
    assert_eq!(one.len(), 1);
    assert!(!one.is_empty());
    let empty = Tier0::parse("// only a comment\n\n").expect("empty");
    assert!(empty.is_empty());
    for e in [
        Tier0Error::Prelude("x".to_string()),
        Tier0Error::Attr {
            line: 4,
            word: "w".to_string(),
        },
        Tier0Error::Duplicate {
            line: 5,
            name: "n".to_string(),
        },
    ] {
        assert!(e.to_string().contains("tier0.h"), "{e}");
    }
}
