//! Language hints of `binary_survey.languages`.

use ghidorah_analysis::analyzers::lang::{self, HINT, Lang, LangHint};
use ghidorah_testkit::elf::{ElfBuilder, ImportKind, Loc, Section, Symbol};

use crate::support::{built, program};

#[test]
fn classify_names() {
    let cases = [
        ("_ZN3foo3barEv", Some(Lang::Cpp)),
        ("_Z4mainv", Some(Lang::Cpp)),
        ("__cxa_atexit", Some(Lang::Cpp)),
        ("__gxx_personality_v0", Some(Lang::Cpp)),
        ("_ZN4core3fmt5write17h0123456789abcdefE", Some(Lang::Rust)),
        ("_ZN4core3fmt5write17h0123456789abcdeE", Some(Lang::Cpp)),
        ("_RNvCs1234_7mycrate3foo", Some(Lang::Rust)),
        ("rust_panic", Some(Lang::Rust)),
        (
            "_ZN3std9panicking11rust_panic17hffffffffffffffffE",
            Some(Lang::Rust),
        ),
        ("rust_begin_unwind", Some(Lang::Rust)),
        ("runtime.main", Some(Lang::Go)),
        ("runtime", None),
        ("main", None),
        ("_start", None),
        ("puts", None),
        ("", None),
    ];
    for (name, lang) in cases {
        assert_eq!(lang::classify(name), lang, "{name}");
    }
    assert_eq!(lang::section_lang(".gopclntab"), Some(Lang::Go));
    assert_eq!(lang::section_lang(".go.buildinfo"), Some(Lang::Go));
    assert_eq!(lang::section_lang(".note.go.buildid"), Some(Lang::Go));
    assert_eq!(lang::section_lang(".text"), None);
    assert_eq!(
        Lang::ALL.map(Lang::name),
        ["c++", "rust", "go"],
        "the output names"
    );
    assert!(HINT.ends_with('.'));
}

#[test]
fn hints_count_names_and_sections() {
    let code = Section::code(".text", &[0xc3; 16]);
    let at = |off| Loc::section(".text", off);
    let b = ElfBuilder::exec()
        .section(code)
        .section(Section::rodata(".gopclntab", &[0xfb, 0xff, 0xff, 0xff]))
        .symbol(Symbol::func("_ZN3foo3barEv", at(0), 1))
        .symbol(Symbol::func("_ZN3foo3bazEv", at(1), 1))
        .symbol(Symbol::func("_ZN3foo3bazEv", at(1), 1).local())
        .symbol(Symbol::func(
            "_ZN4core3fmt5write17h0123456789abcdefE",
            at(2),
            1,
        ))
        .symbol(Symbol::func("_RNvC3foo3bar", at(3), 1))
        .symbol(Symbol::func("runtime.main", at(4), 1))
        .symbol(Symbol::func("main", at(5), 1))
        .import("__cxa_atexit", ImportKind::Plt);
    let (p, _) = built(&b);
    let got = lang::hints(&p);
    let names = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        got,
        [
            LangHint {
                lang: Lang::Cpp,
                count: 3,
                examples: names(&["_ZN3foo3barEv", "_ZN3foo3bazEv", "__cxa_atexit"]),
            },
            LangHint {
                lang: Lang::Rust,
                count: 2,
                examples: names(&["_RNvC3foo3bar", "_ZN4core3fmt5write17h0123456789abcdefE"]),
            },
            LangHint {
                lang: Lang::Go,
                count: 2,
                examples: names(&[".gopclntab", "runtime.main"]),
            },
        ]
    );
    for path in [
        "fixtures/bin/hello.gcc-O2",
        "fixtures/bin/hello.gcc-O2.stripped",
    ] {
        assert_eq!(lang::hints(&program(path)), [], "{path}: C has no hint");
    }
}
