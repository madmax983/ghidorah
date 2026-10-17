//! AC-058: the protections of each fixture equal its truth file.

use ghidorah_base::BinText;
use ghidorah_loader::checksec::{elf, protections};
use ghidorah_loader::{ElfProtections, Protections, Relro};
use ghidorah_testkit::elf::consts::{DT_FLAGS, DT_FLAGS_1};
use ghidorah_testkit::elf::{ElfBuilder, ImportKind, Loc, Section, Symbol};

use crate::json;
use crate::support::{fixture, has_fixture, load_ok, root};

fn relro_name(r: Relro) -> &'static str {
    match r {
        Relro::None => "none",
        Relro::Partial => "partial",
        Relro::Full => "full",
    }
}

/// Renders the truth fields of the protections, in the key order of the truth file.
fn render(p: &ElfProtections, build_id: Option<&str>) -> String {
    format!(
        "build_id={} canary={} fortify={} ibt={} nx={} pie={} relro={} rpath={} runpath={} shstk={}",
        build_id.unwrap_or("null"),
        p.canary,
        p.fortify,
        p.ibt,
        p.nx,
        p.pie,
        relro_name(p.relro),
        p.rpath.is_some(),
        p.runpath.is_some(),
        p.shstk
    )
}

fn render_truth(t: &json::Json) -> String {
    let id = match t.get("build_id") {
        json::Json::Str(s) => s.clone(),
        _ => "null".to_string(),
    };
    format!(
        "build_id={id} canary={} fortify={} ibt={} nx={} pie={} relro={} rpath={} runpath={} shstk={}",
        t.get("canary").bool(),
        t.get("fortify").bool(),
        t.get("ibt").bool(),
        t.get("nx").bool(),
        t.get("pie").bool(),
        t.get("relro").text(),
        t.get("rpath").bool(),
        t.get("runpath").bool(),
        t.get("shstk").bool()
    )
}

#[test]
fn ac_058_protections() {
    let dir = root().join("fixtures/truth");
    let mut checked = 0;
    let mut problems = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("truth dir")
        .map(|e| e.expect("entry").path())
        .collect();
    paths.sort();
    for path in paths {
        let truth = json::parse(&std::fs::read_to_string(&path).expect("truth"));
        let want = render_truth(truth.get("protections"));
        for bin in truth.get("binaries").items() {
            let name = bin.get("name").text();
            if !has_fixture(name) {
                continue;
            }
            checked += 1;
            let (b, _) = load_ok(&fixture(name));
            let Some(Protections::Elf(p)) = b.protections.clone() else {
                problems.push(format!("{name}: protections {:?}", b.protections));
                continue;
            };
            let got = render(&p, b.identity.build_id.as_deref());
            if got != want {
                problems.push(format!("{name}:\n  got  {got}\n  want {want}"));
            }
            let stripped = name.ends_with(".stripped") || name.ends_with(".noshdr");
            if p.stripped != stripped {
                problems.push(format!("{name}: stripped {}", p.stripped));
            }
            if protections(&b) != b.protections {
                problems.push(format!("{name}: checksec differs from the load"));
            }
        }
    }
    assert!(checked >= 130, "only {checked} binaries");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

fn base() -> ElfBuilder {
    ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 16]))
        .symbol(Symbol::func("_start", Loc::section(".text", 0), 1))
        .entry(Loc::symbol("_start"))
}

#[test]
fn builder_protections() {
    let get = |b: ElfBuilder| elf(&load_ok(&b.build()).0);
    let plain = get(base());
    assert!(!plain.pie, "ET_DYN without PT_INTERP or DF_1_PIE");
    assert!(!plain.nx && !plain.canary && !plain.fortify && !plain.ibt && !plain.shstk);
    assert_eq!(plain.relro, Relro::None);
    assert!(!plain.stripped);
    assert!(get(base().interp("/lib64/ld-linux-x86-64.so.2")).pie);
    assert!(get(base().dt_flags_1(0x0800_0000)).pie, "DF_1_PIE");
    assert!(!get(ElfBuilder::exec().section(Section::code(".text", &[0xc3]))).pie);
    assert!(get(base().gnu_stack(false)).nx);
    assert!(!get(base().gnu_stack(true)).nx);
    assert_eq!(get(base().gnu_relro()).relro, Relro::Partial);
    assert_eq!(
        get(base().gnu_relro().dt_flags(8)).relro,
        Relro::Full,
        "DF_BIND_NOW"
    );
    assert_eq!(
        get(base().gnu_relro().dt_flags_1(1)).relro,
        Relro::Full,
        "DF_1_NOW"
    );
    assert_eq!(
        get(base().dt_flags(8)).relro,
        Relro::None,
        "no PT_GNU_RELRO"
    );
    let imports = get(base()
        .import("__stack_chk_fail", ImportKind::Plt)
        .import("__memcpy_chk", ImportKind::Plt)
        .needed("libc.so.6"));
    assert!(imports.canary && imports.fortify);
    let only_chk = get(base().import("__stack_chk_fail", ImportKind::Got));
    assert!(
        only_chk.canary && !only_chk.fortify,
        "_chk_fail does not end with _chk"
    );
    let features = get(base().x86_features(1));
    assert!(features.ibt && !features.shstk);
    let features = get(base().x86_features(2));
    assert!(!features.ibt && features.shstk);
    let paths = get(base().rpath("/r").runpath("/rp"));
    assert_eq!(paths.rpath, Some(BinText::new(b"/r".to_vec())));
    assert_eq!(paths.runpath, Some(BinText::new(b"/rp".to_vec())));
    assert!(get(base().strip_section_headers()).stripped);
    let _ = (DT_FLAGS, DT_FLAGS_1);
}

#[test]
fn bind_now_tag_makes_relro_full() {
    // DT_BIND_NOW (24) replaces DF_BIND_NOW in old files.
    let bytes = base().gnu_relro().dt_flags(0).build();
    let (mut b, _) = load_ok(&bytes);
    assert_eq!(elf(&b).relro, Relro::Partial);
    let flags = b
        .dynamic
        .iter_mut()
        .find(|e| e.tag == 30)
        .expect("DT_FLAGS");
    flags.tag = 24;
    assert_eq!(elf(&b).relro, Relro::Full);
}

#[test]
fn x86_features_count_only_on_x86_64() {
    let bytes = base().machine(183).x86_features(3).build();
    let p = elf(&load_ok(&bytes).0);
    assert!(!p.ibt && !p.shstk);
}

#[test]
fn raw_files_have_no_protections() {
    let (b, _) = ghidorah_loader::load(
        &[0xc3; 16],
        &ghidorah_loader::LoadOpts::raw(0x1000, None),
        &ghidorah_base::Limits::DEFAULT,
    )
    .expect("raw");
    assert_eq!(protections(&b), None);
    assert_eq!(b.protections, None);
}
