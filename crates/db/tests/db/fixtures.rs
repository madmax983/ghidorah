//! `Program::from_binary` over every T1 fixture of `fixtures/manifest.json`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidorah_base::{Address, Limits, SpaceId};
use ghidorah_db::{Program, Source};
use ghidorah_loader::{LoadOpts, SymKind, SymTable, load};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The paths of the T1 fixtures in manifest order.
fn t1_fixtures() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest =
        ghidorah_json::parse(&text, &ghidorah_json::Limits::DEFAULT).expect("manifest JSON");
    let list = manifest
        .get("fixtures")
        .and_then(|f| f.as_array())
        .expect("fixtures list");
    let paths: Vec<String> = list
        .iter()
        .filter(|f| f.get("tier").and_then(|t| t.as_str()) == Some("T1"))
        .filter_map(|f| {
            f.get("path")
                .and_then(|p| p.as_str())
                .map(ToString::to_string)
        })
        .collect();
    assert!(paths.len() > 100, "the manifest lists the T1 fixtures");
    paths
}

fn program(path: &str) -> Program {
    let bytes = std::fs::read(root().join(path)).expect("fixture bytes");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Checks the facts of one fresh program.
fn check(path: &str, p: &Program) {
    let syms = p.base().symbols();
    let addrs: BTreeSet<Address> = syms.iter().map(|s| s.addr).collect();
    for a in &addrs {
        let primaries = syms.at(*a).filter(|s| s.primary).count();
        assert_eq!(primaries, 1, "{path}: {a} has {primaries} primary symbols");
        if a.space == SpaceId::RAM {
            assert!(
                p.mem().region_at(a.off).is_some(),
                "{path}: {a} is not mapped"
            );
        }
    }
    for s in syms.iter() {
        assert_eq!(s.name.source, Source::Imported, "{path}: {}", s.name.value);
        assert!(
            p.addrs_named(&s.name.value).contains(&s.addr),
            "{path}: index of {}",
            s.name.value
        );
        assert!(!s.name.value.is_empty());
    }
    for (name, list) in syms.names() {
        assert!(
            list.windows(2).all(|w| w[0] < w[1]),
            "{path}: {name} addresses sorted"
        );
        for a in list {
            assert!(
                syms.at(*a).any(|s| s.name.value == name),
                "{path}: {name} at {a}"
            );
        }
    }

    let mut exts = BTreeSet::new();
    for (id, row) in p.imports() {
        assert_eq!(&row.id, id);
        assert_eq!(row.ext.space, SpaceId::EXTERNAL);
        assert!(
            exts.insert(row.ext),
            "{path}: {id} shares its EXTERNAL address"
        );
        assert!(row.index < p.binary().imports.len());
        let name = p.name(row.ext).expect("an import has a name");
        assert_eq!(name.source, Source::Imported, "{path}: {id}");
    }
    for s in &p.binary().symbols {
        let named = matches!(s.table, SymTable::Symtab | SymTable::Dynsym)
            && s.kind == SymKind::Func
            && s.size > 0
            && s.shndx != 0
            && p.mem().region_at(s.addr).is_some();
        if let (true, Some(text)) = (named, s.name.as_str())
            && !text.is_empty()
        {
            let at = Address::ram(s.addr);
            assert!(
                p.addrs_named(text).contains(&at),
                "{path}: function symbol {text}"
            );
        }
    }
    for e in &p.binary().entry_points {
        if p.mem().region_at(e.addr).is_some() {
            assert!(
                p.name(Address::ram(e.addr)).is_some(),
                "{path}: entry {:#x}",
                e.addr
            );
        }
    }
    assert!(p.analysis().symbols().is_empty());
    assert!(p.analysis().funcs().is_empty());
    assert!(p.base().refs().is_empty());
    assert!(p.funcs().is_empty());
}

#[test]
fn from_binary_on_every_t1_fixture() {
    for path in t1_fixtures() {
        let p = program(&path);
        check(&path, &p);
        let again = program(&path);
        assert_eq!(
            p.base(),
            again.base(),
            "{path}: from_binary is deterministic"
        );
        assert_eq!(p.imports(), again.imports());
    }
}

#[test]
fn stripped_and_unstripped_twins_share_imports() {
    let full = program("fixtures/bin/socket_client.gcc-O2");
    let stripped = program("fixtures/bin/socket_client.gcc-O2.stripped");
    let ids = |p: &Program| p.imports().keys().cloned().collect::<Vec<_>>();
    assert_eq!(ids(&full), ids(&stripped));
    assert!(!full.imports().is_empty());
    assert!(full.base().symbols().len() > stripped.base().symbols().len());
    assert!(full.addrs_named("main").len() == 1);
    assert!(stripped.addrs_named("main").is_empty());
}
