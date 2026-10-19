//! AC-248, AC-250 and AC-252: the `.pdata` seeds, the TLS and export entries and the MS x64
//! parameters on the PE fixtures (WP-30).

use std::collections::BTreeSet;

use ghidorah_analysis::cc::{self, ParamSource};
use ghidorah_base::{DiagCode, Fuel, Limits};
use ghidorah_db::{PartKind, Program, StartReason};
use ghidorah_loader::{EntryKind, LoadOpts};
use ghidorah_testkit::pe::{self, EXE_BASE};

use crate::support::{analyze, cached, fid, hex, list, program_of, root, truth};

/// The PE fixture images.
const IMAGES: [&str; 4] = ["pe_cc.exe", "pe_dll.dll", "pe_flags.exe", "pe_main.exe"];

/// Gives the path of a PE fixture under the root.
fn path(name: &str) -> String {
    format!("fixtures/bin/pe/{name}")
}

/// Gives the analyzed program of a PE fixture. A load error fails the test before the cache
/// takes its lock, so the lock of the other tests stays good.
fn analyzed_pe(name: &str) -> &'static Program {
    let file = path(name);
    let bytes = std::fs::read(root().join(&file)).expect("the fixture bytes");
    if let Err(e) = ghidorah_loader::load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT) {
        panic!("{name} does not load: {e}");
    }
    cached(&file)
}

/// Gives the truth path of a PE fixture.
fn truth_path(name: &str) -> String {
    let program = name.split('.').next().unwrap_or(name);
    format!("fixtures/truth/pe/{program}.json")
}

/// Gives the `StartAddress` values of the `RuntimeFunction` entries of the readobj golden.
fn golden_starts(name: &str) -> BTreeSet<u64> {
    let file = root()
        .join("tests/golden/loader/pe")
        .join(format!("{name}.readobj.txt"));
    let text = std::fs::read_to_string(file).expect("the golden");
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("StartAddress: ("))
        .map(|v| ghidorah_base::hex::parse_u64(v.trim_end_matches(')')).expect("a hex value"))
        .collect()
}

/// Tells if the published function at `addr` starts by `.pdata`. A reason of a higher
/// confidence also counts: an entry point, a symbol or a PLT stub.
fn pdata_start(p: &Program, addr: u64) -> bool {
    p.func(fid(addr)).is_some_and(|f| {
        f.func.start_reason == StartReason::Pdata
            || (f.func.confidence > 95
                && matches!(
                    f.func.start_reason,
                    StartReason::Entry | StartReason::Symbol | StartReason::PltStub
                ))
    })
}

#[test]
fn ac_248_pdata_starts() {
    let mut checked = 0;
    for name in IMAGES {
        let p = analyzed_pe(name);
        let b = p.binary();
        let starts: BTreeSet<u64> = b
            .pdata
            .iter()
            .filter(|f| !f.fragment)
            .map(|f| b.image_base + u64::from(f.begin))
            .collect();
        assert_eq!(starts, golden_starts(name), "{name}");
        for at in &starts {
            assert!(pdata_start(p, *at), "{name}: no pdata function at {at:#x}");
            checked += 1;
        }
    }
    assert!(checked >= 10, "{checked} starts");
    // Only `.pdata` reaches the delay-load helper of pe_main.
    let p = analyzed_pe("pe_main.exe");
    assert_eq!(
        p.func(fid(0x1_4000_1242)).map(|f| f.func.start_reason),
        Some(StartReason::Pdata)
    );
    // A CHAININFO fragment is a cold part of the root of its chain, not a start.
    let bytes = pe::builder("chain").expect("the variant").build();
    let mut chained = program_of(&bytes, &LoadOpts::AUTO);
    let _ = analyze(&mut chained);
    assert!(chained.func(fid(EXE_BASE + 0x1100)).is_none());
    let root_fn = chained
        .func(fid(EXE_BASE + 0x1000))
        .expect("the root function");
    assert!(
        root_fn
            .func
            .parts
            .iter()
            .any(|part| part.kind == PartKind::Cold && part.range.contains(EXE_BASE + 0x1100)),
        "{:?}",
        root_fn.func.parts
    );
}

#[test]
fn ac_250_tls_and_exports_entries() {
    let p = analyzed_pe("pe_main.exe");
    let t = truth(&truth_path("pe_main.exe"));
    let tls: Vec<u64> = list(&t, "tls_callbacks")
        .iter()
        .map(|c| hex(c.get("addr").expect("an address")))
        .collect();
    let entries: Vec<u64> = p
        .binary()
        .entry_points
        .iter()
        .filter(|e| e.kind == EntryKind::TlsCallback)
        .map(|e| e.addr)
        .collect();
    assert_eq!(entries, tls);
    for at in &tls {
        let f = p.func(fid(*at)).expect("a TLS callback is a function");
        assert_eq!(f.func.start_reason, StartReason::Entry);
    }
    let dll = analyzed_pe("pe_dll.dll");
    let t = truth(&truth_path("pe_dll.dll"));
    let mut code_exports = 0;
    for e in list(&t, "exports") {
        let Some(addr) = e.get("addr").filter(|a| a.as_str().is_some()).map(hex) else {
            continue;
        };
        let f = dll
            .func(fid(addr))
            .expect("an export into code is a function");
        assert_eq!(f.func.start_reason, StartReason::Entry);
        assert!(
            dll.binary()
                .entry_points
                .iter()
                .any(|x| x.addr == addr && x.kind == EntryKind::Export)
        );
        code_exports += 1;
    }
    assert_eq!(code_exports, 3);
    let (b, _) = ghidorah_loader::load(
        &pe::builder("tls_257").expect("variant").build(),
        &LoadOpts::AUTO,
        &Limits::DEFAULT,
    )
    .expect("the variant loads");
    let callbacks = b
        .entry_points
        .iter()
        .filter(|e| e.kind == EntryKind::TlsCallback)
        .count();
    assert_eq!(callbacks, 256);
    assert!(b.diagnostics.iter().any(|d| d.code == DiagCode::Limit));
}

#[test]
fn ac_252_msx64_params() {
    let p = analyzed_pe("pe_cc.exe");
    let t = truth(&truth_path("pe_cc.exe"));
    let (mut total, mut good) = (0u32, 0u32);
    let mut wrong = Vec::new();
    for f in list(&t, "functions") {
        let Some(want) = f.get("params").and_then(ghidorah_json::Value::as_u64) else {
            continue;
        };
        let name = f
            .get("name")
            .and_then(ghidorah_json::Value::as_str)
            .unwrap_or_default();
        let addr = hex(f.get("addr").expect("an address"));
        let (got, source) = cc::params(p, fid(addr), &mut Fuel::new(10_000_000))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(source, ParamSource::Recovered, "{name}");
        total += 1;
        if u64::from(got.count()) == want {
            good += 1;
        } else {
            wrong.push(format!("{name}: {got:?}, want {want}"));
            assert!(want < 4, "{name} has {want} parameters: {got:?}");
        }
    }
    assert!(total >= 18, "{total} functions");
    assert!(good * 100 >= total * 95, "{good} of {total}: {wrong:?}");
    assert_eq!(
        cc::conv_of(p).name,
        "ms_x64",
        "a PE binary uses the MS x64 table"
    );
}
