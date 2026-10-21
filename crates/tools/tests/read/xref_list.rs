//! `xref_list`: import sites against objdump, the cross view of calls, argument values,
//! syscall sites, call-graph depth and bad targets (AC-085b, AC-086a).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::cfg;
use ghidorah_analysis::code::{decode_at, slot_of};
use ghidorah_base::{Address, FuncId};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_testkit::elf::{
    ElfBuilder, FixupKind, ImportKind, Loc, Reloc, RelocTable, Section, Symbol,
};
use ghidorah_tools::Session;
use ghidorah_x86::Flow;

use crate::support::{
    addr_of, all_items, call, call_value, data, fixture, items, json, load_bytes, pe_fixtures,
    program, root, str_of, t1_fixtures, t2_fixtures, truth, truth_fixtures,
};

/// `R_X86_64_64`: a 64-bit absolute address.
const R_X86_64_64: u32 = 1;

/// `R_X86_64_GLOB_DAT`: a GOT slot that holds the address of a symbol.
const R_X86_64_GLOB_DAT: u32 = 6;

/// The PLT sections, which hold the stubs themselves.
const PLT: [&str; 3] = [".plt", ".plt.sec", ".plt.got"];

/// Gives the call sites of `import` in the objdump golden of `name`, outside the PLT, each
/// with the `via` that the site must show: `plt` for a call of `<import@plt>` and `got` for a
/// `call [rip+slot]` that objdump names `<import@GLIBC..>`.
fn objdump_calls(name: &str, import: &str) -> BTreeMap<u64, String> {
    let text = std::fs::read_to_string(root().join(format!("tests/golden/objdump/{name}.txt")))
        .expect("the objdump golden reads");
    let mut section = String::new();
    let mut out = BTreeMap::new();
    let plt = format!("<{import}@plt>");
    let got = format!("<{import}@GLIBC");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Disassembly of section ") {
            rest.trim_end_matches(':').clone_into(&mut section);
            continue;
        }
        if PLT.contains(&section.as_str()) {
            continue;
        }
        let mut parts = line.split('\t');
        let (Some(addr), Some(_bytes), Some(insn)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let via = if insn.contains(&plt) {
            "plt"
        } else if insn.contains(&got) {
            "got"
        } else {
            continue;
        };
        if insn.starts_with("call") {
            let addr = addr.trim().trim_end_matches(':');
            let at = u64::from_str_radix(addr, 16).expect("a hex address");
            out.insert(at, via.to_owned());
        }
    }
    out
}

/// Gives `from` and `via` of each item of `xref_list { targets: ["imp:puts"], kinds: ["call"]
/// }`.
fn puts_call_sites(session: &mut Session) -> BTreeMap<u64, String> {
    let args = json(r#"{"targets":["imp:puts"],"kinds":["call"]}"#);
    let got = all_items(session, "xref_list", &args, 1000);
    let sites: BTreeMap<u64, String> = got
        .iter()
        .map(|i| (addr_of(&str_of(i, "from")), str_of(i, "via")))
        .collect();
    assert_eq!(sites.len(), got.len(), "one item for each site: {got:?}");
    sites
}

/// A built ELF file that calls `puts` in three ways.
struct PutsSites {
    /// The file bytes.
    bytes: Vec<u8>,
    /// The address of `main`.
    main: u64,
    /// The address of `.data`: the second slot of `puts`, then a data word.
    data: u64,
}

/// Builds an ELF file whose `main` calls `puts` in three ways: through its PLT stub, through a
/// second `GLOB_DAT` slot at `.data+0` and through its `.got.plt` slot. The word at `.data+8`
/// holds the address of `puts` through an `R_X86_64_64` relocation, so it is not a slot.
fn puts_sites_elf() -> PutsSites {
    let code = [
        0xe8, 0, 0, 0, 0, // call puts@plt
        0xff, 0x15, 0, 0, 0, 0, // call [rip+.data]
        0xff, 0x15, 0, 0, 0, 0,    // call [rip+puts@got]
        0xc3, // ret
    ];
    let text = Section::code(".text", &code)
        .fixup(1, FixupKind::Rel32, Loc::Plt("puts".into()))
        .fixup(7, FixupKind::Rel32, Loc::section(".data", 0))
        .fixup(13, FixupKind::Rel32, Loc::Got("puts".into()));
    let reloc = |off: u64, kind: u32| Reloc {
        table: RelocTable::Rela,
        at: Loc::section(".data", off),
        kind,
        sym: Some("puts".into()),
        addend: 0,
    };
    let (bytes, layout) = ElfBuilder::dyn_object()
        .section(text)
        .section(Section::data(".data", &[0; 16]))
        .symbol(Symbol::func("main", Loc::section(".text", 0), 18))
        .import("puts", ImportKind::Plt)
        .reloc(reloc(0, R_X86_64_GLOB_DAT))
        .reloc(reloc(8, R_X86_64_64))
        .entry(Loc::symbol("main"))
        .build_with_layout();
    let addr = |name: &str| layout.section(name).expect("a built section").addr;
    PutsSites {
        bytes,
        main: addr(".text"),
        data: addr(".data"),
    }
}

#[test]
fn ac_085b_xref_list_imp_puts() {
    let mut checked = 0;
    let mut vias = BTreeSet::new();
    for name in truth_fixtures() {
        let imports = truth(name);
        let has_puts = imports
            .get("imports")
            .and_then(Value::as_array)
            .is_some_and(|l| l.iter().any(|i| i.as_str() == Some("puts")));
        if !has_puts {
            continue;
        }
        let want = objdump_calls(name, "puts");
        let (mut session, _) = fixture(name);
        let sites = puts_call_sites(&mut session);
        assert_eq!(sites, want, "{name}: the sites and their via");
        let noplt = name.contains("noplt");
        assert!(
            sites.values().all(|via| (via == "got") == noplt),
            "{name}: {sites:?}"
        );
        vias.extend(sites.into_values());
        checked += 1;
    }
    assert!(checked >= 10, "{checked} fixtures");
    assert_eq!(vias, BTreeSet::from(["got".to_owned(), "plt".to_owned()]));
    // No instruction can name the EXTERNAL space, so each ELF call site goes through the stub
    // or a slot. A call through a second slot of the import is a GOT site too.
    let built = puts_sites_elf();
    let (mut session, load) = load_bytes("ac_085b", &built.bytes, "full");
    data(&load);
    let main = built.main;
    let want = BTreeMap::from([
        (main, "plt".to_owned()),
        (main + 5, "got".to_owned()),
        (main + 11, "got".to_owned()),
    ]);
    assert_eq!(puts_call_sites(&mut session), want);
}

#[test]
fn regress_xref_list_second_got_slot() {
    let built = puts_sites_elf();
    let (mut session, load) = load_bytes("regress_second_got_slot", &built.bytes, "full");
    data(&load);
    let envelope = call(&mut session, "xref_list", r#"{"targets":["imp:puts"]}"#);
    let via_of = |from: u64, kind: &str| {
        items(&envelope)
            .iter()
            .find(|i| addr_of(&str_of(i, "from")) == from && str_of(i, "kind") == kind)
            .map(|i| str_of(i, "via"))
            .unwrap_or_else(|| panic!("a {kind} item from {from:#x}: {envelope}"))
    };
    assert_eq!(
        via_of(built.main + 5, "unconditional_call"),
        "got",
        "a call through the second slot goes through the GOT"
    );
    assert_eq!(via_of(built.data, "data"), "got", "the second slot itself");
    assert_eq!(
        via_of(built.data + 8, "data"),
        "direct",
        "a data word that holds the address of puts is not a slot"
    );
}

/// Gives the ID text of a call target: an import, a function or a bare address.
fn target_id(program: &Program, addr: Address) -> String {
    for row in program.imports().values() {
        if row.stub == Some(addr) || row.ext == addr {
            return row.id.to_string();
        }
    }
    if program.func(FuncId(addr)).is_some() {
        return FuncId(addr).to_string();
    }
    format!("addr:{addr}")
}

/// Gives the call targets of the CFG of `func`: direct calls and calls through a slot.
fn cfg_calls(program: &Program, func: FuncId) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(graph) = cfg::build(program, func) else {
        return out;
    };
    for block in &graph.blocks {
        for (at, _) in &block.insns {
            let Some(insn) = decode_at(program, *at) else {
                continue;
            };
            match (insn.flow(), insn.target(), slot_of(&insn)) {
                (Flow::Call, Some(t), _) => {
                    out.insert(target_id(program, Address::ram(t)));
                }
                (Flow::ICall, None, Some(slot)) => {
                    let row = program
                        .imports()
                        .values()
                        .find(|r| r.slot == Some(Address::ram(slot)));
                    if let Some(row) = row {
                        out.insert(row.id.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// The counts of a cross-view run: fixtures, functions and functions with calls.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    fixtures: usize,
    functions: usize,
    with_calls: usize,
}

/// Checks the three call views of each function of each fixture of `names` on 4 threads.
/// Fixture `i` goes to thread `i % 4`, so the large builds spread over the threads.
fn cross_view(names: &[&'static str]) -> Counts {
    let mut parts: [Vec<&'static str>; 4] = Default::default();
    for (i, name) in names.iter().enumerate() {
        parts[i % 4].push(name);
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = parts
            .iter()
            .map(|part| scope.spawn(move || cross_view_of(part)))
            .collect();
        let mut out = Counts::default();
        for handle in handles {
            let c = handle.join().expect("the cross-view thread ends");
            out.fixtures += c.fixtures;
            out.functions += c.functions;
            out.with_calls += c.with_calls;
        }
        out
    })
}

#[test]
fn ac_086a_cross_view() {
    let mut names = t1_fixtures();
    let (pe, t2) = (pe_fixtures(), t2_fixtures());
    assert_eq!(pe.len(), 4, "{pe:?}");
    assert_eq!(t2.len(), 6, "{t2:?}");
    names.extend(pe);
    names.extend(t2);
    let c = cross_view(&names);
    assert!(c.fixtures >= 144, "{c:?}");
    assert!(c.functions >= 6_000, "{c:?}");
    assert!(c.with_calls >= 1_700, "{c:?}");
}

/// Checks the three call views of each function of each fixture of `names`.
fn cross_view_of(names: &[&'static str]) -> Counts {
    let mut checked = 0;
    let (mut functions, mut with_calls) = (0, 0);
    for name in names.iter().copied() {
        let (mut session, id) = fixture(name);
        let funcs = all_items(&mut session, "func_list", &json("{}"), 1000);
        for f in &funcs {
            let fid = str_of(f, "id");
            let entry = Address::ram(addr_of(&str_of(f, "addr")));
            let from_cfg = cfg_calls(program(&session, &id), FuncId(entry));
            let args = Value::object([
                ("target", Value::from(fid.as_str())),
                ("include", json(r#"["callees"]"#)),
                ("max_chars", Value::from(60_000)),
            ]);
            let got = call_value(&mut session, "func_get", args);
            let callees: BTreeSet<String> = data(&got)
                .get("callees")
                .and_then(Value::as_array)
                .expect("callees")
                .iter()
                .map(|c| str_of(c, "id"))
                .collect();
            let args = Value::object([
                ("targets", Value::Array(vec![Value::from(fid.as_str())])),
                ("direction", Value::from("from")),
                ("kinds", json(r#"["call"]"#)),
            ]);
            let refs = all_items(&mut session, "xref_list", &args, 1000);
            let p = program(&session, &id);
            let from_refs: BTreeSet<String> = refs
                .iter()
                .map(|r| {
                    let to = Address::parse(&str_of(r, "to")).expect("an address text");
                    target_id(p, to)
                })
                .collect();
            assert_eq!(callees, from_cfg, "{name} {fid}: func_get against the CFG");
            assert_eq!(
                from_refs, from_cfg,
                "{name} {fid}: xref_list against the CFG"
            );
            functions += 1;
            with_calls += usize::from(!from_cfg.is_empty());
        }
        checked += 1;
    }
    Counts {
        fixtures: checked,
        functions,
        with_calls,
    }
}

#[test]
fn xref_list_args_values() {
    let (mut session, _) = fixture("hello.gcc-O2");
    let envelope = call(
        &mut session,
        "xref_list",
        r#"{"targets":["imp:__printf_chk"],"args":true}"#,
    );
    let list = items(&envelope);
    assert_eq!(list.len(), 1, "{envelope}");
    let site = &list[0];
    assert_eq!(str_of(site, "via"), "plt");
    assert_eq!(
        site.pointer("/from_func/name").and_then(Value::as_str),
        Some("greet")
    );
    let args = site.get("args").and_then(Value::as_array).expect("args");
    assert_eq!(
        args[0].pointer("/value/kind").and_then(Value::as_str),
        Some("int")
    );
    assert_eq!(
        args[0].pointer("/value/v").and_then(Value::as_str),
        Some("0x2"),
        "the fortify level"
    );
    assert_eq!(args[0].get("name").and_then(Value::as_str), Some("flag"));
    assert_eq!(
        args[1].pointer("/value/kind").and_then(Value::as_str),
        Some("str")
    );
    assert_eq!(
        args[1].pointer("/value/id").and_then(Value::as_str),
        Some("str:0x2004")
    );
    assert_eq!(
        args[1].pointer("/value/text/text").and_then(Value::as_str),
        Some("Hello, %s!\\x0a")
    );
    assert_eq!(args[1].get("reg").and_then(Value::as_str), Some("rsi"));
}

#[test]
fn xref_list_syscall_sites() {
    let (mut session, _) = fixture("syscall_only.gcc-O2");
    let envelope = call(&mut session, "xref_list", r#"{"targets":["sys:write"]}"#);
    let sites: Vec<(String, String)> = items(&envelope)
        .iter()
        .map(|i| {
            (
                str_of(i, "from"),
                i.pointer("/from_func/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        sites,
        [
            ("0x401018".to_owned(), "emit_banner".to_owned()),
            ("0x40103a".to_owned(), "emit_status".to_owned())
        ],
        "{envelope}"
    );
    assert!(
        items(&envelope)
            .iter()
            .all(|i| str_of(i, "kind") == "syscall")
    );
}

/// Gives the `(from, to)` pairs of the call-graph edges of an `xref_list` result.
fn edge_pairs(envelope: &Value) -> BTreeSet<(String, String)> {
    data(envelope)
        .get("edges")
        .and_then(Value::as_array)
        .expect("edges")
        .iter()
        .map(|e| (str_of(e, "from"), str_of(e, "to")))
        .collect()
}

#[test]
fn xref_list_depth_edges() {
    // gcc -O0 has no tail calls, so each truth call edge is a call.
    let (mut session, _) = fixture("hello.gcc-O0");
    let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
    let up = call(
        &mut session,
        "xref_list",
        r#"{"targets":["finish"],"depth":3}"#,
    );
    let edges = edge_pairs(&up);
    assert!(edges.contains(&pair("fn:0x11ba", "fn:0x1197")), "{edges:?}");
    assert!(edges.contains(&pair("fn:0x11f6", "fn:0x11ba")), "{edges:?}");
    let basis = data(&up).get("basis").expect("basis");
    assert!(basis.get("complete").and_then(Value::as_bool).is_some());
    let down = call(
        &mut session,
        "xref_list",
        r#"{"targets":["fn:0x11f6"],"direction":"from","depth":2,"kinds":["call"]}"#,
    );
    let edges = edge_pairs(&down);
    assert!(edges.contains(&pair("fn:0x11f6", "fn:0x11ba")), "{edges:?}");
    assert!(edges.contains(&pair("fn:0x11ba", "fn:0x1169")), "{edges:?}");
    let one = call(&mut session, "xref_list", r#"{"targets":["finish"]}"#);
    assert!(data(&one).get("edges").is_none(), "depth 1 has no edges");
    let small = call(
        &mut session,
        "xref_list",
        r#"{"targets":["fn:0x11f6"],"direction":"from","depth":3,"max_nodes":2}"#,
    );
    let nodes: BTreeSet<String> = edge_pairs(&small)
        .into_iter()
        .flat_map(<[String; 2]>::from)
        .collect();
    assert!(nodes.len() <= 2, "{nodes:?}");
}

#[test]
fn xref_list_bad_target_goes_to_errors() {
    let (mut session, _) = fixture("hello.gcc-O2");
    let envelope = call(
        &mut session,
        "xref_list",
        r#"{"targets":["imp:puts","no_such_name","str:0x2010"]}"#,
    );
    let d = data(&envelope);
    assert!(!items(&envelope).is_empty());
    let errors = d.get("errors").and_then(Value::as_array).expect("errors");
    assert_eq!(errors.len(), 1, "{envelope}");
    assert_eq!(errors[0].get("index").and_then(Value::as_u64), Some(1));
    assert_eq!(
        errors[0].pointer("/error/code").and_then(Value::as_str),
        Some("NOT_FOUND")
    );
    let strings = items(&envelope)
        .iter()
        .filter(|i| str_of(i, "to") == "0x2010")
        .count();
    assert!(
        strings > 0,
        "the string target lists its references: {envelope}"
    );
}

/// Gives the `basis` of an `xref_list` result as `(complete, unresolved)`.
fn basis_of(envelope: &Value) -> (bool, Vec<String>) {
    let basis = data(envelope).get("basis").expect("basis");
    let complete = basis.get("complete").and_then(Value::as_bool);
    let unresolved = basis
        .get("unresolved")
        .and_then(Value::as_array)
        .expect("basis.unresolved")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    (complete.expect("basis.complete"), unresolved)
}

/// Gives `resolved[index].resolved_from.scope` of an `xref_list` result.
fn scope_of(envelope: &Value, index: usize) -> String {
    data(envelope)
        .get("resolved")
        .and_then(Value::as_array)
        .and_then(|l| l.get(index))
        .and_then(|r| r.pointer("/resolved_from/scope"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn regress_xref_from_name_reads_body() {
    let (mut session, _) = fixture("func_ptrs.gcc-O2");
    let name = call(
        &mut session,
        "xref_list",
        r#"{"targets":["run_op"],"direction":"from"}"#,
    );
    let to: BTreeSet<String> = items(&name).iter().map(|i| str_of(i, "to_name")).collect();
    assert!(to.contains("ops"), "the data ref to ops: {name}");
    assert_eq!(
        basis_of(&name),
        (false, vec!["0x1366".to_owned()]),
        "the jmp [rdx+rax*8] at 0x1366 is a gap: {name}"
    );
    assert_eq!(scope_of(&name, 0), "function", "{name}");
    let by_id = call(
        &mut session,
        "xref_list",
        r#"{"targets":["fn:0x1350"],"direction":"from"}"#,
    );
    assert_eq!(items(&by_id), items(&name), "a name and fn: read one body");
    assert_eq!(basis_of(&by_id), basis_of(&name));
    let site = call(
        &mut session,
        "xref_list",
        r#"{"targets":["0x1366"],"direction":"from"}"#,
    );
    assert_eq!(scope_of(&site, 0), "insn", "{site}");
    assert_eq!(
        basis_of(&site),
        (false, vec!["0x1366".to_owned()]),
        "{site}"
    );
    let entry = call(
        &mut session,
        "xref_list",
        r#"{"targets":["0x1350"],"direction":"from"}"#,
    );
    assert_eq!(scope_of(&entry, 0), "insn", "{entry}");
    assert!(items(&entry).is_empty(), "endbr64 has no refs: {entry}");
    assert_eq!(basis_of(&entry), (true, Vec::new()), "{entry}");
    let main = call(
        &mut session,
        "xref_list",
        r#"{"targets":["main"],"direction":"from","kinds":["call"]}"#,
    );
    let calls = items(&main);
    assert!(calls.len() >= 3, "main's calls: {main}");
    assert!(
        calls
            .iter()
            .all(|i| i.pointer("/from_func/name").and_then(Value::as_str) == Some("main")),
        "{main}"
    );
    assert!(
        calls.iter().any(|i| str_of(i, "to_name") == "qsort@plt"),
        "{main}"
    );
}

#[test]
fn regress_xref_basis_open_without_analysis() {
    let mut session = crate::support::session();
    let load = call(
        &mut session,
        "binary_load",
        r#"{"path":"fixtures/bin/hello.gcc-O0","analysis":"none"}"#,
    );
    data(&load);
    let envelope = call(&mut session, "xref_list", r#"{"targets":["imp:puts"]}"#);
    assert!(
        !basis_of(&envelope).0,
        "no analysis run, so the list can miss sites: {envelope}"
    );
}

/// The call of `m4(double a, int b, double c, int d)` in `pe_cc.exe` labels each slot with its
/// register. A floating slot names its XMM register and has no value. The items labelled each
/// slot with the integer register of its position (r3-engine-06).
#[test]
fn regress_positional_float_slot_regs() {
    let (mut session, _) = fixture("pe/pe_cc.exe");
    let envelope = call(
        &mut session,
        "xref_list",
        r#"{"targets":["fn:0x140001150"],"args":true}"#,
    );
    let site = items(&envelope)
        .into_iter()
        .find(|i| str_of(i, "from") == "0x1400013ef")
        .unwrap_or_else(|| panic!("the call of m4: {envelope}"));
    let args = site.get("args").and_then(Value::as_array).expect("args");
    let got: Vec<(String, String)> = args
        .iter()
        .map(|a| {
            let kind = a.pointer("/value/kind").and_then(Value::as_str);
            (str_of(a, "reg"), kind.unwrap_or_default().to_owned())
        })
        .collect();
    let want = [
        ("xmm0", "unknown"),
        ("rdx", "int"),
        ("xmm2", "unknown"),
        ("r9", "int"),
    ];
    let want: Vec<(String, String)> = want
        .iter()
        .map(|(r, k)| ((*r).to_owned(), (*k).to_owned()))
        .collect();
    assert_eq!(got, want, "{envelope}");
}
