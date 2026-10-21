//! Indirect jumps and calls through a register that holds an import slot (design Section 7.8).
//!
//! The C runtime of gcc loads a weak import slot into `rax`, tests it and jumps or calls
//! through `rax`. The analysis resolves the site to the import.

use ghidorah_analysis::analyzers::metrics::{ItemKind, worklist};
use ghidorah_analysis::ctx::UNIT_NULL_TARGET;
use ghidorah_base::{Address, JumpTableId, WarningCode};
use ghidorah_db::{CodeUnit, Program};

use crate::support::{cached, fid, fixtures};

/// The names of the C runtime functions with such a site.
const CRT: [&str; 3] = ["_init", "deregister_tm_clones", "register_tm_clones"];

/// Gives the non-RAM target of the reference of `kind` from `site`.
fn import_ref(p: &Program, site: u64, call: bool) -> Option<Address> {
    p.refs_from(Address::ram(site))
        .iter()
        .map(|r| r.value.key)
        .find(|k| !k.to.is_ram() && k.kind.is_call() == call)
        .map(|k| k.to)
}

#[test]
fn regress_register_slot_sites() {
    let p = cached("fixtures/bin/switch.gcc-O2");
    // jmp rax in deregister_tm_clones and register_tm_clones, call rax in _init.
    for (entry, site, call) in [
        (0x1140, 0x115f, false),
        (0x1170, 0x11a0, false),
        (0x1000, 0x1014, true),
    ] {
        let ext = import_ref(p, site, call);
        assert!(ext.is_some(), "{site:#x}: no reference to the import");
        assert!(
            p.jump_table(JumpTableId(Address::ram(site))).is_none(),
            "{site:#x}: an unresolved table"
        );
        let func = p.func(fid(entry)).expect("the function");
        assert!(
            func.func
                .caveats
                .iter()
                .all(|c| c.code != WarningCode::JumptableUnresolved),
            "{entry:#x}: {:?}",
            func.func.caveats
        );
    }
    let names: Vec<String> = [0x115f, 0x11a0, 0x1014]
        .into_iter()
        .filter_map(|site| import_ref(p, site, site == 0x1014))
        .filter_map(|ext| p.name(ext).map(|n| n.text))
        .collect();
    assert_eq!(
        names,
        [
            "_ITM_deregisterTMCloneTable",
            "_ITM_registerTMCloneTable",
            "__gmon_start__"
        ]
    );
}

/// A file with no import of the weak symbol jumps through the constant 0. The guard skips
/// the jump, so it has no target and no table.
#[test]
fn regress_null_target_site() {
    let p = cached("fixtures/bin/hello.gcc-O2-nocet-nopie");
    for site in [0x0040_10bc, 0x0040_10fe] {
        let flags = p.code_unit(site).map(|u| {
            let CodeUnit::Insn { flags, .. } = u;
            flags
        });
        assert!(
            flags.is_some_and(|f| f & UNIT_NULL_TARGET != 0),
            "{site:#x}: {flags:?}"
        );
        assert!(p.jump_table(JumpTableId(Address::ram(site))).is_none());
        assert!(p.refs_from(Address::ram(site)).is_empty());
    }
}

#[test]
fn regress_crt_has_no_unresolved_items() {
    let mut checked = 0;
    let mut bad = Vec::new();
    for f in fixtures() {
        if f.tier != "T1" || f.variant != "none" || f.path.contains("/pe/") {
            continue;
        }
        let p = cached(&f.path);
        checked += 1;
        for item in worklist(p) {
            if !matches!(
                item.kind,
                ItemKind::UnresolvedJump | ItemKind::UnresolvedCall
            ) {
                continue;
            }
            let name = item
                .func
                .and_then(|id| p.name(id.0))
                .map(|n| n.text)
                .unwrap_or_default();
            if CRT.contains(&name.as_str()) {
                bad.push(format!("{}: {name} {:#x}", f.path, item.at.off));
            }
        }
    }
    assert!(checked >= 30, "only {checked} fixtures");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
