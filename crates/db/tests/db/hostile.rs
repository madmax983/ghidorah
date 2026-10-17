//! `Program::from_binary` on hostile symbol tables.

use std::time::{Duration, Instant};

use ghidorah_base::{Address, Limits};
use ghidorah_db::Program;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{Loc, Symbol, minimal};

fn program(bytes: &[u8]) -> Program {
    let (binary, mem) = load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// The time cap of one load. A linear load takes well below 1 s. The quadratic key search
/// of the parent commit takes about 20 s.
const FLOOD_CAP: Duration = Duration::from_secs(8);

#[test]
fn regress_symbol_flood_loads_in_linear_time() {
    let names = 70_000;
    let mut b = minimal();
    for i in 0..names {
        let name = format!("s{i}");
        b = b
            .symbol(Symbol::func(&name, Loc::section(".text", 0), 1))
            .export(Symbol::func(&name, Loc::section(".text", 0), 1));
    }
    let bytes = b.build();
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("load");
    let start = Instant::now();
    let p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary");
    let took = start.elapsed();
    assert!(took < FLOOD_CAP, "from_binary took {took:?}");

    let at = Address::ram(
        p.binary()
            .entry_points
            .first()
            .map(|e| e.addr)
            .expect("entry"),
    );
    let syms = p.base().symbols();
    let count = syms.at(at).count();
    assert_eq!(
        count,
        usize::from(u16::MAX) + 1,
        "the keys of one address end at u16::MAX"
    );
    assert_eq!(syms.at(at).filter(|s| s.primary).count(), 1);
    assert_eq!(p.addrs_named("_start"), [at]);
}

#[test]
fn bidi_names_keep_their_exact_text() {
    let text = "bad\u{202e}name";
    let b = minimal().symbol(Symbol::func(text, Loc::section(".text", 4), 1));
    let p = program(&b.build());
    let at = p.addrs_named(text);
    assert_eq!(at.len(), 1, "the name index holds the exact text");
    let name = p.name(at[0]).expect("a name");
    assert_eq!(name.text, text);
    assert!(!name.is_default());
}
