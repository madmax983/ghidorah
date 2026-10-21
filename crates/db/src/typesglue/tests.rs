use ghidorah_base::{FuncId, TypeRef};
use ghidorah_loader::Format;
use ghidorah_types::{DataModel, Prim, TypeId, parse_sig};

use super::{TypeInput, TypeMode, Types, model_for};
use crate::edit::Edit;
use crate::journal::{Line, TxLine};
use crate::listing::DataDef;
use crate::program::Program;
use crate::source::Source;
use crate::tests::{fixture, ram, seeded, session};
use crate::tx::Tx;

/// The prototype of the type input tests. It adds a function type and a pointer type.
const SIG: &str = "int check(const unsigned char *key, int len)";

#[test]
fn types_start_with_the_prelude() {
    let types = Types::for_format(Format::Elf64Le).unwrap();
    assert!(types.store().lookup_typedef("size_t").is_some());
    assert!(types.store().lookup_tag("sockaddr_in").is_some());
    assert_eq!(*types.model(), DataModel::X86_64_SYSV);
    for format in [Format::Elf64Le, Format::Raw] {
        assert_eq!(model_for(format), DataModel::X86_64_SYSV);
    }
    assert_eq!(model_for(Format::Pe32Plus), DataModel::X86_64_WIN);
    let size_t = types.store().lookup_typedef("size_t").unwrap();
    let r = types.type_ref(size_t).unwrap();
    assert_eq!(r, TypeRef::named("size_t").unwrap());
    assert_eq!(types.by_ref(&r), Some(size_t));
}

#[test]
fn sig_gives_function_types_only() {
    let mut types = Types::for_format(Format::Raw).unwrap();
    let parsed = parse_sig(types.store_mut(), "int f(char *s, ...)").unwrap();
    let sig = types.sig(parsed.ty).unwrap();
    assert!(sig.variadic);
    assert_eq!(sig.params.len(), 1);
    let int = types.store().prim(Prim::Int);
    assert_eq!(types.sig(int), None);
}

#[test]
fn prototypes_by_linked_name() {
    assert!(Types::prototype("puts").is_some());
    assert!(Types::prototype("puts@GLIBC_2.2.5").is_some());
    assert!(Types::prototype("no_such_function_xyz").is_none());
}

/// Gives an agent transaction on `p`.
fn agent(p: &mut Program) -> Tx<'_> {
    p.begin("type_edit", Source::Agent, session("mcp-1"))
        .unwrap()
}

/// Gives the signature edit of `ty` on the seeded function `0x1080`.
fn sig_edit(tx: &Tx<'_>, ty: TypeId) -> Edit {
    Edit::SetSignature {
        id: FuncId(ram(0x1080)),
        sig: Some(tx.fact(ty)),
    }
}

#[test]
fn a_parse_that_adds_types_is_an_input() {
    let mut types = Types::for_format(Format::Raw).unwrap();
    let before = types.store().len();
    let first = types.parse_sig(SIG).unwrap();
    assert!(types.store().len() > before);
    assert_eq!(
        types.inputs(),
        [TypeInput {
            mode: TypeMode::Sig,
            text: SIG.to_owned(),
        }]
    );
    // The same text adds no type, so it is not a second input.
    let again = types.parse_sig(SIG).unwrap();
    assert_eq!(again.ty, first.ty);
    assert_eq!(types.inputs().len(), 1);
    let int = types.parse_type("int").unwrap();
    assert_eq!(int, types.store().prim(Prim::Int));
    assert_eq!(types.inputs().len(), 1);
    assert!(types.parse_type("struct no_such_tag_xyz").is_err());
    assert_eq!(types.inputs().len(), 1);
    let mut other = Types::for_format(Format::Raw).unwrap();
    other.replay(types.inputs()).unwrap();
    assert_eq!(other, types, "a replay of the inputs gives the same types");
    assert_eq!(TypeMode::parse("sig"), Some(TypeMode::Sig));
    assert_eq!(TypeMode::parse("type"), Some(TypeMode::Type));
    assert_eq!(TypeMode::parse("decls"), None);
}

#[test]
fn a_rollback_or_a_noop_puts_the_store_back() {
    let mut p = seeded();
    let want = p.types().clone();
    {
        let mut tx = agent(&mut p);
        tx.parse_sig(SIG).unwrap();
        // A drop without a commit rolls back.
    }
    assert_eq!(*p.types(), want, "the rollback puts the store back");
    let mut tx = agent(&mut p);
    tx.parse_type("struct sockaddr_in *").unwrap();
    let commit = tx.commit().unwrap();
    assert!(commit.noop);
    assert!(commit.types.is_empty());
    assert_eq!(*p.types(), want, "a no-op commit puts the store back");
}

#[test]
fn a_commit_line_replays_its_types() {
    let start = seeded();
    let mut edited = start.clone();
    let mut tx = agent(&mut edited);
    let parsed = tx.parse_sig(SIG).unwrap();
    let edit = sig_edit(&tx, parsed.ty);
    tx.apply(edit).unwrap();
    let commit = tx.commit().unwrap();
    assert_eq!(commit.types.len(), 1, "the commit holds the input");
    let line = TxLine::of_commit(&commit);
    let text = crate::journal::encode(&Line::Tx(Box::new(line)));
    assert!(text.contains("\"types\""), "{text}");
    let Line::Tx(read) = crate::journal::decode(&text).unwrap() else {
        panic!("a commit line");
    };
    assert_eq!(read.types, commit.types);
    let mut fresh = start;
    crate::replay::apply_tx(&mut fresh, &read).unwrap();
    assert_eq!(fresh.types(), edited.types());
    let sig = fresh
        .func(FuncId(ram(0x1080)))
        .and_then(|v| v.sig)
        .map(|s| s.value);
    assert_eq!(sig, Some(parsed.ty));
    assert_eq!(fresh.state_hash().unwrap(), edited.state_hash().unwrap());
}

#[test]
fn a_snapshot_keeps_the_types() {
    let mut p = fixture("hello.gcc-O2");
    let fresh = p.clone();
    let mut tx = agent(&mut p);
    let ty = tx.parse_type("struct sockaddr_in *").unwrap();
    let def = tx.fact(DataDef { ty, len: 8 });
    tx.apply(Edit::SetDataDef {
        at: ram(0x4010),
        def: Some(def),
    })
    .unwrap();
    tx.commit().unwrap();
    let text = crate::snapshot::encode(&p, 1, None).unwrap();
    let snap = crate::snapshot::decode(text.as_bytes()).unwrap();
    let mut back = fresh;
    snap.restore(&mut back).unwrap();
    assert_eq!(back.types(), p.types());
    assert_eq!(back.state_hash().unwrap(), p.state_hash().unwrap());
    let dump = crate::codec::facts(&p);
    assert!(
        dump.pointer("/types/inputs").is_some(),
        "the fact dump holds the inputs: {dump}"
    );
}
