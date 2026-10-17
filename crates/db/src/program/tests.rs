use std::path::PathBuf;

use ghidorah_base::{Address, FuncId, JumpTableId, Limits, Range, Rev, Storage, TxId, VarId};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_types::TypeId;

use super::{AnalysisSet, Program};
use crate::comments::CommentKind;
use crate::fact::{Invalid, Origin, SessionLabel};
use crate::funcs::{Function, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::{CodeUnit, DataDef, FlowKind};
use crate::overrides::FlowOverride;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::strings::{Encoding, StrInfo};
use crate::symbols::SymKind;
use crate::why::{FactKey, RuleCode, Why};

fn program(name: &str) -> Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bin")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).unwrap();
    Program::from_binary(binary, mem, &Limits::DEFAULT).unwrap()
}

fn agent() -> Origin {
    Origin::new(
        Source::Agent,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    )
}

fn ram(off: u64) -> Address {
    Address::ram(off)
}

fn func(entry: u64, last: u64, source: Source) -> Function {
    let mut f = Function::new(ram(entry), StartReason::Call, 95, source);
    let mut body = RangeSet::new();
    body.insert(Range { first: entry, last });
    f.body = body;
    f
}

fn text(p: &Program, addr: Address) -> Option<(String, Source)> {
    p.name(addr).map(|n| (n.text, n.source))
}

#[test]
fn default_names_computed_on_read() {
    let mut p = program("hello.gcc-O2.stripped");
    let symbols_before = p.base().symbols().len();
    let analysis = p.layer_mut(Source::Analysis).unwrap();
    analysis
        .funcs
        .insert(func(0x1080, 0x1088, Source::Analysis))
        .unwrap();
    analysis
        .listing
        .insert_unit(
            0x2004,
            CodeUnit::Insn {
                len: 1,
                flow: FlowKind::Trap,
                flags: 0,
            },
        )
        .unwrap();
    analysis
        .listing
        .set_data(
            0x10a0,
            Some(DataDef {
                ty: TypeId::from_index(1),
                len: 4,
            }),
            &Origin::analysis(),
        )
        .unwrap();

    assert_eq!(
        text(&p, ram(0x1080)),
        Some(("FUN_00001080".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x1085)),
        Some(("LAB_00001085".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x2000)),
        Some(("DAT_00002000".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x2004)),
        Some(("LAB_00002004".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x10a0)),
        Some(("DAT_000010a0".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x4010)),
        Some(("DAT_00004010".to_string(), Source::Default)),
        ".bss"
    );
    assert_eq!(
        text(&p, Address::external(0x99)),
        Some(("EXT_00000099".to_string(), Source::Default))
    );
    assert_eq!(
        text(&p, ram(0x10_0000)),
        None,
        "an unmapped address has no name"
    );
    assert!(p.name(ram(0x1080)).unwrap().is_default());

    assert_eq!(
        p.base().symbols().len(),
        symbols_before,
        "a read stores no name"
    );
    assert!(p.analysis().symbols().is_empty());
    assert!(p.addrs_named("FUN_00001080").is_empty());

    p.layer_mut(Source::Agent)
        .unwrap()
        .symbols
        .set_name(
            ram(0x1080),
            Some("parse_cfg".to_string()),
            SymKind::Function,
            &agent(),
        )
        .unwrap();
    assert_eq!(
        text(&p, ram(0x1080)),
        Some(("parse_cfg".to_string(), Source::Agent))
    );
    assert!(!p.name(ram(0x1080)).unwrap().is_default());
    assert_eq!(p.addrs_named("parse_cfg"), [ram(0x1080)]);
    p.layer_mut(Source::Agent)
        .unwrap()
        .symbols
        .set_name(ram(0x1080), None, SymKind::Function, &agent())
        .unwrap();
    assert_eq!(
        text(&p, ram(0x1080)),
        Some(("FUN_00001080".to_string(), Source::Default))
    );
}

#[test]
fn from_binary_gives_imported_symbols_and_imports() {
    let p = program("hello.gcc-O2");
    let main = p.primary_symbol(ram(0x1080)).unwrap();
    assert_eq!(main.name.value, "main");
    assert_eq!(main.name.source, Source::Imported);
    assert_eq!(main.name.session.as_str(), SessionLabel::LOAD);
    assert_eq!(main.kind, SymKind::Function);
    assert_eq!(p.addrs_named("main"), [ram(0x1080)]);
    assert_eq!(
        text(&p, ram(0x1090)),
        Some(("_start".to_string(), Source::Imported))
    );
    assert!(
        p.addrs_named("hello.c").is_empty(),
        "file symbols do not map"
    );
    assert!(
        p.addrs_named("puts@GLIBC_2.2.5").is_empty(),
        "undefined symbols are imports"
    );

    let puts = p
        .imports()
        .values()
        .find(|i| i.id.name() == Some("puts"))
        .unwrap();
    assert_eq!(puts.slot, Some(ram(0x3fc8)));
    assert_eq!(puts.stub, Some(ram(0x1060)));
    assert_eq!(
        puts.ext,
        Address::external(u64::try_from(puts.index).unwrap() + 1)
    );
    assert_eq!(p.addrs_named("puts@plt"), [ram(0x1060)]);
    assert_eq!(p.addrs_named("puts@got"), [ram(0x3fc8)]);
    assert_eq!(p.addrs_named("puts"), [puts.ext]);
    assert_eq!(
        text(&p, puts.ext),
        Some(("puts".to_string(), Source::Imported))
    );
    assert_eq!(
        p.primary_symbol(ram(0x1060)).unwrap().kind,
        SymKind::Function
    );
    assert_eq!(
        p.primary_symbol(ram(0x3fc8)).unwrap().kind,
        SymKind::GlobalVar
    );
    assert_eq!(p.imports().len(), p.binary().imports.len());

    let scan = ghidorah_loader::stubs::find(p.binary(), p.mem(), &Limits::DEFAULT);
    for stub in &scan.stubs {
        let label = ghidorah_loader::stubs::label(p.binary(), stub);
        let label = label.as_str().unwrap();
        assert!(p.addrs_named(label).contains(&ram(stub.addr)), "{label}");
    }
    assert_eq!(p.addrs_named(".plt0"), [ram(0x1020)]);

    let meta = p.meta();
    assert_eq!(meta.binary_id, p.binary().identity.binary_id());
    assert_eq!(meta.file_size, u64::try_from(p.mem().file().len()).unwrap());
    assert_eq!(meta.bits, 64);
    assert_eq!(p.rev(), Rev(0));
    assert!(p.analysis().funcs().is_empty());
    assert!(p.notes().is_empty());
    assert!(p.progress().iter().next().is_none());
    assert!(p.types().store().lookup_typedef("size_t").is_some());
    assert!(p.exports().len() <= p.binary().exports.len());
}

#[test]
fn layers_route_writes_by_source() {
    let mut p = program("hello.gcc-O2.stripped");
    assert_eq!(
        p.layer_mut(Source::Default).unwrap_err(),
        Invalid::DefaultSource
    );
    for s in [Source::Agent, Source::Imported, Source::User] {
        p.layer_mut(s).unwrap().strings.insert(0x2000, info());
        assert_eq!(p.base().strings().len(), 1, "{s}");
    }
    p.layer_mut(Source::Analysis)
        .unwrap()
        .strings
        .insert(0x2001, info());
    assert_eq!(p.analysis().strings().len(), 1);

    let mut fresh = AnalysisSet::default();
    fresh.strings.insert(0x2002, info());
    let old = p.swap_analysis(Box::new(fresh));
    assert_eq!(old.strings().get(0x2001), Some(&info()));
    assert_eq!(p.analysis().strings().get(0x2002), Some(&info()));
    assert!(p.analysis().strings().get(0x2001).is_none());

    p.set_rev(Rev(5));
    assert_eq!(p.rev(), Rev(5));
    assert!(p.notes_mut().is_empty());
    assert_eq!(p.progress_mut().iter().count(), 0);
    assert!(p.types_mut().store_mut().len() > 19);
}

fn info() -> StrInfo {
    StrInfo {
        encoding: Encoding::Ascii,
        len: 4,
        referenced: false,
    }
}

#[test]
fn merged_functions_take_the_body_from_analysis_and_the_source_from_base() {
    let mut p = program("hello.gcc-O2.stripped");
    let id = FuncId(ram(0x1080));
    let base = p.layer_mut(Source::Agent).unwrap();
    base.funcs
        .insert(func(0x1080, 0x1080, Source::Agent))
        .unwrap();
    base.funcs.set_noreturn(id, Some(true), &agent()).unwrap();
    base.funcs
        .insert(func(0x11c0, 0x11c0, Source::Agent))
        .unwrap();
    let analysis = p.layer_mut(Source::Analysis).unwrap();
    analysis
        .funcs
        .insert(func(0x1080, 0x1088, Source::Analysis))
        .unwrap();
    analysis
        .funcs
        .set_noreturn(id, Some(false), &Origin::analysis())
        .unwrap();
    analysis
        .funcs
        .set_sig(id, Some(TypeId::from_index(4)), &Origin::analysis())
        .unwrap();
    analysis
        .funcs
        .insert(func(0x1090, 0x10b5, Source::Analysis))
        .unwrap();

    let v = p.func(id).unwrap();
    assert_eq!(v.id(), id);
    assert_eq!(
        v.func.body.ranges(),
        [Range {
            first: 0x1080,
            last: 0x1088
        }]
    );
    assert_eq!(v.source, Source::Agent);
    assert_eq!(
        v.noreturn.map(|f| f.value),
        Some(true),
        "the agent flag wins"
    );
    assert_eq!(v.sig.map(|f| f.value), Some(TypeId::from_index(4)));
    assert_eq!(
        p.func(FuncId(ram(0x1090))).unwrap().source,
        Source::Analysis
    );
    let only_base = p.func(FuncId(ram(0x11c0))).unwrap();
    assert_eq!(only_base.func.body.ranges(), [Range::single(0x11c0)]);
    assert!(p.func(FuncId(ram(0x9999))).is_none());
    let entries: Vec<FuncId> = p.funcs().iter().map(super::FuncView::id).collect();
    assert_eq!(entries, [id, FuncId(ram(0x1090)), FuncId(ram(0x11c0))]);

    assert_eq!(p.owner_of(ram(0x1084)), Some(id));
    assert_eq!(p.owner_of(ram(0x11c0)), Some(FuncId(ram(0x11c0))));
    assert_eq!(p.owner_of(ram(0x11c1)), None);
    assert_eq!(p.owner_of(Address::external(0x1084)), None);
}

/// The keys of the analysis facts of [`seeded`].
struct Seed {
    a: Address,
    k: RefKey,
    k2: RefKey,
    jt: JumpTableId,
    table: JumpTable,
    v: VarId,
    why: Why,
}

fn insn(len: u8, flow: FlowKind) -> CodeUnit {
    CodeUnit::Insn {
        len,
        flow,
        flags: 0,
    }
}

/// Gives a program with one analysis fact in each table.
fn seeded() -> (Program, Seed) {
    let mut p = program("hello.gcc-O2.stripped");
    let a = ram(0x1080);
    let k = RefKey {
        from: a,
        op_index: 0,
        to: ram(0x2004),
        kind: RefType::Read,
    };
    let k2 = RefKey {
        from: a,
        op_index: 1,
        to: ram(0x2004),
        kind: RefType::Data,
    };
    let table = JumpTable {
        base: None,
        entry_size: 4,
        count: 0,
        targets: Vec::new(),
        method: JtMethod::A,
        resolved: false,
    };
    let seed = Seed {
        a,
        k,
        k2,
        jt: JumpTableId(ram(0x1088)),
        table,
        v: VarId {
            func: FuncId(a),
            storage: Storage::Ret,
        },
        why: Why {
            rule: RuleCode::new("R_CALL_TARGET").unwrap(),
            premises: Vec::new(),
        },
    };
    let origin = Origin::analysis();
    let layer = p.layer_mut(Source::Analysis).unwrap();
    layer
        .symbols
        .add(a, "main".to_string(), SymKind::Function, &origin)
        .unwrap();
    layer
        .refs
        .add(
            Ref {
                key: k,
                primary: true,
            },
            &origin,
        )
        .unwrap();
    layer
        .refs
        .add(
            Ref {
                key: k2,
                primary: false,
            },
            &origin,
        )
        .unwrap();
    layer
        .comments
        .set(a, CommentKind::Eol, Some("auto".to_string()), &origin)
        .unwrap();
    layer
        .jumptables
        .set(seed.jt, Some(seed.table.clone()), &origin)
        .unwrap();
    layer
        .listing
        .insert_unit(0x1080, insn(4, FlowKind::Seq))
        .unwrap();
    layer.strings.insert(0x2004, info());
    layer
        .vars
        .set_name(&seed.v, Some("rv".to_string()), &origin)
        .unwrap();
    layer
        .vars
        .set_type(&seed.v, Some(TypeId::from_index(2)), &origin)
        .unwrap();
    layer
        .why
        .insert(FactKey::Func(FuncId(a)), seed.why.clone())
        .unwrap();
    (p, seed)
}

#[test]
fn merged_reads_see_analysis_facts() {
    let (p, s) = seeded();
    let a = s.a;
    assert_eq!(text(&p, a), Some(("main".to_string(), Source::Analysis)));
    assert_eq!(p.symbols_at(a).len(), 1);
    assert_eq!(p.addrs_named("main"), [a]);
    assert_eq!(p.refs_from(a).len(), 2);
    assert_eq!(p.refs_to(ram(0x2004)).len(), 2);
    assert_eq!(p.comment(a, CommentKind::Eol).unwrap().value, "auto");
    assert_eq!(p.jump_table(s.jt).unwrap().value, s.table);
    assert_eq!(p.code_unit(0x1080).map(CodeUnit::len), Some(4));
    assert_eq!(p.string(0x2004), Some(&info()));
    assert_eq!(p.var(&s.v).name.unwrap().value, "rv");
    assert_eq!(p.why(&FactKey::Func(FuncId(a))), Some(&s.why));
    assert!(p.data_def(0x10a0).is_none());
    assert!(p.flow_override(a).is_none());
    assert!(p.why(&FactKey::Entry(1)).is_none());
}

#[test]
fn merged_reads_prefer_the_base_layer() {
    let (mut p, s) = seeded();
    let a = s.a;
    let mut agent_table = s.table.clone();
    agent_table.method = JtMethod::Agent;
    agent_table.targets = vec![ram(0x1084)];
    let origin = agent();
    let layer = p.layer_mut(Source::Agent).unwrap();
    layer
        .symbols
        .set_name(a, Some("parse_cfg".to_string()), SymKind::Function, &origin)
        .unwrap();
    layer
        .refs
        .add(
            Ref {
                key: s.k,
                primary: false,
            },
            &origin,
        )
        .unwrap();
    layer
        .comments
        .set(a, CommentKind::Eol, Some("mine".to_string()), &origin)
        .unwrap();
    layer
        .jumptables
        .set(s.jt, Some(agent_table.clone()), &origin)
        .unwrap();
    layer
        .overrides
        .set(a, Some(FlowOverride::CallAsJump), &origin)
        .unwrap();
    let def = DataDef {
        ty: TypeId::from_index(1),
        len: 1,
    };
    layer.listing.set_data(0x10a0, Some(def), &origin).unwrap();
    layer
        .vars
        .set_name(&s.v, Some("result".to_string()), &origin)
        .unwrap();
    layer
        .listing
        .insert_unit(0x10a0, insn(1, FlowKind::Ret))
        .unwrap();
    layer.strings.insert(0x2010, info());

    assert_eq!(text(&p, a), Some(("parse_cfg".to_string(), Source::Agent)));
    assert_eq!(
        p.symbols_at(a).len(),
        2,
        "the analysis name stays as a second label"
    );
    assert_eq!(p.primary_symbol(a).unwrap().name.source, Source::Agent);
    assert_eq!(p.addrs_named("main"), [a]);
    let pairs = |refs: Vec<&crate::fact::Fact<Ref>>| -> Vec<(RefKey, Source)> {
        refs.iter().map(|f| (f.value.key, f.source)).collect()
    };
    let want = [(s.k, Source::Agent), (s.k2, Source::Analysis)];
    assert_eq!(pairs(p.refs_from(a)), want);
    assert_eq!(pairs(p.refs_to(ram(0x2004))), want);
    assert_eq!(p.comment(a, CommentKind::Eol).unwrap().value, "mine");
    assert_eq!(p.jump_table(s.jt).unwrap().value, agent_table);
    assert_eq!(p.flow_override(a).unwrap().value, FlowOverride::CallAsJump);
    assert_eq!(p.data_def(0x10a0).unwrap().source, Source::Agent);
    let view = p.var(&s.v);
    assert_eq!(view.name.unwrap().value, "result");
    assert_eq!(view.ty.unwrap().source, Source::Analysis);
    assert_eq!(p.code_unit(0x10a0).map(CodeUnit::len), Some(1));
    assert_eq!(p.string(0x2010), Some(&info()));
}
