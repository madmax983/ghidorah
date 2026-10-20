//! The output ACs over the fixture functions (WP-23): the snippets and goto budgets,
//! determinism, the cache, the self-check, the FLAT rate, the calls and the field access of a
//! typed pointer. `out_linemap` holds the line map coverage.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use ghidorah_analysis::fir::Opts as FirOpts;
use ghidorah_analysis::fir::l1;
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, Limits, VarId};
use ghidorah_db::{CommentKind, Edit, Program, RefType, SessionLabel, Source, SymKind, VarField};
use ghidorah_decomp::print::{self, CallTarget, PrintEnv, Signature};
use ghidorah_decomp::selfcheck::Validation;
use ghidorah_decomp::{Cache, Env, Mode, Opts, Output, ProgramEnv};
use ghidorah_ir::{NoNames, Switches};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_types::{DataModel, Prim, Type, TypeId, TypeStore};

use crate::fixtures::{entry_of, fid, json, program, root};

/// Gives the T1 and T2 fixtures of the manifest in manifest order, every variant included.
fn all_fixtures() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    json(&text)
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures")
        .iter()
        .filter(|f| matches!(f.get("tier").and_then(Value::as_str), Some("T1" | "T2")))
        .filter_map(|f| f.get("path").and_then(Value::as_str))
        .map(|p| p.trim_start_matches("fixtures/bin/").to_owned())
        .collect()
}

/// One rendered function of the corpus.
pub struct Item {
    /// The fixture name.
    pub fixture: String,
    /// The entry of the function.
    pub entry: u64,
    /// The output.
    pub out: Output,
}

/// Renders each function of one fixture, thunks excluded.
fn render_all(name: &str) -> Vec<Item> {
    let p = program(name);
    p.funcs()
        .iter()
        .filter(|v| !v.func.flags.thunk)
        .map(|v| {
            let entry = v.id().0.off;
            let out = ghidorah_decomp::render(
                p,
                fid(entry),
                &Opts::default(),
                &NoNames,
                &mut Fuel::new(50_000_000),
            )
            .unwrap_or_else(|e| panic!("{name} {entry:#x}: {e}"));
            Item {
                fixture: name.to_owned(),
                entry,
                out,
            }
        })
        .collect()
}

/// Gives the rendered functions of every T1 and T2 fixture. The test binary renders them once.
pub fn corpus() -> &'static [Item] {
    static CORPUS: OnceLock<Vec<Item>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let names = all_fixtures();
        let chunks: Vec<Vec<String>> = (0..4)
            .map(|k| names.iter().skip(k).step_by(4).cloned().collect())
            .collect();
        let parts: Vec<Vec<Item>> = std::thread::scope(|s| {
            #[expect(
                clippy::needless_collect,
                reason = "every thread starts before the first join"
            )]
            let handles: Vec<_> = chunks
                .iter()
                .map(|c| s.spawn(move || c.iter().flat_map(|n| render_all(n)).collect()))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a worker thread"))
                .collect()
        });
        let mut all: Vec<Item> = parts.into_iter().flatten().collect();
        all.sort_by(|a, b| (&a.fixture, a.entry).cmp(&(&b.fixture, b.entry)));
        all
    })
}

#[test]
fn ac_106a_selfcheck_ok() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|i| i.out.metrics.validation != Validation::Ok)
        .map(|i| format!("{} {:#x}", i.fixture, i.entry))
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn ac_106b_flat_rate() {
    let items = corpus();
    let structured = items
        .iter()
        .filter(|i| i.out.metrics.mode == Mode::Structured)
        .count();
    assert!(
        structured * 100 >= items.len() * 95,
        "{structured} of {} functions are structured",
        items.len()
    );
    for i in items {
        assert!(
            !i.out.lines.is_empty(),
            "{} {:#x} has no text",
            i.fixture,
            i.entry
        );
        assert_eq!(
            i.out.metrics.mode.fallback_mode(),
            if i.out.metrics.mode == Mode::Structured {
                "none"
            } else {
                "flat"
            }
        );
    }
}

/// Gives the call targets of the CFG of a function. They are the call references from sites
/// outside the elided ranges and the targets of the tail jumps.
fn cfg_targets(p: &Program, entry: u64, out: &Output) -> BTreeSet<u64> {
    let in_elided = |a: u64| {
        out.elided
            .iter()
            .any(|e| (e.start..e.start.saturating_add(e.size)).contains(&a))
    };
    let mut want = BTreeSet::new();
    for (site, _) in print::body_units(p, fid(entry)) {
        if in_elided(site) {
            continue;
        }
        for r in p.refs_from(Address::ram(site)) {
            if r.value.key.kind.is_call() {
                want.insert(r.value.key.to.off);
            }
        }
    }
    let ir = l1::build(
        p,
        fid(entry),
        &FirOpts::DEFAULT,
        &Switches::all(),
        &mut Fuel::unlimited(),
    )
    .expect("the L1 form");
    for site in &ir.tail_calls {
        for r in p.refs_from(Address::ram(*site)) {
            if r.value.key.kind == RefType::UnconditionalJump {
                want.insert(r.value.key.to.off);
            }
        }
    }
    want
}

#[test]
fn ac_086b_decomp_calls() {
    let mut bad = Vec::new();
    let mut calls = 0usize;
    for item in corpus().iter().filter(|i| !i.fixture.starts_with("large.")) {
        let p = program(&item.fixture);
        let got: BTreeSet<u64> = item
            .out
            .lines
            .iter()
            .flat_map(|l| &l.calls)
            .filter_map(|c| match c.target {
                CallTarget::Addr(a) => Some(a),
                CallTarget::Syscall(_) => None,
            })
            .collect();
        calls += got.len();
        let want = cfg_targets(p, item.entry, &item.out);
        if got != want {
            bad.push(format!(
                "{} {:#x}: {got:x?} != {want:x?}",
                item.fixture, item.entry
            ));
        }
    }
    assert!(calls > 500, "only {calls} call targets");
    assert!(
        bad.is_empty(),
        "{} functions: {:?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
}

#[test]
fn ac_102_snippets_and_goto_budget() {
    let text = std::fs::read_to_string(root().join("tests/golden/decomp/snippets.json"))
        .expect("the snippet file");
    let spec = json(&text);
    let rows = spec
        .get("functions")
        .and_then(Value::as_array)
        .expect("functions");
    assert!(rows.len() >= 6);
    let mut bad = Vec::new();
    for row in rows {
        let s = |k: &str| {
            row.get(k)
                .and_then(Value::as_str)
                .expect("a text")
                .to_owned()
        };
        let (fixture, function) = (s("fixture"), s("function"));
        let p = program(&fixture);
        let out = ghidorah_decomp::render(
            p,
            fid(entry_of(p, &function)),
            &Opts::default(),
            &NoNames,
            &mut Fuel::unlimited(),
        )
        .expect("the render");
        let text = out.text();
        let max = row
            .get("max_gotos")
            .and_then(Value::as_u64)
            .expect("max_gotos");
        if u64::from(out.metrics.goto_count) > max {
            bad.push(format!(
                "{fixture} {function}: {} gotos",
                out.metrics.goto_count
            ));
        }
        for snippet in row
            .get("snippets")
            .and_then(Value::as_array)
            .expect("snippets")
        {
            let snippet = snippet.as_str().expect("a snippet");
            if !text.contains(snippet) {
                bad.push(format!("{fixture} {function}: no `{snippet}` in\n{text}"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Loads and analyzes a fixture again, with no cache.
fn fresh(name: &str) -> Program {
    let bytes = std::fs::read(root().join("fixtures/bin").join(name)).expect("the fixture bytes");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the bytes load");
    let mut p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary");
    let out = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete);
    p
}

/// Gives the JSON text of every member of an output.
fn output_json(out: &Output) -> String {
    let opt = |v: Option<String>| v.map_or(Value::Null, Value::from);
    let lines: Vec<Value> = out
        .lines
        .iter()
        .map(|l| {
            Value::object([
                ("text", Value::from(l.text.as_str())),
                ("kind", Value::from(format!("{:?}", l.kind))),
                ("depth", Value::from(u64::from(l.depth))),
                (
                    "ops",
                    Value::Array(l.ops.iter().map(|o| Value::from(o.to_string())).collect()),
                ),
                ("span", opt(l.span.map(|s| format!("{s:x?}")))),
                ("comment", opt(l.comment.map(|c| c.name().to_owned()))),
                ("calls", Value::from(format!("{:?}", l.calls))),
                ("strings", Value::from(format!("{:x?}", l.strings))),
            ])
        })
        .collect();
    let vars: Vec<Value> = out
        .vars
        .iter()
        .map(|v| {
            Value::object([
                ("id", Value::from(v.id.to_string())),
                ("name", Value::from(v.name.as_str())),
                ("type", Value::from(v.ty.as_str())),
                ("source", Value::from(v.source)),
            ])
        })
        .collect();
    let value = Value::object([
        ("entry", Value::from(out.entry)),
        ("name", Value::from(out.name.as_str())),
        ("lines", Value::Array(lines)),
        ("elided", Value::from(format!("{:x?}", out.elided))),
        ("vars", Value::Array(vars)),
        ("warnings", Value::from(format!("{:x?}", out.warnings))),
        ("metrics", Value::from(format!("{:?}", out.metrics))),
    ]);
    ghidorah_json::write(&value)
}

#[test]
fn ac_104a_decomp_determinism() {
    for name in ["hello.gcc-O2", "switch.gcc-O0", "socket_client.clang-O2"] {
        let (one, two) = (fresh(name), fresh(name));
        let mut count = 0;
        for f in one.funcs() {
            let id = f.id();
            let render = |p: &Program| {
                ghidorah_decomp::render(p, id, &Opts::default(), &NoNames, &mut Fuel::unlimited())
                    .expect("the render")
            };
            let (first, other, again) = (render(&one), render(&two), render(&one));
            assert!(!first.lines.is_empty(), "{name} {id}");
            assert_eq!(output_json(&first), output_json(&other), "{name} {id}");
            assert_eq!(output_json(&first), output_json(&again), "{name} {id}");
            count += 1;
        }
        assert!(count > 5, "{name}: {count}");
    }
}

/// Commits one edit in `p`.
fn commit(p: &mut Program, make: impl FnOnce(&ghidorah_db::Tx<'_>) -> Edit) {
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let edit = make(&tx);
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
}

/// Gives the first type of the store that `pick` accepts.
fn type_where(p: &Program, pick: impl Fn(&Type) -> bool) -> TypeId {
    let store = p.types().store();
    store
        .ids()
        .find(|id| store.get(*id).is_some_and(&pick))
        .expect("the store holds the type")
}

/// Makes the edit of one step of the cache test.
type Make = Box<dyn Fn(&ghidorah_db::Tx<'_>) -> Edit>;

/// Gives the edits of the cache test: renames, a retype, a signature and a comment.
fn cache_steps(p: &Program, run: u64, finish: u64, var: &VarId) -> Vec<(&'static str, Make)> {
    let int = type_where(p, |t| *t == Type::Prim(Prim::Int));
    let sig = type_where(p, |t| matches!(t, Type::Func(_)));
    let rename = |addr: u64, name: &'static str| -> Make {
        Box::new(move |tx| Edit::SetName {
            addr: Address::ram(addr),
            key: None,
            kind: SymKind::Function,
            primary: true,
            name: Some(tx.fact(name.to_owned())),
            evidence: Vec::new(),
        })
    };
    let (named, typed) = (var.clone(), var.clone());
    vec![
        ("rename of the function", rename(run, "run_renamed")),
        ("rename of a callee", rename(finish, "finish_renamed")),
        (
            "rename of a variable",
            Box::new(move |tx| Edit::SetVarFact {
                var: named.clone(),
                field: VarField::Name(Some(tx.fact("count".to_owned()))),
            }),
        ),
        (
            "retype of a variable",
            Box::new(move |tx| Edit::SetVarFact {
                var: typed.clone(),
                field: VarField::Type(Some(tx.fact(int))),
            }),
        ),
        (
            "signature of a callee",
            Box::new(move |tx| Edit::SetSignature {
                id: fid(finish),
                sig: Some(tx.fact(sig)),
            }),
        ),
        (
            "comment in the body",
            Box::new(move |tx| Edit::SetComment {
                addr: Address::ram(run),
                kind: CommentKind::Pre,
                text: Some(tx.fact("entry".to_owned())),
            }),
        ),
    ]
}

#[test]
fn ac_104b_cache_invalidation() {
    let mut p = program("hello.gcc-O0").clone();
    let (run, finish) = (entry_of(&p, "run"), entry_of(&p, "finish"));
    let opts = Opts::default();
    let mut cache = Cache::new(8);
    let mut look = |p: &Program| {
        cache
            .render(p, fid(run), &opts, &NoNames, &mut Fuel::unlimited())
            .expect("the render")
    };
    let (first, hit) = look(&p);
    assert!(!hit, "the first lookup misses");
    assert!(look(&p).1, "the second lookup hits");
    let var = first
        .vars
        .first()
        .map(|v| v.id.clone())
        .expect("run has a variable");
    let steps = cache_steps(&p, run, finish, &var);
    let mut last = first;
    for (what, make) in steps {
        commit(&mut p, |tx| make(tx));
        let (out, hit) = look(&p);
        assert!(!hit, "the lookup after the {what} misses");
        assert!(look(&p).1, "the lookup after the {what} hits again");
        if !what.starts_with("signature") {
            assert_ne!(out.text(), last.text(), "the {what} changes the text");
        }
        last = out;
    }
    let text = last.text();
    assert!(
        text.contains("run_renamed") && text.contains("finish_renamed"),
        "{text}"
    );
    assert!(
        text.contains("int count") || text.contains("count"),
        "{text}"
    );
}

/// The facts of a program with one more variable type.
struct Typed<'a> {
    inner: ProgramEnv<'a>,
    store: TypeStore,
    model: DataModel,
    var: VarId,
    ty: TypeId,
}

impl Env for Typed<'_> {
    fn callee_name(&self, addr: u64) -> Option<String> {
        self.inner.callee_name(addr)
    }
    fn is_noreturn(&self, addr: u64) -> bool {
        self.inner.is_noreturn(addr)
    }
    fn is_string(&self, addr: u64) -> bool {
        self.inner.is_string(addr)
    }
}

impl PrintEnv for Typed<'_> {
    fn var_name(&self, id: &VarId) -> Option<(String, &'static str)> {
        self.inner.var_name(id)
    }
    fn var_type(&self, id: &VarId) -> Option<TypeId> {
        (*id == self.var).then_some(self.ty)
    }
    fn comments(&self, entry: u64) -> Vec<(u64, CommentKind, String)> {
        self.inner.comments(entry)
    }
    fn signature(&self, addr: u64) -> Option<Signature> {
        self.inner.signature(addr)
    }
    fn param_count(&self, addr: u64) -> Option<u8> {
        self.inner.param_count(addr)
    }
    fn string_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        self.inner.string_bytes(addr)
    }
    fn types(&self) -> Option<(&TypeStore, &DataModel)> {
        Some((&self.store, &self.model))
    }
    fn call_targets(&self, site: u64) -> Vec<u64> {
        self.inner.call_targets(site)
    }
    fn syscall_name(&self, nr: u64) -> Option<&'static str> {
        self.inner.syscall_name(nr)
    }
}

#[test]
fn lattice_field_access_through_a_typed_pointer() {
    let p = program("socket_client.gcc-O2");
    let entry = entry_of(p, "connect_to");
    let render = |env: &dyn PrintEnv| {
        let d = ghidorah_decomp::decompile(p, fid(entry), &Opts::default(), &mut Fuel::unlimited())
            .expect("the decompile");
        ghidorah_decomp::finish(
            d,
            env,
            &NoNames,
            "connect_to",
            &print::body_units(p, fid(entry)),
        )
    };
    let plain = render(&ProgramEnv(p));
    let line = plain
        .lines
        .iter()
        .find(|l| l.text.contains("*(uint16_t *)(") && l.text.contains(" + 2) = "))
        .unwrap_or_else(|| panic!("no 16-bit store at offset 2:\n{}", plain.text()));
    let base = line
        .text
        .split("*(uint16_t *)(")
        .nth(1)
        .and_then(|t| t.split(" + 2)").next())
        .expect("a base name")
        .to_owned();
    let var = plain
        .vars
        .iter()
        .find(|v| v.name == base)
        .map(|v| v.id.clone())
        .expect("the base is a variable");
    let mut store = p.types().store().clone();
    let rec = store
        .lookup_tag("sockaddr_in")
        .expect("the prelude has sockaddr_in");
    let ty = store.ptr(rec).expect("a pointer type");
    let env = Typed {
        inner: ProgramEnv(p),
        store,
        model: *p.types().model(),
        var: var.clone(),
        ty,
    };
    let typed = render(&env);
    let text = typed.text();
    assert!(text.contains(&format!("{base}->sin_port = ")), "{text}");
    assert!(text.contains(&format!("{base}->sin_family = 2")), "{text}");
    let row = typed
        .vars
        .iter()
        .find(|v| v.id == var)
        .expect("the variable row");
    assert_eq!(row.ty, "struct sockaddr_in *");
}
