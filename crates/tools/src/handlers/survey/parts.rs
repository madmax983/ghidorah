//! The sections of `binary_survey`. Each section is a [`Part`]: members, one list that the
//! budget can cut, and the `search` call that lists the rest.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::analyzers::{lang, metrics};
use ghidorah_analysis::{CallGraph, Callee};
use ghidorah_base::{Address, Caps, Fuel, FuncId};
use ghidorah_db::{Program, Types};
use ghidorah_json::{Object, Value};
use ghidorah_loader::{EntryKind, Kind, Protections, Relro, SegmentKind};

use super::{DIAG_PLACES, STRING_FUNCS, TOP_FUNCTIONS, WHY_REST, WORK_ITEMS};
use crate::handlers::func_sections::{self as fs, Namer};

/// One section: its members, its list and the call that lists the items it leaves out.
pub struct Part {
    /// The members before the list.
    pub head: Object,
    /// The member name of the list, or `None` for a section with no list.
    pub key: Option<&'static str>,
    /// The list.
    pub list: Vec<Value>,
    /// The `search` call that lists the rest of the list.
    pub rest: Option<Value>,
}

impl Part {
    /// Makes a section with no list.
    fn plain(head: Object) -> Self {
        Self {
            head,
            key: None,
            list: Vec::new(),
            rest: None,
        }
    }

    /// Makes a section with a list. `kind` names the `search` kind of the rest, if any.
    fn listed(mut head: Object, key: &'static str, list: Vec<Value>, kind: Option<&str>) -> Self {
        let mut total = Object::new();
        total.push("total", Value::from(list.len()));
        for (k, v) in head.into_members() {
            total.push(k, v);
        }
        head = total;
        let rest = kind.map(|k| {
            Value::object([
                ("tool", Value::from("search")),
                ("args", Value::object([("kind", Value::from(k))])),
                ("why", Value::from(WHY_REST)),
            ])
        });
        Self {
            head,
            key: Some(key),
            list,
            rest,
        }
    }

    /// Gives the section value with the first `k` items of the list.
    #[must_use]
    pub fn value(&self, k: usize) -> Value {
        let mut out = self.head.clone();
        if let Some(key) = self.key {
            out.push(
                key,
                Value::Array(self.list.iter().take(k).cloned().collect()),
            );
            let left = self.list.len().saturating_sub(k);
            if left > 0 {
                let mut omitted = Object::new();
                omitted.push("count", Value::from(left));
                if let Some(rest) = &self.rest {
                    omitted.push("next", rest.clone());
                }
                out.push("omitted", Value::Object(omitted));
            }
        }
        Value::Object(out)
    }
}

/// The parts of the call that every section reads.
pub struct Ctx<'a> {
    /// The program.
    pub program: &'a Program,
    /// The file name.
    pub file_name: &'a str,
    /// The namer of the result.
    pub namer: &'a Namer,
    /// The caps of binary text.
    pub caps: Caps,
}

/// Gives a section by name.
pub fn part(c: &Ctx<'_>, name: &str, graph: &CallGraph, fuel: &mut Fuel) -> Part {
    match name {
        "identity" => identity(c),
        "protections" => protections(c.program),
        "segments" => segments(c.program),
        "sections" => sections(c.program),
        "imports" => imports(c),
        "exports" => exports(c),
        "strings" => strings(c),
        "entries" => entries(c),
        "functions" => functions(c, graph),
        "syscalls" => syscalls(c.program, fuel),
        "notes" => notes(c.program),
        "coverage" => coverage(c.program),
        "languages" => languages(c),
        _ => diagnostics(c.program),
    }
}

/// The identity: file, hash, format, machine, kind, base, entry, size and build ID.
fn identity(c: &Ctx<'_>) -> Part {
    let p = c.program;
    let meta = p.meta();
    let b = p.binary();
    let kind = match meta.kind {
        Kind::Exec => "exec",
        Kind::Dyn => "dyn",
        Kind::Raw => "raw",
    };
    let entry = b
        .entry_points
        .iter()
        .find(|e| e.kind == EntryKind::Entry)
        .map_or(Value::Null, |e| fs::hex(e.addr));
    let mut out = Object::new();
    out.push("file_name", Value::from(fs::safe(c.file_name)));
    out.push(
        "sha256",
        Value::from(ghidorah_base::hex::encode(&meta.sha256)),
    );
    out.push("format", Value::from(meta.format.name()));
    out.push("arch", Value::from(meta.arch.to_string()));
    out.push("bits", Value::from(meta.bits));
    out.push("kind", Value::from(kind));
    out.push("image_base", fs::hex(meta.image_base));
    out.push("entry", entry);
    out.push("size", Value::from(meta.file_size));
    if let Some(id) = &b.identity.build_id {
        out.push("build_id", Value::from(fs::safe(id)));
    }
    if let Some(soname) = &b.identity.soname {
        out.push("soname", fs::bin_text(soname.as_bytes(), c.caps));
    }
    if let Some(interp) = &b.interp {
        out.push("interp", fs::bin_text(interp.as_bytes(), c.caps));
    }
    Part::plain(out)
}

/// The checksec flags of design Section 4.6, or `null`.
fn protections(p: &Program) -> Part {
    let mut out = Object::new();
    match &p.binary().protections {
        Some(Protections::Elf(e)) => {
            let relro = match e.relro {
                Relro::None => "none",
                Relro::Partial => "partial",
                Relro::Full => "full",
            };
            out.push("pie", Value::Bool(e.pie));
            out.push("nx", Value::Bool(e.nx));
            out.push("relro", Value::from(relro));
            out.push("canary", Value::Bool(e.canary));
            out.push("fortify", Value::Bool(e.fortify));
            out.push("ibt", Value::Bool(e.ibt));
            out.push("shstk", Value::Bool(e.shstk));
            out.push("rpath", Value::Bool(e.rpath.is_some()));
            out.push("runpath", Value::Bool(e.runpath.is_some()));
            out.push("stripped", Value::Bool(e.stripped));
        }
        Some(Protections::Pe(e)) => {
            out.push("dynamic_base", Value::Bool(e.dynamic_base));
            out.push("high_entropy_va", Value::Bool(e.high_entropy_va));
            out.push("nx_compat", Value::Bool(e.nx_compat));
            out.push("guard_cf", Value::Bool(e.guard_cf));
            out.push("force_integrity", Value::Bool(e.force_integrity));
        }
        None => {}
    }
    Part::plain(out)
}

/// Gives the name of a segment kind.
fn segment_kind(kind: SegmentKind) -> String {
    match kind {
        SegmentKind::Elf(t) => match t {
            1 => "load".to_owned(),
            2 => "dynamic".to_owned(),
            3 => "interp".to_owned(),
            4 => "note".to_owned(),
            6 => "phdr".to_owned(),
            7 => "tls".to_owned(),
            0x6474_e550 => "gnu_eh_frame".to_owned(),
            0x6474_e551 => "gnu_stack".to_owned(),
            0x6474_e552 => "gnu_relro".to_owned(),
            0x6474_e553 => "gnu_property".to_owned(),
            other => format!("{other:#x}"),
        },
        SegmentKind::PeHeaders => "pe_headers".to_owned(),
        SegmentKind::PeSection => "pe_section".to_owned(),
        SegmentKind::Raw => "raw".to_owned(),
    }
}

/// The program headers with their IDs, kinds, starts, sizes and permissions.
fn segments(p: &Program) -> Part {
    let list = p
        .binary()
        .segments
        .iter()
        .map(|s| {
            let mut out = Object::new();
            out.push("id", Value::from(format!("seg:{}", s.index)));
            out.push("kind", Value::from(segment_kind(s.kind)));
            if let Some(r) = s.va {
                out.push("start", fs::hex(r.first));
            }
            out.push("size", fs::hex(s.mem_size));
            out.push("perms", Value::from(s.perms.to_string()));
            Value::Object(out)
        })
        .collect();
    Part::listed(Object::new(), "items", list, Some("segment"))
}

/// The section headers with their IDs, names, starts and sizes.
fn sections(p: &Program) -> Part {
    let list = p
        .binary()
        .sections
        .iter()
        .filter(|s| !s.name.is_empty())
        .map(|s| {
            let name = fs::safe(&s.name.render(Caps::DETAILED).text);
            let mut out = Object::new();
            out.push("id", Value::from(format!("sec:{}:{name}", s.index)));
            out.push("name", Value::from(name));
            if let Some(r) = s.va {
                out.push("start", fs::hex(r.first));
            }
            out.push("size", fs::hex(s.size));
            Value::Object(out)
        })
        .collect();
    Part::listed(Object::new(), "items", list, Some("section"))
}

/// The libraries and the imports in groups by Tier-0 category. PE imports group by DLL in
/// library order first, and each item names its DLL. An import by ordinal shows `#<ordinal>`.
fn imports(c: &Ctx<'_>) -> Part {
    let p = c.program;
    let libraries: Vec<String> = (p.binary().libraries.iter())
        .map(|l| fs::safe(&l.render(Caps::DETAILED).text))
        .collect();
    let mut grouped: BTreeMap<(usize, usize, String), Value> = BTreeMap::new();
    for row in p.imports().values() {
        let name = match (row.id.name(), row.id.ordinal()) {
            (Some(n), _) => n.to_owned(),
            (None, Some(o)) => format!("#{o}"),
            (None, None) => row.id.to_string(),
        };
        let category = Types::prototype(&name).map(|proto| proto.category);
        let order = category.map_or(usize::MAX, |cat| {
            ghidorah_types::Category::ALL
                .iter()
                .position(|x| *x == cat)
                .unwrap_or(usize::MAX)
        });
        let dll = row.id.lib();
        let group = dll.map_or(0, |d| {
            (libraries.iter())
                .position(|x| x.eq_ignore_ascii_case(d))
                .unwrap_or(usize::MAX)
        });
        let mut out = Object::new();
        out.push("id", Value::from(row.id.to_string()));
        if let Some(d) = dll {
            out.push("dll", Value::from(fs::safe(d)));
        }
        out.push("name", Value::from(c.namer.text(&name)));
        out.push(
            "category",
            Value::from(category.map_or("other", |cat| cat.name())),
        );
        if row.delay {
            out.push("delay", Value::Bool(true));
        }
        grouped.insert((group, order, row.id.to_string()), Value::Object(out));
    }
    let mut head = Object::new();
    let libraries = libraries.into_iter().map(Value::from).collect();
    head.push("libraries", Value::Array(libraries));
    Part::listed(
        head,
        "items",
        grouped.into_values().collect(),
        Some("import"),
    )
}

/// The exports with their addresses.
fn exports(c: &Ctx<'_>) -> Part {
    let list = c
        .program
        .exports()
        .values()
        .map(|row| {
            let name = row
                .id
                .name()
                .map_or_else(|| row.id.to_string(), str::to_owned);
            let mut out = Object::new();
            out.push("id", Value::from(row.id.to_string()));
            out.push("name", Value::from(c.namer.text(&name)));
            out.push("addr", row.addr.map_or(Value::Null, fs::addr));
            Value::Object(out)
        })
        .collect();
    Part::listed(Object::new(), "items", list, Some("export"))
}

/// The referenced strings, the most referenced first, with up to 3 functions each.
fn strings(c: &Ctx<'_>) -> Part {
    let p = c.program;
    let mut found: Vec<(usize, u64, BTreeSet<FuncId>)> = Vec::new();
    let mut addrs = BTreeSet::new();
    for layer in [p.base(), p.analysis()] {
        addrs.extend(layer.strings().iter().map(|(at, _)| at));
    }
    for at in addrs {
        let refs = p.refs_to(Address::ram(at));
        if refs.is_empty() {
            continue;
        }
        let funcs = refs
            .iter()
            .filter_map(|r| p.owner_of(r.value.key.from))
            .collect();
        found.push((refs.len(), at, funcs));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let list = found
        .into_iter()
        .filter_map(|(count, at, funcs)| {
            let text = fs::string_text(p, at, c.caps)?;
            let names = funcs
                .iter()
                .take(STRING_FUNCS)
                .map(|f| Value::from(c.namer.of(p, f.0)))
                .collect();
            Some(Value::object([
                (
                    "id",
                    Value::from(ghidorah_base::StringId(Address::ram(at)).to_string()),
                ),
                ("text", text),
                ("ref_count", Value::from(count)),
                ("funcs", Value::Array(names)),
            ]))
        })
        .collect();
    Part::listed(Object::new(), "items", list, Some("string"))
}

/// Gives the name of an entry kind.
const fn entry_kind(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Entry => "entry",
        EntryKind::Init => "init",
        EntryKind::Fini => "fini",
        EntryKind::InitArray => "init_array",
        EntryKind::FiniArray => "fini_array",
        EntryKind::PreinitArray => "preinit_array",
        EntryKind::Export => "export",
        EntryKind::TlsCallback => "tls_callback",
    }
}

/// The entry points.
fn entries(c: &Ctx<'_>) -> Part {
    let p = c.program;
    let list = p
        .binary()
        .entry_points
        .iter()
        .map(|e| {
            Value::object([
                ("addr", fs::hex(e.addr)),
                ("kind", Value::from(entry_kind(e.kind))),
                ("name", Value::from(c.namer.of(p, Address::ram(e.addr)))),
            ])
        })
        .collect();
    Part::listed(Object::new(), "items", list, None)
}

/// The function counts and the first functions in priority order.
fn functions(c: &Ctx<'_>, graph: &CallGraph) -> Part {
    let p = c.program;
    let funcs = p.funcs();
    let mut reasons: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut named = 0u64;
    for f in &funcs {
        let n = reasons.entry(f.func.start_reason.name()).or_default();
        *n = n.saturating_add(1);
        named = named.saturating_add(u64::from(p.name(f.id().0).is_some_and(|n| !n.is_default())));
    }
    let by_reason = reasons
        .into_iter()
        .map(|(r, n)| Value::object([("reason", Value::from(r)), ("count", Value::from(n))]))
        .collect();
    let top = metrics::priority(p)
        .into_iter()
        .take(TOP_FUNCTIONS)
        .map(|r| {
            let size = p
                .func(r.func)
                .map_or(0, |v| u64::try_from(v.func.size()).unwrap_or(u64::MAX));
            Value::object([
                ("id", Value::from(r.func.to_string())),
                ("name", Value::from(c.namer.of(p, r.func.0))),
                ("size", Value::from(size)),
                (
                    "callers",
                    Value::from(graph.callers(&Callee::Func(r.func)).len()),
                ),
            ])
        })
        .collect();
    let mut head = Object::new();
    head.push("total", Value::from(funcs.len()));
    head.push("named", Value::from(named));
    head.push("by_reason", Value::Array(by_reason));
    let mut part = Part::listed(Object::new(), "top", top, None);
    part.head = head;
    part
}

/// The syscall numbers of the sites with their site counts.
fn syscalls(p: &Program, fuel: &mut Fuel) -> Part {
    let mut counts: BTreeMap<(Option<u64>, String), u64> = BTreeMap::new();
    if p.meta().arch.is_x86_64() {
        for site in ghidorah_analysis::syscalls::sites(p, fuel) {
            let id = site
                .id()
                .map_or_else(|| "sys:unknown".to_owned(), |i| i.to_string());
            let n = counts.entry((site.nr, id)).or_default();
            *n = n.saturating_add(1);
        }
    }
    let list = counts
        .into_iter()
        .map(|((nr, id), sites)| {
            let name = id.trim_start_matches("sys:").to_owned();
            Value::object([
                ("id", Value::from(id)),
                ("name", Value::from(name)),
                ("nr", nr.map_or(Value::Null, Value::from)),
                ("sites", Value::from(sites)),
            ])
        })
        .collect();
    Part::listed(Object::new(), "items", list, None)
}

/// The ELF notes with their names, types and the start of their data.
fn notes(p: &Program) -> Part {
    let list = p
        .binary()
        .notes
        .iter()
        .map(|n| {
            let shown = n.desc.get(..32).unwrap_or(&n.desc);
            Value::object([
                (
                    "name",
                    Value::from(fs::safe(&n.name.render(Caps::DETAILED).text)),
                ),
                ("kind", Value::from(n.kind)),
                ("desc", Value::from(ghidorah_base::hex::encode(shown))),
                ("desc_size", Value::from(n.desc_size)),
            ])
        })
        .collect();
    Part::listed(Object::new(), "items", list, None)
}

/// The coverage counts and the first worklist items.
fn coverage(p: &Program) -> Part {
    let c = metrics::coverage(p);
    let pct = c
        .visited
        .saturating_mul(100)
        .checked_div(c.functions)
        .unwrap_or(0);
    let work = metrics::worklist(p);
    let items = work
        .iter()
        .take(WORK_ITEMS)
        .map(|w| {
            let mut out = Object::new();
            out.push("kind", Value::from(w.kind.name()));
            out.push("at", fs::addr(w.at));
            if let Some(f) = w.func {
                out.push("func", Value::from(f.to_string()));
            }
            if let Some(r) = w.remedy {
                out.push(
                    "remedy",
                    Value::object([("tool", Value::from("func_edit")), ("args", r.args())]),
                );
            }
            Value::Object(out)
        })
        .collect();
    let mut out = Object::new();
    out.push("functions", Value::from(c.functions));
    out.push("analyzed", Value::from(c.analyzed));
    out.push("visited", Value::from(c.visited));
    out.push("named", Value::from(c.named));
    out.push("typed", Value::from(c.typed));
    out.push("commented", Value::from(c.commented));
    out.push("pct", Value::from(pct));
    out.push(
        "worklist",
        Value::object([
            ("total", Value::from(work.len())),
            ("items", Value::Array(items)),
        ]),
    );
    Part::plain(out)
}

/// The language hints of design Section 9.6.
fn languages(c: &Ctx<'_>) -> Part {
    let list = lang::hints(c.program)
        .into_iter()
        .map(|h| {
            let examples = h
                .examples
                .iter()
                .map(|e| Value::from(c.namer.text(e)))
                .collect();
            Value::object([
                ("lang", Value::from(h.lang.name())),
                ("count", Value::from(h.count)),
                ("examples", Value::Array(examples)),
                ("hint", Value::from(lang::HINT)),
            ])
        })
        .collect();
    Part::listed(Object::new(), "items", list, None)
}

/// The loader diagnostics by code, with the first places of each code.
fn diagnostics(p: &Program) -> Part {
    let b = p.binary();
    let mut by: BTreeMap<&'static str, (u64, Vec<Value>)> = BTreeMap::new();
    for d in &b.diagnostics {
        let slot = by.entry(d.code.name()).or_default();
        slot.0 = slot.0.saturating_add(1);
        if slot.1.len() < DIAG_PLACES {
            let mut place = Object::new();
            place.push("path", Value::from(fs::safe(&d.path)));
            if let Some(off) = d.offset {
                place.push("offset", fs::hex(off));
            }
            slot.1.push(Value::Object(place));
        }
    }
    let list = by
        .into_iter()
        .map(|(code, (count, places))| {
            Value::object([
                ("code", Value::from(code)),
                ("count", Value::from(count)),
                ("places", Value::Array(places)),
            ])
        })
        .collect();
    let mut head = Object::new();
    let total = u64::try_from(b.diagnostics.len())
        .unwrap_or(u64::MAX)
        .saturating_add(b.diagnostics_dropped);
    head.push("total", Value::from(total));
    let mut part = Part::listed(Object::new(), "items", list, None);
    part.head = head;
    part
}
