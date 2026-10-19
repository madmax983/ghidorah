//! The output step of `func_similar`: the items, the renames, the budget cut and the hints.
//!
//! Budget cut: while the result is larger than the room of the call, the step removes the
//! last match of the longest match list. A later item loses a match first when two lists have
//! the same length. `omitted.matches` counts the removed matches.

use ghidorah_analysis::similar::{Index, Match};
use ghidorah_base::BinaryId;
use ghidorah_json::{Object, Value};

use super::super::func_sections::{self as fs, Namer};
use super::find::{Item, Opts, Proposal, addr_of, id_of, program_of};
use super::{RENAME_LABEL, WHY_BEST, WHY_RENAME};
use crate::api::Host;
use crate::args::Args;
use crate::batch::MAX_FUEL;
use crate::dispatch::Ctx;
use crate::hints::Call;
use crate::session::Session;

/// The reads of one render.
pub struct View<'a> {
    /// The session.
    pub session: &'a Session,
    /// The corpus index.
    pub index: &'a Index,
    /// The namer of the result.
    pub namer: Namer,
}

impl View<'_> {
    /// Gives the binary ID text of the document `doc`.
    fn binary_text(&self, doc: usize) -> String {
        self.index
            .docs()
            .get(doc)
            .map_or_else(String::new, |d| d.binary.to_string())
    }

    /// Gives the output name of the document `doc`.
    fn name(&self, doc: usize) -> String {
        let addr = addr_of(self.index, doc);
        self.index
            .docs()
            .get(doc)
            .and_then(|d| program_of(self.session, d.binary))
            .map_or_else(|| addr.to_string(), |p| self.namer.of(p, addr))
    }

    /// Gives the `query` object of the document `doc`.
    fn query(&self, doc: usize) -> Value {
        let features = self.index.docs().get(doc).map_or(0, |d| d.vector.len());
        Value::object([
            ("id", Value::from(id_of(self.index, doc))),
            ("binary_id", Value::from(self.binary_text(doc))),
            ("name", Value::from(self.name(doc))),
            (
                "features",
                Value::from(u64::try_from(features).unwrap_or(u64::MAX)),
            ),
        ])
    }

    /// Gives the object of one match.
    fn one_match(&self, m: &Match) -> Value {
        let top: Vec<Value> = m
            .top
            .iter()
            .map(|t| {
                Value::object([
                    ("kind", Value::from(t.kind.name())),
                    ("text", Value::from(fs::safe(&t.text))),
                    ("weight", Value::from(t.weight)),
                ])
            })
            .collect();
        Value::object([
            ("id", Value::from(id_of(self.index, m.doc))),
            ("binary_id", Value::from(self.binary_text(m.doc))),
            ("name", Value::from(self.name(m.doc))),
            ("score", Value::from(m.score)),
            ("shared", Value::from(m.shared)),
            ("total", Value::from(m.total)),
            ("top_features", Value::Array(top)),
        ])
    }

    /// Gives the `proposal` object.
    fn proposal(&self, p: &Proposal) -> Value {
        Value::object([
            ("name", Value::from(p.name.as_str())),
            (
                "from",
                Value::object([
                    ("binary_id", Value::from(self.binary_text(p.from))),
                    ("id", Value::from(id_of(self.index, p.from))),
                ]),
            ),
            ("score", Value::from(p.score)),
            ("evidence", texts(&p.evidence)),
        ])
    }
}

/// Gives a JSON array of texts.
fn texts(list: &[String]) -> Value {
    Value::Array(list.iter().map(|t| Value::from(t.as_str())).collect())
}

/// Gives the renames of the proposals in item order.
fn renames(view: &View<'_>, items: &[Item]) -> Vec<Value> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Found {
                doc,
                proposal: Some(p),
                ..
            } => Some(Value::object([
                ("target", Value::from(id_of(view.index, *doc))),
                ("name", Value::from(p.name.as_str())),
                ("evidence", texts(&p.evidence)),
            ])),
            _ => None,
        })
        .collect()
}

/// Gives the data of the call: the items with their matches cut to the room of `ctx`.
pub fn render(view: &View<'_>, items: &[Item], ctx: &Ctx) -> Object {
    let mut lists: Vec<Vec<Value>> = items
        .iter()
        .map(|item| match item {
            Item::Found { matches, .. } => matches.iter().map(|m| view.one_match(m)).collect(),
            Item::Bad { .. } => Vec::new(),
        })
        .collect();
    let renames = renames(view, items);
    let room = fs::room(ctx);
    let mut omitted = 0u64;
    loop {
        let out = assemble(view, items, &lists, &renames, omitted);
        let size = fs::chars(ctx, &Value::Object(out.clone()));
        let mut excess = size.saturating_sub(room);
        if excess == 0 {
            return out;
        }
        let mut cut = false;
        while excess > 0 {
            let longest = (0..lists.len())
                .max_by_key(|i| lists.get(*i).map_or(0, Vec::len))
                .filter(|i| lists.get(*i).is_some_and(|l| !l.is_empty()));
            let Some(popped) = longest.and_then(|i| lists.get_mut(i)).and_then(Vec::pop) else {
                break;
            };
            excess = excess.saturating_sub(fs::chars(ctx, &popped).saturating_add(1));
            omitted = omitted.saturating_add(1);
            cut = true;
        }
        if !cut {
            return out;
        }
    }
}

/// Gives the data object of the items with the match lists `lists`.
fn assemble(
    view: &View<'_>,
    items: &[Item],
    lists: &[Vec<Value>],
    renames: &[Value],
    omitted: u64,
) -> Object {
    let list: Vec<Value> = items
        .iter()
        .zip(lists)
        .map(|(item, matches)| match item {
            Item::Found { doc, proposal, .. } => {
                let mut o = Object::new();
                o.push("query", view.query(*doc));
                o.push("matches", Value::Array(matches.clone()));
                if let Some(p) = proposal {
                    o.push("proposal", view.proposal(p));
                }
                Value::Object(o)
            }
            Item::Bad { input, error } => {
                Value::object([("input", input.clone()), ("error", error.to_json())])
            }
        })
        .collect();
    let mut out = Object::new();
    out.push("items", Value::Array(list));
    out.push("renames", Value::Array(renames.to_vec()));
    out.push(
        "corpus",
        Value::object([
            (
                "binaries",
                Value::from(u64::try_from(view.session.binaries().count()).unwrap_or(u64::MAX)),
            ),
            (
                "functions",
                Value::from(u64::try_from(view.index.len()).unwrap_or(u64::MAX)),
            ),
        ]),
    );
    if omitted > 0 {
        out.push(
            "omitted",
            Value::object([("matches", Value::from(omitted))]),
        );
    }
    out
}

/// Adds the `next` calls: the rename batch of the proposals and `func_get` on the best match.
pub fn hints(view: &View<'_>, bound: BinaryId, args: &Args, items: &[Item], ctx: &mut Ctx) {
    let session = view.session;
    let proposals = items.iter().any(|i| {
        matches!(
            i,
            Item::Found {
                proposal: Some(_),
                ..
            }
        )
    });
    let writable = session.binary(bound).is_some_and(|b| !b.read_only);
    if proposals
        && writable
        && session.in_profile("symbol_rename")
        && session.in_profile("batch_run")
    {
        ctx.next.push(Call::new(
            "batch_run",
            batch(view.index, bound, args, items),
            WHY_RENAME,
        ));
    }
    let best = items.iter().find_map(|i| match i {
        Item::Found { matches, .. } => matches.first(),
        Item::Bad { .. } => None,
    });
    if let Some(m) = best {
        ctx.next.push(Call::new(
            "func_get",
            Value::object([
                ("binary_id", Value::from(view.binary_text(m.doc))),
                ("target", Value::from(id_of(view.index, m.doc))),
            ]),
            WHY_BEST,
        ));
    }
}

/// Gives the arguments of the rename batch: step `s1` repeats the call with `fn:` IDs, and
/// step `s2` renames through a reference to the renames of `s1`.
fn batch(index: &Index, bound: BinaryId, args: &Args, items: &[Item]) -> Value {
    let opts = Opts::of(args);
    let targets: Vec<Value> = items
        .iter()
        .filter_map(|i| match i {
            Item::Found { doc, .. } => Some(Value::from(id_of(index, *doc))),
            Item::Bad { .. } => None,
        })
        .collect();
    let s1 = Value::object([
        ("targets", Value::Array(targets)),
        ("scope", Value::from(opts.scope.name())),
        ("min_score", Value::from(opts.min_score)),
        ("limit", Value::from(u64::try_from(opts.limit).unwrap_or(0))),
        ("propose_names", Value::Bool(true)),
    ]);
    let reference = Value::object([
        ("$ref", Value::from("s1")),
        ("ptr", Value::from("/data/renames")),
    ]);
    Value::object([
        ("binary_id", Value::from(bound.to_string())),
        ("label", Value::from(RENAME_LABEL)),
        ("max_steps", Value::from(MAX_FUEL)),
        (
            "steps",
            Value::Array(vec![
                Value::object([
                    ("id", Value::from("s1")),
                    ("tool", Value::from("func_similar")),
                    ("args", s1),
                ]),
                Value::object([
                    ("id", Value::from("s2")),
                    ("tool", Value::from("symbol_rename")),
                    ("args", Value::object([("items", reference)])),
                ]),
            ]),
        ),
    ])
}
