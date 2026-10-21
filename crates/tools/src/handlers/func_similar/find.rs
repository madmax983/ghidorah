//! The query step of `func_similar`: the targets, the ranked matches and the name proposals.
//!
//! A proposal needs the four rules of [`propose`]. The rank-1 candidate must also be the first
//! match, so `min_score` can hide it. The margin of rule 4 reads every ranked candidate, so
//! `limit` does not change a proposal. A name that needs an escape gives no proposal.
//!
//! The evidence is the texts of the top features of the rank-1 match. A text with an escape or
//! with more than 200 characters stays out, so each entry is valid for `symbol_rename`.

use ghidorah_analysis::similar::{Index, Match, Named, Scope, Scored, propose};
use ghidorah_base::{Address, BinaryId, ErrorCode, FuncId, OutOfFuel};
use ghidorah_db::{Program, Source};
use ghidorah_json::Value;

use super::super::func_sections as fs;
use crate::args::Args;
use crate::dispatch::Ctx;
use crate::errors::ToolError;
use crate::handlers::symbol_rename::{MAX_EVIDENCE, MAX_EVIDENCE_CHARS};
use crate::session::Session;

/// The query arguments of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opts {
    /// The candidate set.
    pub scope: Scope,
    /// The lowest score of a match.
    pub min_score: u32,
    /// The largest number of matches of one item.
    pub limit: usize,
    /// `propose_names`.
    pub propose: bool,
}

impl Opts {
    /// Gives the options of the parsed arguments `args`.
    #[must_use]
    pub fn of(args: &Args) -> Self {
        let int = |name: &str, default: i64| args.int(name).unwrap_or(default);
        Self {
            scope: args
                .str("scope")
                .and_then(Scope::parse)
                .unwrap_or(Scope::Binary),
            min_score: u32::try_from(int("min_score", super::DEFAULT_MIN_SCORE)).unwrap_or(0),
            limit: usize::try_from(int("limit", super::DEFAULT_LIMIT)).unwrap_or(0),
            propose: args.bool("propose_names").unwrap_or(false),
        }
    }
}

/// A name proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The proposed name: the name of the rank-1 match.
    pub name: String,
    /// The document of the rank-1 match.
    pub from: usize,
    /// The rank-1 score.
    pub score: u32,
    /// The texts of the top features of the rank-1 match.
    pub evidence: Vec<String>,
}

/// The result of one target.
#[derive(Debug, Clone)]
pub enum Item {
    /// The query document, its matches and its proposal.
    Found {
        /// The query document.
        doc: usize,
        /// The explained matches in match order.
        matches: Vec<Match>,
        /// The name proposal.
        proposal: Option<Proposal>,
    },
    /// A target that does not resolve.
    Bad {
        /// The input of the target.
        input: Value,
        /// The error.
        error: ToolError,
    },
}

/// Gives the program of the open binary `id`.
pub fn program_of(session: &Session, id: BinaryId) -> Option<&Program> {
    session.binary(id).map(|b| &b.program)
}

/// Gives the program and the name of the document `doc`.
fn name_of(session: &Session, index: &Index, doc: usize) -> Option<(String, Source)> {
    let d = index.docs().get(doc)?;
    let n = program_of(session, d.binary)?.name(d.func.0)?;
    Some((n.text, n.source))
}

/// Resolves one target to a function of the bound program.
fn resolve(program: &Program, input: &Value, path: &str) -> Result<FuncId, ToolError> {
    let (func, _) = crate::resolve::function(program, input, &fs::site(path))?;
    if program.func(func).is_none() {
        return Err(ToolError::new(ErrorCode::NotFound)
            .var("kind", "function")
            .path(path)
            .detail("kind", Value::from("function")));
    }
    Ok(func)
}

/// Why the query step stopped before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// The ranking ran out of fuel.
    Fuel,
    /// The client cancelled the request.
    Cancel,
    /// The `max_ms` guard of the call fired.
    Time,
}

impl Halt {
    /// Gives the `details.stopped_by` value of the stop: `fuel`, `cancel` or `time`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fuel => "fuel",
            Self::Cancel => "cancel",
            Self::Time => "time",
        }
    }
}

impl From<OutOfFuel> for Halt {
    fn from(_: OutOfFuel) -> Self {
        Self::Fuel
    }
}

/// Puts the result of each target of the call in `out`, in input order. Before each target
/// the loop checks the cancel flag. Before each target after the first, it checks the
/// `max_ms` guard of `ctx`: the guard started at the monotonic time `began`. So the first
/// target always runs, and each call makes progress. After a stop, `out` holds the results of
/// the targets before it.
///
/// # Errors
///
/// Returns [`Halt::Fuel`] when the ranking runs out of the fuel of `ctx`, [`Halt::Cancel`]
/// after a cancel, and [`Halt::Time`] when the guard fires.
pub fn find(
    session: &Session,
    index: &Index,
    bound: BinaryId,
    args: &Args,
    ctx: &mut Ctx,
    began: u64,
    out: &mut Vec<Item>,
) -> Result<(), Halt> {
    let opts = Opts::of(args);
    let Some(program) = program_of(session, bound) else {
        return Ok(());
    };
    let (inputs, name) = match args.list("targets") {
        Some(list) => (list.to_vec(), "targets"),
        None => (
            vec![args.get("target").cloned().unwrap_or_default()],
            "target",
        ),
    };
    out.reserve(inputs.len());
    for (i, input) in inputs.into_iter().enumerate() {
        if ctx.cancelled() {
            return Err(Halt::Cancel);
        }
        if i > 0 && session.past_max_ms(began, ctx.max_ms) {
            return Err(Halt::Time);
        }
        let path = if name == "targets" {
            fs::item_path(name, i)
        } else {
            "/target".to_owned()
        };
        let func = match resolve(program, &input, &path) {
            Ok(func) => func,
            Err(error) => {
                out.push(Item::Bad { input, error });
                continue;
            }
        };
        let Some(doc) = index.position(bound, func) else {
            let error = ToolError::new(ErrorCode::NotFound)
                .var("kind", "function")
                .path(&path)
                .detail("kind", Value::from("function"));
            out.push(Item::Bad { input, error });
            continue;
        };
        let ranked = index.ranked(doc, opts.scope, &mut ctx.fuel)?;
        let matches: Vec<Match> = ranked
            .iter()
            .filter(|s| s.score >= opts.min_score)
            .take(opts.limit)
            .map(|s| index.explain(doc, s.doc))
            .collect();
        let proposal = if opts.propose {
            proposal(session, index, doc, &ranked, &matches)
        } else {
            None
        };
        out.push(Item::Found {
            doc,
            matches,
            proposal,
        });
    }
    Ok(())
}

/// Gives the proposal of the query `doc` by the rules of the module doc.
fn proposal(
    session: &Session,
    index: &Index,
    doc: usize,
    ranked: &[Scored],
    matches: &[Match],
) -> Option<Proposal> {
    let first = ranked.first()?;
    let top = matches.first().filter(|m| m.doc == first.doc)?;
    let (_, query) = name_of(session, index, doc)?;
    let (name, source) = name_of(session, index, first.doc)?;
    if fs::safe(&name) != name {
        return None;
    }
    let mut named = vec![Named {
        name: &name,
        source,
        score: first.score,
    }];
    let other = ranked.iter().skip(1).find_map(|s| {
        name_of(session, index, s.doc)
            .filter(|(n, _)| *n != name)
            .map(|(n, src)| (n, src, s.score))
    });
    if let Some((n, src, score)) = &other {
        named.push(Named {
            name: n,
            source: *src,
            score: *score,
        });
    }
    if !propose(query, &named) {
        return None;
    }
    let evidence = top
        .top
        .iter()
        .map(|t| t.text.clone())
        .filter(|t| t.chars().count() <= MAX_EVIDENCE_CHARS && fs::safe(t) == *t)
        .take(MAX_EVIDENCE)
        .collect();
    Some(Proposal {
        name,
        from: first.doc,
        score: first.score,
        evidence,
    })
}

/// Gives the `fn:` ID text of the document `doc`.
pub fn id_of(index: &Index, doc: usize) -> String {
    index
        .docs()
        .get(doc)
        .map_or_else(String::new, |d| d.func.to_string())
}

/// Gives the address of the document `doc`.
pub fn addr_of(index: &Index, doc: usize) -> Address {
    index.docs().get(doc).map_or(Address::ram(0), |d| d.func.0)
}
