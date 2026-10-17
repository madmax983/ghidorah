//! The query, the scope and the item list of one `search` call.

use ghidorah_base::{Address, ErrorCode, FuncId, Glob};
use ghidorah_db::Program;
use ghidorah_json::{Object, Value};

use super::ORDER;
use crate::args::Args;
use crate::dispatch::{Item, KeyPart, SortKey};
use crate::errors::ToolError;
use crate::handlers::func_sections as fs;

/// How a query matches a text.
pub enum Matcher {
    /// Every text matches: the query is empty.
    All,
    /// A part of the text, with no regard to the ASCII letter case.
    Substr(String),
    /// A glob over the whole text.
    Glob(Glob),
    /// The exact text.
    Exact(String),
}

impl Matcher {
    /// Reads the query and the match mode of the call.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a glob that does not parse.
    pub fn of(args: &Args) -> Result<Self, ToolError> {
        let query = args.str("query").unwrap_or_default();
        if query.is_empty() {
            return Ok(Self::All);
        }
        Ok(match args.str("match").unwrap_or("substr") {
            "glob" => Self::Glob(fs::glob(query, "/query")?),
            "exact" => Self::Exact(query.to_owned()),
            _ => Self::Substr(query.to_ascii_lowercase()),
        })
    }

    /// Tells if `text` matches.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        match self {
            Self::All => true,
            Self::Substr(q) => text.to_ascii_lowercase().contains(q.as_str()),
            Self::Glob(g) => g.matches(text),
            Self::Exact(q) => text == q,
        }
    }
}

/// The scope of one call: the address ranges and the permissions that items must have.
#[derive(Default)]
pub struct Scope {
    ranges: Vec<(u64, u64)>,
    perms: Option<ghidorah_loader::Perms>,
    body: Option<FuncId>,
    given: bool,
}

/// Gives `INVALID_ARGUMENT` for the scope member `name`.
fn bad_scope(name: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", name)
        .path(&format!("/scope/{name}"))
        .detail("expected", Value::from(expected))
}

impl Scope {
    /// Reads the scope of the call.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for an unknown section, bad permissions or a bad range, and
    /// the errors of the resolver.
    pub fn of(p: &Program, args: &Args) -> Result<Self, ToolError> {
        let Some(scope) = args.get("scope") else {
            return Ok(Self::default());
        };
        let mut out = Self {
            given: true,
            ..Self::default()
        };
        if let Some(name) = scope.get("section").and_then(Value::as_str) {
            let found: Vec<(u64, u64)> = p
                .binary()
                .sections
                .iter()
                .filter(|s| s.name.as_str() == Some(name))
                .filter_map(|s| s.va.map(|r| (r.first, r.last)))
                .collect();
            if found.is_empty() {
                return Err(bad_scope("section", "the name of a mapped section"));
            }
            out.ranges = found;
        }
        if let Some(start) = scope.get("start") {
            let (a, _) = crate::resolve::address(p, start, &fs::site("/scope/start"))?;
            let size = match scope.get("size") {
                Some(v) => {
                    let text = v.as_str().unwrap_or_default();
                    ghidorah_base::hex::parse_u64(text)
                        .or_else(|| v.as_u64())
                        .ok_or_else(|| bad_scope("size", "a 0x hex size"))?
                }
                None => 1,
            };
            let last = a
                .off
                .checked_add(size.max(1) - 1)
                .ok_or_else(|| bad_scope("size", "a range that does not wrap"))?;
            out.ranges.push((a.off, last));
        }
        if let Some(text) = scope.get("perms").and_then(Value::as_str) {
            let mut bits = ghidorah_loader::Perms::NONE;
            for c in text.chars() {
                let bit = match c {
                    'r' => ghidorah_loader::Perms::READ,
                    'w' => ghidorah_loader::Perms::WRITE,
                    'x' => ghidorah_loader::Perms::EXECUTE,
                    _ => return Err(bad_scope("perms", "the letters r, w and x")),
                };
                bits = bits.union(bit);
            }
            out.perms = Some(bits);
        }
        if let Some(target) = scope.get("func") {
            let (f, _) = crate::resolve::function(p, target, &fs::site("/scope/func"))?;
            out.body = Some(f);
        }
        Ok(out)
    }

    /// Tells if an item at `addr` is in the scope. With a scope, an item with no RAM address
    /// is out of it.
    #[must_use]
    pub fn holds(&self, p: &Program, addr: Option<Address>) -> bool {
        if !self.given {
            return true;
        }
        let Some(a) = addr.filter(Address::is_ram) else {
            return false;
        };
        let in_range =
            self.ranges.is_empty() || self.ranges.iter().any(|(f, l)| *f <= a.off && a.off <= *l);
        let perms = self.perms.is_none_or(|bits| {
            p.mem()
                .region_at(a.off)
                .is_some_and(|r| r.perms.contains(bits))
        });
        let body = self.body.is_none_or(|f| p.owner_of(a) == Some(f));
        in_range && perms && body
    }
}

/// The items of one call and their place rules.
pub struct Items<'a> {
    /// The program.
    pub program: &'a Program,
    /// The scope.
    pub scope: Scope,
    /// The items so far.
    pub list: Vec<Item>,
    /// `true` when the fuel ran out before the end of the search.
    pub cut: bool,
}

/// One new item: `{ kind, id, addr?, text?, func?, extra }`.
pub struct New {
    /// The entity kind of [`ORDER`].
    pub kind: &'static str,
    /// The ID.
    pub id: String,
    /// The address.
    pub addr: Option<Address>,
    /// The text: a plain text or binary text.
    pub text: Option<Value>,
    /// The function of the item.
    pub func: Option<FuncId>,
    /// The other members.
    pub extra: Object,
    /// The order of items with an equal kind, address and ID.
    pub seq: u64,
}

impl New {
    /// Makes an item with no address, text, function or extra member.
    #[must_use]
    pub fn item(kind: &'static str, id: String) -> Self {
        Self {
            kind,
            id,
            addr: None,
            text: None,
            func: None,
            extra: Object::new(),
            seq: 0,
        }
    }
}

impl Items<'_> {
    /// Adds the item `new` when it is in the scope. `next` is an optional call of the item.
    pub fn push(&mut self, new: New, next: Option<Value>) {
        if !self.scope.holds(self.program, new.addr) {
            return;
        }
        let order = ORDER
            .iter()
            .position(|k| *k == new.kind)
            .unwrap_or(ORDER.len());
        let (space, off) = new
            .addr
            .map_or((0, 0), |a| (u64::from(a.space.code()), a.off));
        let key = SortKey(vec![
            KeyPart::Int(u64::try_from(order).unwrap_or(u64::MAX)),
            KeyPart::Int(space),
            KeyPart::Int(off),
            KeyPart::Text(new.id.clone()),
            KeyPart::Int(new.seq),
        ]);
        let mut out = Object::new();
        out.push("kind", Value::from(new.kind));
        out.push("id", Value::from(new.id));
        if let Some(a) = new.addr {
            out.push("addr", fs::addr(a));
        }
        if let Some(text) = new.text {
            out.push("text", text);
        }
        if let Some(f) = new.func {
            out.push("func", Value::from(f.to_string()));
        }
        out.push("extra", Value::Object(new.extra));
        if let Some(next) = next {
            out.push("next", next);
        }
        self.list.push(Item {
            key,
            value: Value::Object(out),
        });
    }
}
