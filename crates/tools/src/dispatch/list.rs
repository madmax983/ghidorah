//! The list steps of the pipeline: set filter, cursor, count, limit, projection, table and trim.

use ghidorah_base::ErrorCode;
use ghidorah_json::pointer::{Pointer, Segment};
use ghidorah_json::{Object, Value};

use super::{Call0, Ctx, CursorCall, Item, ListPayload, SortKey, Total, first_page};
use crate::api::Host;
use crate::args::Shape;
use crate::budget::{MAX_LIMIT, fit_items};
use crate::content::result_chars;
use crate::envelope::{Body, Envelope, Page};
use crate::errors::{ToolError, int};
use crate::hints::{Call, HINT_NEXT_PAGE, HINT_TOO_BIG};

/// The rows of a list result and the members around them.
struct Rows {
    /// The members before the rows, for example `cols`.
    head: Object,
    /// The member name of the rows: `items` or `rows`. `None` when a projection drops them.
    key: Option<&'static str>,
    /// The rows.
    list: Vec<Value>,
    /// The members after the rows.
    tail: Object,
}

impl Rows {
    /// Gives `data` with the first `k` rows.
    fn data(&self, k: usize) -> Value {
        let mut out = self.head.clone();
        if let Some(key) = self.key {
            out.push(
                key,
                Value::Array(self.list.iter().take(k).cloned().collect()),
            );
        }
        for (name, value) in self.tail.iter() {
            out.push(name, value.clone());
        }
        Value::Object(out)
    }
}

/// Splits `data` into its rows and the members around them. The table form puts `cols` first.
fn split(data: Value, shape: Shape) -> Rows {
    let mut out = Rows {
        head: Object::new(),
        key: None,
        list: Vec::new(),
        tail: Object::new(),
    };
    let members = match data {
        Value::Object(object) => object.into_members(),
        other => vec![("data".to_owned(), other)],
    };
    let mut items = None;
    for (name, value) in members {
        match (name.as_str(), value, &items) {
            ("items", Value::Array(list), None) => items = Some(list),
            (_, value, None) => out.head.push(name, value),
            (_, value, Some(_)) => out.tail.push(name, value),
        }
    }
    let Some(items) = items else {
        return out;
    };
    if shape == Shape::Objects {
        out.key = Some("items");
        out.list = items;
        return out;
    }
    let mut cols: Vec<String> = Vec::new();
    for object in items.iter().filter_map(Value::as_object) {
        for (name, _) in object.iter() {
            if !cols.iter().any(|c| c == name) {
                cols.push(name.to_owned());
            }
        }
    }
    out.list = items
        .iter()
        .map(|item| {
            Value::Array(
                cols.iter()
                    .map(|c| item.get(c).cloned().unwrap_or_default())
                    .collect(),
            )
        })
        .collect();
    out.head.push(
        "cols",
        Value::Array(cols.into_iter().map(Value::from).collect()),
    );
    out.key = Some("rows");
    out
}

/// Gives the parts of `value` that `paths` select. `*` maps over the items of an array.
fn pick(value: &Value, paths: &[&[Segment]]) -> Option<Value> {
    if paths.iter().any(|p| p.is_empty()) {
        return Some(value.clone());
    }
    match value {
        Value::Object(object) => {
            let mut out = Object::new();
            for (name, member) in object.iter() {
                let sub: Vec<&[Segment]> = paths
                    .iter()
                    .filter_map(|p| match p.split_first() {
                        Some((Segment::Key(k), rest)) if k == name => Some(rest),
                        _ => None,
                    })
                    .collect();
                if let (false, Some(v)) = (sub.is_empty(), pick(member, &sub)) {
                    out.push(name, v);
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let index = i.to_string();
                let mut star = false;
                let sub: Vec<&[Segment]> = paths
                    .iter()
                    .filter_map(|p| match p.split_first() {
                        Some((Segment::Star, rest)) => {
                            star = true;
                            Some(rest)
                        }
                        Some((Segment::Key(k), rest)) if *k == index => Some(rest),
                        _ => None,
                    })
                    .collect();
                match pick(item, &sub) {
                    Some(v) if !sub.is_empty() => out.push(v),
                    _ if star => out.push(empty_like(item)),
                    _ => {}
                }
            }
            (!out.is_empty()).then_some(Value::Array(out))
        }
        _ => None,
    }
}

/// Gives an empty value of the same kind: `{}` for an object, `[]` for an array, else `null`.
fn empty_like(value: &Value) -> Value {
    match value {
        Value::Object(_) => Value::Object(Object::new()),
        Value::Array(_) => Value::Array(Vec::new()),
        _ => Value::Null,
    }
}

/// Keeps only the parts of `data` that `pointers` select (the `fields` argument).
pub(super) fn project(data: &Value, pointers: &[Pointer]) -> Value {
    let paths: Vec<&[Segment]> = pointers.iter().map(Pointer::segments).collect();
    pick(data, &paths).unwrap_or_else(|| empty_like(data))
}

/// The state of one page: the rows, their keys and the page facts.
struct Pager<'a, S: Host> {
    host: &'a S,
    ctx: &'a Ctx,
    next: &'a [Call],
    cursor: CursorCall<'a>,
    rows: Rows,
    keys: Vec<SortKey>,
    /// `true` when the limit cut items.
    beyond_limit: bool,
    base: Page,
    narrow: String,
}

impl<S: Host> Pager<'_, S> {
    fn envelope(&self, data: Value, page: Page) -> Envelope {
        Envelope {
            frame: self.ctx.frame.clone(),
            body: Body::Ok {
                data,
                page: Some(page),
                warnings: self.ctx.warnings.clone(),
                mutation: self.ctx.mutation.clone(),
            },
            next: self.next.to_vec(),
        }
    }

    /// Gives the page facts of a page with the first `k` rows.
    fn page(&self, k: usize) -> Page {
        let n = self.rows.list.len();
        let truncated = self.beyond_limit || k < n;
        let aligned = n == self.keys.len();
        let cursor = match (truncated && aligned, k.checked_sub(1)) {
            (true, Some(prev)) => self
                .keys
                .get(prev)
                .map(|key| self.host.encode_cursor(&self.cursor, key)),
            _ => None,
        };
        let hint = match (truncated, k) {
            (false, _) => None,
            (true, 0) if n > 0 => Some(HINT_TOO_BIG.to_owned()),
            (true, _) => Some(self.narrow.clone()),
        };
        Page {
            returned: u64::try_from(k).unwrap_or(u64::MAX),
            truncated,
            next_cursor: cursor,
            hint,
            ..self.base.clone()
        }
    }

    fn size(&self, envelope: &Envelope) -> u64 {
        result_chars(&envelope.to_json(), false, self.ctx.budget.mode)
    }

    /// Gives the page with the most rows that fits the budget (kernel K6).
    fn fit(&self) -> Result<Envelope, ToolError> {
        let n = self.rows.list.len();
        let limit = self.ctx.budget.limit();
        let full = self.envelope(self.rows.data(n), self.page(n));
        if self.size(&full) <= limit {
            return Ok(full);
        }
        // The estimate has no cursor, so it never costs more than a real page.
        let estimate = Page {
            truncated: true,
            hint: Some(self.narrow.clone()),
            ..self.base.clone()
        };
        let overhead = self.size(&self.envelope(self.rows.data(0), estimate));
        let texts: Vec<String> = self.rows.list.iter().map(ghidorah_json::write).collect();
        let mut k = fit_items(&texts, overhead, limit, self.ctx.budget.mode).min(n);
        loop {
            let candidate = self.envelope(self.rows.data(k), self.page(k));
            let chars = self.size(&candidate);
            if chars <= limit {
                return Ok(candidate);
            }
            let Some(fewer) = k.checked_sub(1) else {
                return Err(ToolError::new(ErrorCode::OutputBudgetExceeded)
                    .detail("chars", int(chars))
                    .detail("limit", int(limit)));
            };
            k = fewer;
        }
    }
}

/// Applies the `in` filter and the cursor. Gives the items left, the total and the bound flag.
fn select<S: Host>(
    call: &Call0<'_, S>,
    host: &S,
    ctx: &Ctx,
    cursor: &CursorCall<'_>,
    mut items: Vec<Item>,
    total: Total,
) -> Result<(Vec<Item>, u64, bool), ToolError> {
    let globals = call.args.globals();
    items.sort_by(|a, b| a.key.cmp(&b.key));
    let (mut total, mut lower) = match total {
        Total::Items => (u64::try_from(items.len()).unwrap_or(u64::MAX), false),
        Total::Exact(n) => (n, false),
        Total::AtLeast(n) => (n, true),
    };
    if let Some(set) = &globals.in_set {
        let members = host.members(&ctx.frame, set)?;
        items.retain(|item| members.holds(&item.value));
        total = u64::try_from(items.len()).unwrap_or(u64::MAX);
        lower = false;
    }
    if let Some(text) = &globals.cursor {
        let after = host
            .decode_cursor(cursor, text)
            .map_err(|e| first_page(call, e))?;
        items.retain(|item| item.key > after);
    }
    Ok((items, total, lower))
}

/// Shapes, pages and trims a list payload into its envelope.
pub(super) fn shape<S: Host>(
    call: &Call0<'_, S>,
    host: &S,
    ctx: &Ctx,
    list: ListPayload,
    next: &[Call],
) -> Result<Envelope, ToolError> {
    let globals = call.args.globals();
    let cursor = CursorCall {
        tool_index: call.index,
        tool: call.tool.name,
        args: call.args,
        frame: &ctx.frame,
    };
    let (mut items, total, lower) = select(call, host, ctx, &cursor, list.items, list.total)?;
    let base = Page {
        total,
        lower_bound: lower,
        ..Page::default()
    };
    let mut pager = Pager {
        host,
        ctx,
        next,
        cursor,
        rows: split(Value::Null, Shape::Objects),
        keys: Vec::new(),
        beyond_limit: false,
        base,
        narrow: list.narrow.unwrap_or_else(|| HINT_NEXT_PAGE.to_owned()),
    };
    if globals.count_only {
        let data = Value::object([("count", int(total))]);
        return Ok(pager.envelope(data, pager.base.clone()));
    }
    let default_limit = call.tool.list.map_or(MAX_LIMIT, |l| l.default_limit);
    let limit = usize::try_from(globals.limit.unwrap_or(default_limit)).unwrap_or(usize::MAX);
    pager.beyond_limit = items.len() > limit;
    items.truncate(limit);
    pager.keys = items.iter().map(|item| item.key.clone()).collect();
    let mut data = Object::new();
    data.push(
        "items",
        Value::Array(items.into_iter().map(|item| item.value).collect()),
    );
    for (name, value) in list.extra.into_members() {
        data.push(name, value);
    }
    let mut data = Value::Object(data);
    if !globals.fields.is_empty() {
        data = project(&data, &globals.fields);
    }
    pager.rows = split(data, globals.shape);
    pager.fit()
}
