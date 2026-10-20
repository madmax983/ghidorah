//! The render of one function of `func_get`: the header, the sections within their shares and
//! the `omitted` and `budgets` members.

use ghidorah_base::{ErrorCode, Fuel, FuncId};
use ghidorah_db::PartKind;
use ghidorah_json::{Object, Value};

use super::{MIN_SHARE, remedy};
use crate::args::Args;
use crate::budget::section_weight;
use crate::content::{self, ContentMode};
use crate::dispatch::{KeyPart, SortKey};
use crate::envelope::Frame;
use crate::errors::ToolError;
use crate::handlers::func_sections::{self as fs, CursorScope, Render};
use crate::session::Session;

/// The characters of the `omitted` entry of one section.
const OMITTED_ENTRY: u64 = 32;

/// The characters of the `budgets` row of one section in the detailed format.
const BUDGET_ENTRY: u64 = 96;

/// The arguments that a section cursor does not bind.
const CURSOR_FREE: [&str; 3] = ["cursors", "disasm_limit", "include"];

/// The section cursors of the call: the function entry and the last row address of each.
/// The decompile cursor holds the entry and the number of the next line.
#[derive(Debug, Default)]
pub struct Cursors {
    disasm: Option<(u64, u64)>,
    ir: Option<(u64, u64)>,
    decomp: Option<(u64, u64)>,
}

/// Gives the `(entry, after)` pair of a cursor key.
fn pair(key: &SortKey) -> Option<(u64, u64)> {
    match key.0.as_slice() {
        [KeyPart::Int(entry), KeyPart::Int(after)] => Some((*entry, *after)),
        _ => None,
    }
}

/// The parts of one call that every function render shares.
pub struct Job<'a> {
    /// The parts of a section render.
    pub render: Render<'a>,
    /// The sections of the call in include order.
    pub include: &'a [&'static str],
    /// The most rows of one row section.
    pub limit: usize,
    /// The section cursors of the call.
    pub cursors: Cursors,
    /// The session of the call.
    pub session: &'a Session,
    /// The frame of the call.
    pub frame: &'a Frame,
    /// The arguments of the call.
    pub args: &'a Args,
    /// The content mode of the result.
    pub mode: ContentMode,
    /// `true` for the detailed format: each function gets its `budgets` member.
    pub detailed: bool,
    /// The window and the passes of the `decomp` section.
    pub decomp: fs::DecompOpts,
    /// `true` when `ir_opts.level` is `l1`.
    pub ir_l1: bool,
}

impl Job<'_> {
    /// Gives the cursor scope of the section byte `section`.
    fn scope(&self, section: u8) -> CursorScope<'_> {
        CursorScope {
            session: self.session,
            frame: self.frame,
            args: self.args,
            drop: &CURSOR_FREE,
            section,
        }
    }

    /// Gives the characters of the member `"name":value,` in the result.
    fn member(&self, name: &str, value: &Value) -> u64 {
        let text = format!("\"{name}\":{},", ghidorah_json::write(value));
        content::cost(&text, self.mode)
    }

    /// Gives the address after which the rows of `entry` start in `section`.
    fn after(&self, section: &str, entry: u64) -> Option<u64> {
        let found = match section {
            "ir" => self.cursors.ir,
            "decomp" => self.cursors.decomp,
            _ => self.cursors.disasm,
        };
        found.filter(|(e, _)| *e == entry).map(|(_, a)| a)
    }

    /// Renders the `decomp` section of `func` within `share`: the most lines of the window
    /// that fit. Gives the value or the omitted entry, the need and the use.
    fn decomp(
        &self,
        func: FuncId,
        share: u64,
        fuel: &mut Fuel,
    ) -> (Result<Value, Value>, u64, u64) {
        let p = self.render.program;
        let entry = func.0.off;
        let out = match fs::decomp_output(p, func, &self.decomp.opts, fuel) {
            Ok(out) => out,
            Err(text) => {
                let value = Value::object([("error", Value::from(text))]);
                let need = self.member("decomp", &value);
                return (Ok(value), need, need);
            }
        };
        let start = self
            .after("decomp", entry)
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(self.decomp.start);
        let scope = self.scope(fs::DECOMP);
        let cursor = |next: usize| {
            let key = SortKey(vec![
                KeyPart::Int(entry),
                KeyPart::Int(u64::try_from(next).unwrap_or(u64::MAX)),
            ]);
            scope.encode(key)
        };
        let caps = self.render.caps;
        let check = |c| remedy::checked(self.session, c);
        let remedies = fs::Remedies {
            program: p,
            func,
            check: &check,
        };
        let window = |k: usize| fs::decomp_value(&remedies, &out, start, k, caps, &cursor);
        let whole = window(self.decomp.count);
        let need = self.member("decomp", &whole);
        if need <= share {
            return (Ok(whole), need, need);
        }
        let (mut lo, mut hi) = (0usize, self.decomp.count);
        let mut best: Option<(Value, u64)> = None;
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            let value = window(mid);
            let used = self.member("decomp", &value);
            if used <= share {
                lo = mid;
                best = Some((value, used));
            } else {
                hi = mid - 1;
            }
        }
        match best {
            Some((value, used)) if lo > 0 => (Ok(value), need, used),
            _ => {
                let omitted = Value::object([("chars", Value::from(fs::size(&whole)))]);
                (Err(omitted), need, 0)
            }
        }
    }
}

/// The result of one row section: the rows, the members before them and the cursor maker.
struct RowSection {
    head: Object,
    rows: Vec<Value>,
    more: bool,
    section: u8,
}

impl RowSection {
    /// Gives the section value with the first `k` rows, and a cursor when rows follow.
    fn value(&self, job: &Job<'_>, entry: u64, k: usize) -> Value {
        let mut out = self.head.clone();
        let rows: Vec<Value> = self.rows.iter().take(k).cloned().collect();
        let key = if self.section == fs::IR {
            "insns"
        } else {
            "rows"
        };
        let last = rows
            .last()
            .and_then(|r| r.get("a"))
            .and_then(Value::as_str)
            .and_then(ghidorah_base::hex::parse_u64);
        out.push(key, Value::Array(rows));
        if let (true, Some(last)) = (self.more || k < self.rows.len(), last) {
            let cursor = SortKey(vec![KeyPart::Int(entry), KeyPart::Int(last)]);
            out.push(
                "next_cursor",
                Value::from(job.scope(self.section).encode(cursor)),
            );
        }
        Value::Object(out)
    }
}

/// Gives the row section `name` of `func`, or `None` for another section. An IR with an
/// `Intrinsic` op adds the entry of `func` to `marks`.
fn row_section(
    job: &Job<'_>,
    name: &str,
    func: FuncId,
    fuel: &mut Fuel,
    marks: &mut Marks,
) -> Option<RowSection> {
    let entry = func.0.off;
    let after = job.after(name, entry);
    let p = job.render.program;
    match name {
        "disasm" => {
            let (rows, more) = fs::body_rows(p, func, after, job.limit, job.render.namer);
            Some(RowSection {
                head: Object::new(),
                rows,
                more,
                section: fs::DISASM,
            })
        }
        "ir" => {
            let mut head = Object::new();
            head.push("level", Value::from(if job.ir_l1 { "l1" } else { "l0" }));
            let rows = if job.ir_l1 {
                fs::l1_rows(p, func, after, job.limit, fuel)
            } else {
                fs::ir_rows(p, func, after, job.limit, fuel)
            };
            let (rows, more) = match rows {
                Ok(ir) => {
                    head.push("lift_ver", Value::from(ir.lift_ver));
                    if ir.intrinsic {
                        marks.intrinsic.push(entry);
                    }
                    (ir.rows, ir.more)
                }
                Err(text) => {
                    head.push("error", Value::from(text));
                    (Vec::new(), false)
                }
            };
            Some(RowSection {
                head,
                rows,
                more,
                section: fs::IR,
            })
        }
        _ => None,
    }
}

/// Gives the header of `func`: its ID, name, entry, size, parts, signature, start reason,
/// confidence, flags and caveats.
fn header(r: &Render<'_>, func: FuncId) -> Result<Object, ToolError> {
    let p = r.program;
    let view = p.func(func).ok_or_else(|| {
        ToolError::new(ErrorCode::NotFound)
            .var("kind", "function")
            .detail("kind", Value::from("function"))
    })?;
    let f = view.func;
    let parts = f
        .parts
        .iter()
        .map(|part| {
            let size = u64::try_from(part.range.len()).unwrap_or(u64::MAX);
            let kind = match part.kind {
                PartKind::Main => "main",
                PartKind::Cold => "cold",
                PartKind::Thunk => "thunk",
            };
            Value::object([
                ("start", fs::hex(part.range.first)),
                ("size", fs::hex(size)),
                ("kind", Value::from(kind)),
            ])
        })
        .collect();
    let signature = view
        .sig
        .and_then(|s| fs::type_text(p, s.value))
        .map_or(Value::Null, Value::from);
    let mut flags = Vec::new();
    if view.noreturn.is_some_and(|n| n.value) {
        flags.push(Value::from("noreturn"));
    }
    if f.flags.thunk {
        flags.push(Value::from("thunk"));
    }
    if f.flags.varargs {
        flags.push(Value::from("varargs"));
    }
    let caveats = f
        .caveats
        .iter()
        .map(|c| {
            let mut out = Object::new();
            out.push("code", Value::from(c.code.info().name));
            if let Some(at) = c.at {
                out.push("at", fs::addr(at));
            }
            if let Some(remedy) = &c.remedy {
                out.push("remedy", Value::from(remedy.as_str()));
            }
            Value::Object(out)
        })
        .collect();
    let mut out = Object::new();
    out.push("id", Value::from(func.to_string()));
    out.push("name", Value::from(r.namer.of(p, func.0)));
    out.push("entry", fs::addr(func.0));
    out.push(
        "size",
        Value::from(u64::try_from(f.size()).unwrap_or(u64::MAX)),
    );
    out.push("parts", Value::Array(parts));
    out.push("signature", signature);
    out.push("start_reason", Value::from(f.start_reason.name()));
    out.push("confidence", Value::from(f.confidence));
    out.push("flags", Value::Array(flags));
    out.push("caveats", Value::Array(caveats));
    Ok(out)
}

/// The budget record of one section: its weight, share, need and use.
struct Spent {
    section: &'static str,
    share: u64,
    need: u64,
    used: u64,
}

/// What one function render gives besides its value.
#[derive(Default)]
pub struct Marks {
    /// The functions that the call marks `visited`.
    pub visited: Vec<FuncId>,
    /// The entries of the functions whose IR holds an `Intrinsic`.
    pub intrinsic: Vec<u64>,
}

/// Gives the most rows of `rows` whose section fits `share`, with the value and its cost.
///
/// The first guess adds the cost of each row to the cost of a one-row section. The exact
/// cost of the guess then decides, and the guess drops rows until it fits.
fn fit_rows(
    job: &Job<'_>,
    name: &str,
    rows: &RowSection,
    entry: u64,
    share: u64,
) -> Option<(Value, u64)> {
    let first = rows.value(job, entry, 1);
    let mut cost = job.member(name, &first);
    let sep = job.mode.copies();
    let mut k = 1;
    for row in rows.rows.iter().skip(1) {
        let next = cost
            .saturating_add(content::cost(&ghidorah_json::write(row), job.mode))
            .saturating_add(sep);
        if next > share {
            break;
        }
        cost = next;
        k += 1;
    }
    while k > 0 {
        let value = rows.value(job, entry, k);
        let exact = job.member(name, &value);
        if exact <= share {
            return Some((value, exact));
        }
        k -= 1;
    }
    None
}

/// Renders one section of `func` within `share`. Gives the value or the omitted entry, the
/// characters that the full section needs and the characters that the result uses.
fn render_section(
    job: &Job<'_>,
    name: &'static str,
    func: FuncId,
    share: u64,
    fuel: &mut Fuel,
    marks: &mut Marks,
) -> (Result<Value, Value>, u64, u64) {
    if name == "decomp" {
        return job.decomp(func, share, fuel);
    }
    let entry = func.0.off;
    let (whole, section) = match row_section(job, name, func, fuel, marks) {
        Some(rs) => (rs.value(job, entry, rs.rows.len()), Some(rs)),
        None => (
            fs::section(&job.render, name, func).unwrap_or(Value::Null),
            None,
        ),
    };
    let need = job.member(name, &whole);
    if need <= share {
        return (Ok(whole), need, need);
    }
    if let Some((value, used)) = section.and_then(|r| fit_rows(job, name, &r, entry, share)) {
        return (Ok(value), need, used);
    }
    let omitted = Value::object([("chars", Value::from(fs::size(&whole)))]);
    (Err(omitted), need, 0)
}

/// Renders `func` within `budget` characters.
///
/// # Errors
///
/// `NOT_FOUND` when `func` is not a function of the program.
pub fn one(
    job: &Job<'_>,
    func: FuncId,
    budget: u64,
    fuel: &mut Fuel,
    marks: &mut Marks,
) -> Result<Value, ToolError> {
    let mut out = header(&job.render, func)?;
    let count = u64::try_from(job.include.len()).unwrap_or(u64::MAX);
    let mut entry_cost = OMITTED_ENTRY;
    if job.detailed {
        entry_cost = entry_cost.saturating_add(BUDGET_ENTRY);
    }
    let total = budget
        .saturating_sub(content::cost(
            &ghidorah_json::write(&Value::Object(out.clone())),
            job.mode,
        ))
        .saturating_sub(entry_cost.saturating_mul(count));
    let mut free = u128::from(total);
    let mut left: u128 = job
        .include
        .iter()
        .map(|s| u128::from(section_weight(s)))
        .sum();
    let mut omitted = Object::new();
    let mut spent = Vec::new();
    for name in job.include {
        let weight = u128::from(section_weight(name));
        let share = u64::try_from(free.saturating_mul(weight) / left.max(1)).unwrap_or(u64::MAX);
        left = left.saturating_sub(weight);
        if share < MIN_SHARE {
            omitted.push(*name, Value::Null);
            spent.push(Spent {
                section: name,
                share,
                need: 0,
                used: 0,
            });
            continue;
        }
        let (value, need, used) = render_section(job, name, func, share, fuel, marks);
        match value {
            Ok(v) => out.push(*name, v),
            Err(entry) => omitted.push(*name, entry),
        }
        free = free.saturating_sub(u128::from(used));
        spent.push(Spent {
            section: name,
            share,
            need,
            used,
        });
    }
    if job
        .include
        .iter()
        .any(|s| matches!(*s, "disasm" | "ir" | "decomp"))
    {
        marks.visited.push(func);
    }
    if !omitted.is_empty() {
        out.push("omitted", Value::Object(omitted));
    }
    if job.detailed {
        let rows = spent
            .iter()
            .map(|s| {
                Value::object([
                    ("section", Value::from(s.section)),
                    ("weight", Value::from(section_weight(s.section))),
                    ("share", Value::from(s.share)),
                    ("need", Value::from(s.need)),
                    ("used", Value::from(s.used)),
                ])
            })
            .collect();
        out.push(
            "budgets",
            Value::object([
                ("total", Value::from(total)),
                ("sections", Value::Array(rows)),
            ]),
        );
    }
    Ok(Value::Object(out))
}

/// Reads the section cursors of the job.
///
/// # Errors
///
/// `CURSOR_INVALID` when a cursor is not a cursor of this call and section.
pub fn cursors(job: &Job<'_>) -> Result<Cursors, ToolError> {
    let mut out = Cursors::default();
    let Some(given) = job.args.get("cursors") else {
        return Ok(out);
    };
    for (name, section) in [
        ("disasm", fs::DISASM),
        ("ir", fs::IR),
        ("decomp", fs::DECOMP),
    ] {
        if let Some(text) = given.get(name).and_then(Value::as_str) {
            let key = job.scope(section).decode(text)?;
            let found = pair(&key).ok_or_else(|| ToolError::new(ErrorCode::CursorInvalid))?;
            match name {
                "ir" => out.ir = Some(found),
                "decomp" => out.decomp = Some(found),
                _ => out.disasm = Some(found),
            }
        }
    }
    Ok(out)
}
