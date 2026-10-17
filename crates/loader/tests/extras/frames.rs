//! A reader of `readelf --debug-dump=frames` goldens and an independent CFA row model.
//!
//! The model reads the listing lines of readelf, not the bytes. It knows the CFA lines of
//! the fixtures: `def_cfa`, `def_cfa_offset`, `def_cfa_register`, `advance_loc*`,
//! `remember_state` and `restore_state`. A `def_cfa_expression` line clears the rows.

use std::collections::BTreeMap;

use crate::support::hex;

/// One CFA row of the model: address, register and offset.
pub type Row = (u64, u16, i64);

/// One FDE of a golden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenFde {
    /// The section offset of the record.
    pub offset: u64,
    /// The section offset of the CIE.
    pub cie: u64,
    /// The first address.
    pub pc_begin: u64,
    /// The first address after the range.
    pub pc_end: u64,
    /// The rows of the model.
    pub rows: Vec<Row>,
}

/// The CFA state of the model: register and offset.
type State = Option<(u16, i64)>;

/// Adds a row, or replaces the row at the same address. A row that repeats the rule
/// before it is not kept.
fn emit(rows: &mut Vec<Row>, pc: u64, state: State, end: u64) {
    let Some((reg, off)) = state else {
        return;
    };
    if pc >= end {
        return;
    }
    if rows.last().is_some_and(|r| r.0 == pc) {
        rows.pop();
    }
    if rows.last().is_some_and(|r| (r.1, r.2) == (reg, off)) {
        return;
    }
    rows.push((pc, reg, off));
}

/// Parses `r7 (rsp)` into 7.
fn reg(text: &str) -> u16 {
    let t = text.trim();
    let t = t.strip_prefix('r').unwrap_or(t);
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("register {text:?}: {e}"))
}

/// The state of one record while the reader walks its lines.
struct Walk {
    state: State,
    stack: Vec<State>,
    loc: u64,
    end: u64,
    rows: Vec<Row>,
    dead: bool,
}

impl Walk {
    fn line(&mut self, line: &str) {
        let line = line.trim();
        if self.dead {
            return;
        }
        if let Some(rest) = line.strip_prefix("DW_CFA_def_cfa: ") {
            let (r, off) = rest.split_once(" ofs ").expect("def_cfa form");
            self.state = Some((reg(r), off.trim().parse().expect("offset")));
        } else if let Some(rest) = line.strip_prefix("DW_CFA_def_cfa_offset: ") {
            let off = rest.trim().parse().expect("offset");
            self.state = self.state.map(|(r, _)| (r, off));
        } else if let Some(rest) = line.strip_prefix("DW_CFA_def_cfa_register: ") {
            let r = reg(rest);
            self.state = Some((r, self.state.map_or(0, |s| s.1)));
        } else if line.starts_with("DW_CFA_advance_loc") {
            let (_, to) = line.rsplit_once(" to ").expect("advance form");
            self.loc = hex(to);
            return;
        } else if line == "DW_CFA_remember_state" {
            self.stack.push(self.state);
            return;
        } else if line == "DW_CFA_restore_state" {
            self.state = self.stack.pop().expect("a remembered state");
        } else if line.starts_with("DW_CFA_def_cfa_expression") {
            self.dead = true;
            self.rows.clear();
            return;
        } else {
            return;
        }
        emit(&mut self.rows, self.loc, self.state, self.end);
    }
}

/// Parses the FDEs of a golden body in record order.
pub fn parse(text: &str) -> Vec<GoldenFde> {
    let mut cies: BTreeMap<u64, State> = BTreeMap::new();
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let is_cie = fields.len() == 4 && fields[3] == "CIE";
        let is_fde = fields.len() == 6 && fields[3] == "FDE";
        if !is_cie && !is_fde {
            continue;
        }
        let offset = hex(fields[0]);
        let (cie, pc_begin, pc_end) = if is_fde {
            let cie = hex(fields[4].trim_start_matches("cie="));
            let (a, b) = fields[5]
                .trim_start_matches("pc=")
                .split_once("..")
                .expect("pc range");
            (cie, hex(a), hex(b))
        } else {
            (offset, 0, u64::MAX)
        };
        let state = if is_fde {
            cies.get(&cie).copied().flatten()
        } else {
            None
        };
        let mut walk = Walk {
            state,
            stack: Vec::new(),
            loc: pc_begin,
            end: pc_end,
            rows: Vec::new(),
            dead: false,
        };
        emit(&mut walk.rows, pc_begin, state, pc_end);
        while let Some(next) = lines.peek() {
            if next.trim().is_empty() {
                break;
            }
            walk.line(next);
            lines.next();
        }
        if is_cie {
            cies.insert(offset, if walk.dead { None } else { walk.state });
        } else {
            out.push(GoldenFde {
                offset,
                cie,
                pc_begin,
                pc_end,
                rows: walk.rows,
            });
        }
    }
    out
}
