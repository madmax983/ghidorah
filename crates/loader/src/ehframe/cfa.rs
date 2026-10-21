//! The CFA row interpreter of one CIE or FDE program.

use ghidorah_base::DiagCode;
use ghidorah_kernel::{Endian, ReadError, Reader};

use crate::binary::CfaRow;

const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
const DW_CFA_UNDEFINED: u8 = 0x07;
const DW_CFA_SAME_VALUE: u8 = 0x08;
const DW_CFA_REGISTER: u8 = 0x09;
const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
const DW_CFA_RESTORE_STATE: u8 = 0x0b;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
const DW_CFA_EXPRESSION: u8 = 0x10;
const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
const DW_CFA_DEF_CFA_SF: u8 = 0x12;
const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
const DW_CFA_VAL_OFFSET: u8 = 0x14;
const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
const DW_CFA_GNU_ARGS_SIZE: u8 = 0x2e;
const DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED: u8 = 0x2f;

/// The DWARF register number of `rsp`.
const RSP: u16 = 7;

/// The ops of the PLT expression of GNU ld after `DW_OP_breg7 <base>`: `breg16 0; lit15;
/// and`, then `lit<k>`, then `ge; lit3; shl; plus`.
const PLT_HEAD: [u8; 4] = [0x80, 0x00, 0x3f, 0x1a];
/// The ops of the PLT expression after `lit<k>`.
const PLT_TAIL: [u8; 4] = [0x2a, 0x33, 0x24, 0x22];
/// The opcode of `DW_OP_breg7`.
const DW_OP_BREG7: u8 = 0x77;
/// The opcode of `DW_OP_lit0`. `DW_OP_lit<k>` is `0x30 + k` for `k` in 0..=31.
const DW_OP_LIT0: u8 = 0x30;

/// The CFA rule: a register and an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Rule {
    /// The DWARF register number, or `None` before the first `def_cfa`.
    pub(crate) reg: Option<u16>,
    /// The offset from the register.
    pub(crate) offset: i64,
}

/// The factors of a CIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Factors {
    /// The code alignment factor of `advance_loc`.
    pub(crate) code: u64,
    /// The data alignment factor of the `_sf` forms.
    pub(crate) data: i64,
}

/// The rows and the last rule of one program.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Run {
    /// The rows in address order.
    pub(crate) rows: Vec<CfaRow>,
    /// The rule after the last instruction.
    pub(crate) rule: Rule,
}

/// The cause of a stopped program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stop {
    /// The diagnostic code.
    pub(crate) code: DiagCode,
    /// The offset of the instruction in the program.
    pub(crate) at: usize,
    /// The opcode.
    pub(crate) opcode: u8,
    /// A short fact for the diagnostic.
    pub(crate) hint: &'static str,
}

/// The interpreter state of one program.
struct Machine<'a> {
    reader: Reader<'a>,
    factors: Factors,
    loc: u64,
    end: Option<u64>,
    rule: Rule,
    stack: Vec<Rule>,
    rows: Vec<CfaRow>,
    /// The instructions and the PLT rows so far.
    count: u64,
    /// The cap of `count`.
    max_insns: u64,
}

/// The result of one instruction.
enum Step {
    /// The program goes on.
    Next,
    /// The location is at or after the end of the range. No later row can count.
    Done,
}

/// A failed instruction: the code and the hint of the diagnostic.
type Fail = (DiagCode, &'static str);

const fn read_fail(e: ReadError) -> Fail {
    match e {
        ReadError::BadLeb => (DiagCode::Overflow, "a LEB128 operand is not valid"),
        ReadError::Eof | ReadError::NoNul => (DiagCode::Oob, "an operand runs past the program"),
    }
}

impl Machine<'_> {
    fn uleb(&mut self) -> Result<u64, Fail> {
        self.reader.uleb128().map_err(read_fail)
    }

    fn sleb(&mut self) -> Result<i64, Fail> {
        self.reader.sleb128().map_err(read_fail)
    }

    fn reg(&mut self) -> Result<u16, Fail> {
        let v = self.uleb()?;
        u16::try_from(v).map_err(|_| (DiagCode::Overflow, "a register number is above 65535"))
    }

    fn offset(&mut self) -> Result<i64, Fail> {
        let v = self.uleb()?;
        i64::try_from(v).map_err(|_| (DiagCode::Overflow, "a CFA offset is above the i64 range"))
    }

    fn factored(&mut self) -> Result<i64, Fail> {
        let v = self.sleb()?;
        v.checked_mul(self.factors.data)
            .ok_or((DiagCode::Overflow, "a factored CFA offset overflows"))
    }

    fn skip_block(&mut self) -> Result<(), Fail> {
        let len = self.uleb()?;
        let len = usize::try_from(len).map_err(|_| read_fail(ReadError::Eof))?;
        self.reader.skip(len).map_err(read_fail)
    }

    /// Moves the location by `delta` code units.
    fn advance(&mut self, delta: u64) -> Result<Step, Fail> {
        let overflow = (
            DiagCode::Overflow,
            "the location goes past the 64-bit range",
        );
        let bytes = delta.checked_mul(self.factors.code).ok_or(overflow)?;
        self.loc = self.loc.checked_add(bytes).ok_or(overflow)?;
        if self.end.is_some_and(|end| self.loc >= end) {
            return Ok(Step::Done);
        }
        Ok(Step::Next)
    }

    /// Sets the CFA rule at the current location.
    fn set(&mut self, rule: Rule) -> Step {
        self.rule = rule;
        emit(&mut self.rows, self.loc, rule);
        Step::Next
    }

    /// Reads the operands of a register-rule opcode. The CFA does not change.
    fn register_rule(&mut self, op: u8) -> Result<Step, Fail> {
        match op {
            DW_CFA_OFFSET_EXTENDED
            | DW_CFA_REGISTER
            | DW_CFA_VAL_OFFSET
            | DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED => {
                self.uleb()?;
                self.uleb()?;
            }
            DW_CFA_OFFSET_EXTENDED_SF | DW_CFA_VAL_OFFSET_SF => {
                self.uleb()?;
                self.sleb()?;
            }
            DW_CFA_EXPRESSION | DW_CFA_VAL_EXPRESSION => {
                self.uleb()?;
                self.skip_block()?;
            }
            _ => {
                self.uleb()?;
            }
        }
        Ok(Step::Next)
    }

    /// Reads a `def_cfa_expression`. The PLT expression of GNU ld gives its rows to the end of
    /// the range ([`plt_rule`]). It is the last instruction, so only `nop` padding can
    /// follow it. Another expression stops the program.
    fn def_cfa_expression(&mut self) -> Result<Step, Fail> {
        const EXPRESSION: Fail = (DiagCode::CfaOpcode, "the CFA is a DWARF expression");
        let len = self.uleb()?;
        let len = usize::try_from(len).map_err(|_| read_fail(ReadError::Eof))?;
        let block = self.reader.take(len).map_err(read_fail)?;
        let (base, k) = plt_rule(block).ok_or(EXPRESSION)?;
        let end = self.end.ok_or(EXPRESSION)?;
        if self.reader.rest().iter().any(|b| *b != DW_CFA_NOP) {
            return Err(EXPRESSION);
        }
        self.plt_rows(base, k, end)?;
        Ok(Step::Done)
    }

    /// Adds the rows of the PLT rule from the location to `end`. An offset below `k` in a
    /// 16-byte entry gets `rsp + base`. Another offset gets `rsp + base + 8`. Each row counts
    /// as one instruction of the cap.
    fn plt_rows(&mut self, base: i64, k: u64, end: u64) -> Result<(), Fail> {
        const LIMIT: Fail = (
            DiagCode::Limit,
            "the PLT rule has more rows than the instruction cap",
        );
        let pushed = base
            .checked_add(8)
            .ok_or((DiagCode::Overflow, "a CFA offset overflows"))?;
        let offset_at = |pc: u64| if pc % 16 >= k { pushed } else { base };
        let mut pc = self.loc;
        while pc < end {
            self.count = self.count.checked_add(1).ok_or(LIMIT)?;
            if self.count > self.max_insns {
                return Err(LIMIT);
            }
            emit(
                &mut self.rows,
                pc,
                Rule {
                    reg: Some(RSP),
                    offset: offset_at(pc),
                },
            );
            // The next change is at the next entry start or at offset `k` of the entry.
            let entry = pc & !15;
            let at_k = entry.checked_add(k).filter(|q| *q > pc && k < 16);
            match at_k.or_else(|| entry.checked_add(16)) {
                Some(q) => pc = q,
                None => break,
            }
        }
        self.rule = Rule {
            reg: Some(RSP),
            offset: offset_at(pc),
        };
        Ok(())
    }

    /// Runs one instruction with the opcode `op`.
    fn step(&mut self, op: u8) -> Result<Step, Fail> {
        let low = op & 0x3f;
        match op & 0xc0 {
            0x40 => return self.advance(u64::from(low)),
            0x80 => {
                self.uleb()?;
                return Ok(Step::Next);
            }
            0xc0 => return Ok(Step::Next),
            _ => {}
        }
        let rule = self.rule;
        let step = match op {
            DW_CFA_NOP => Step::Next,
            DW_CFA_ADVANCE_LOC1 => {
                let d = self.reader.u8().map_err(read_fail)?;
                self.advance(u64::from(d))?
            }
            DW_CFA_ADVANCE_LOC2 => {
                let d = self.reader.u16().map_err(read_fail)?;
                self.advance(u64::from(d))?
            }
            DW_CFA_ADVANCE_LOC4 => {
                let d = self.reader.u32().map_err(read_fail)?;
                self.advance(u64::from(d))?
            }
            DW_CFA_OFFSET_EXTENDED
            | DW_CFA_RESTORE_EXTENDED
            | DW_CFA_UNDEFINED
            | DW_CFA_SAME_VALUE
            | DW_CFA_REGISTER
            | DW_CFA_EXPRESSION
            | DW_CFA_OFFSET_EXTENDED_SF
            | DW_CFA_VAL_OFFSET
            | DW_CFA_VAL_OFFSET_SF
            | DW_CFA_VAL_EXPRESSION
            | DW_CFA_GNU_ARGS_SIZE
            | DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED => self.register_rule(op)?,
            DW_CFA_REMEMBER_STATE => {
                self.stack.push(rule);
                Step::Next
            }
            DW_CFA_RESTORE_STATE => {
                let saved = self.stack.pop().ok_or((
                    DiagCode::CfaOpcode,
                    "restore_state has no remember_state before it",
                ))?;
                self.set(saved)
            }
            DW_CFA_DEF_CFA => {
                let reg = self.reg()?;
                let offset = self.offset()?;
                self.set(Rule {
                    reg: Some(reg),
                    offset,
                })
            }
            DW_CFA_DEF_CFA_SF => {
                let reg = self.reg()?;
                let offset = self.factored()?;
                self.set(Rule {
                    reg: Some(reg),
                    offset,
                })
            }
            DW_CFA_DEF_CFA_REGISTER => {
                let reg = self.reg()?;
                self.set(Rule {
                    reg: Some(reg),
                    ..rule
                })
            }
            DW_CFA_DEF_CFA_OFFSET => {
                let offset = self.offset()?;
                self.set(Rule { offset, ..rule })
            }
            DW_CFA_DEF_CFA_OFFSET_SF => {
                let offset = self.factored()?;
                self.set(Rule { offset, ..rule })
            }
            DW_CFA_DEF_CFA_EXPRESSION => self.def_cfa_expression()?,
            _ => return Err((DiagCode::CfaOpcode, "the opcode is not supported")),
        };
        Ok(step)
    }
}

/// Gives the base offset and the entry offset `k` of the PLT expression of GNU ld, or `None`
/// for another expression.
///
/// The expression is `breg7 <base>; breg16 0; lit15; and; lit<k>; ge; lit3; shl; plus`. So
/// the CFA is `rsp + base`, plus 8 when `rip & 15 >= k`. The lazy PLT pushes the slot index
/// at offset 11 of each entry, and the IBT PLT at offset 9.
fn plt_rule(block: &[u8]) -> Option<(i64, u64)> {
    let mut r = Reader::new(block, Endian::Little);
    if r.u8().ok()? != DW_OP_BREG7 {
        return None;
    }
    let base = r.sleb128().ok()?;
    let head = r.take(PLT_HEAD.len()).ok()?;
    let lit = r.u8().ok()?;
    let tail = r.take(PLT_TAIL.len()).ok()?;
    let k = lit.checked_sub(DW_OP_LIT0).filter(|k| *k < 32)?;
    let exact = head == PLT_HEAD && tail == PLT_TAIL && r.remaining() == 0;
    exact.then_some((base, u64::from(k)))
}

/// Adds a row at `pc`, or replaces the row at the same address. The list keeps no row that
/// repeats the rule before it. A rule with no register gives no row.
fn emit(rows: &mut Vec<CfaRow>, pc: u64, rule: Rule) {
    let Some(reg) = rule.reg else {
        return;
    };
    if rows.last().is_some_and(|r| r.pc == pc) {
        rows.pop();
    }
    if rows
        .last()
        .is_some_and(|r| r.reg == reg && r.offset == rule.offset)
    {
        return;
    }
    rows.push(CfaRow {
        pc,
        reg,
        offset: rule.offset,
    });
}

/// Runs `program` from `start` with the rule `init`.
///
/// `end` is the first address after the PC range. The run keeps no row at or after `end`.
/// `None` keeps no row limit, for the initial program of a CIE. A program with more than
/// `max_insns` instructions stops with `E_LIMIT`.
pub(crate) fn run(
    program: &[u8],
    factors: Factors,
    start: u64,
    end: Option<u64>,
    init: Rule,
    max_insns: u64,
) -> Result<Run, Stop> {
    let mut m = Machine {
        reader: Reader::new(program, Endian::Little),
        factors,
        loc: start,
        end,
        rule: init,
        stack: Vec::new(),
        rows: Vec::new(),
        count: 0,
        max_insns,
    };
    if end.is_none_or(|e| start < e) {
        emit(&mut m.rows, start, init);
    }
    while m.reader.remaining() > 0 {
        let at = m.reader.pos();
        let opcode = m.reader.u8().unwrap_or(DW_CFA_NOP);
        m.count = m.count.saturating_add(1);
        let step = if m.count > max_insns {
            Err((
                DiagCode::Limit,
                "the FDE has more CFA instructions than the limit",
            ))
        } else {
            m.step(opcode)
        };
        match step {
            Ok(Step::Next) => {}
            Ok(Step::Done) => break,
            Err((code, hint)) => {
                return Err(Stop {
                    code,
                    at,
                    opcode,
                    hint,
                });
            }
        }
    }
    m.rows.shrink_to_fit();
    Ok(Run {
        rows: m.rows,
        rule: m.rule,
    })
}
