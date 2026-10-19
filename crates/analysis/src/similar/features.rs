//! The feature stream of one function (design Section 7.13).
//!
//! [`stream`] reads the L0 function IR (design Section 7.12) and the analysis facts of one
//! function. It gives one [`Feature`] for each occurrence. The key of a feature is
//! `fnv1a64(kind code, 0x00, key text)`.
//!
//! | Kind | Text | Key text | Rule |
//! |---|---|---|---|
//! | `opcode` | `op1:<t>`, `op2:<t>,<t>`, `op3:<t>,<t>,<t>` | the text | n-grams of the op tokens of one block, in op order |
//! | `cfg` | `cfg:blocks=<b>`, `cfg:edges=<b>`, `cfg:loops=<b>`, `cfg:depth=<b>` | the text | buckets of the CFG counts |
//! | `wl` | `wl1:<16 hex>`, `wl2:<16 hex>` | the text | one Weisfeiler-Lehman label per block and round |
//! | `const` | `const:<signed hex>` | the text | immediates and absolute displacements |
//! | `string` | the `str:` ID | the 16 hex digits of the FNV-1a 64 of the string bytes | each reference to a string |
//! | `import` | the `imp:` ID | the import name without the library | each reference to an import |
//! | `callees` | `callees=<b>` | the text | the bucket of the direct callee count |
//!
//! Op tokens: the opcode name and the width, for example `Add.64`. `Get` and `Put` keep the
//! location class in place of the width: `gpr`, `xmm`, `flags`, `stack`, `seg` or `reg`. A
//! constant argument adds `.k`. `Nop` ops give no token. Register numbers and constant values
//! never appear in a token.
//!
//! A bucket `b` is `floor(log2(x + 1))`. The loop depth is the largest number of natural loops
//! that hold one block.
//!
//! WL labels: the round-0 label of a block is the FNV-1a 64 of its terminator kind, the bucket
//! of its op count and its call count. Round `k` hashes the round `k - 1` label of the block,
//! the sorted labels of its successors and the sorted labels of its predecessors.
//!
//! Constants: an immediate or the displacement of a memory operand with no base and no
//! index. A value `v` counts when `|v| > 255` as `i64` and no mapped region holds `v`. A
//! RIP-relative displacement is an address, so it never counts.
//!
//! The direct callees are the distinct targets of the direct calls of the body.
//!
//! A function whose L0 IR does not build has no feature. Only a fuel stop is an error.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fnv1a64, Fuel, FuncId, ImportId, Limits, OutOfFuel, StringId};
use ghidorah_db::{FlowKind, Program};
use ghidorah_ir::{Arg, Loc, Node, Op, Opc, dominators, loops};
use ghidorah_x86::Operand;

use crate::code::decode_at;
use crate::fir::{self, FirError, FuncIr, Opts};

/// The largest absolute value of a constant that gives no feature.
pub const MIN_CONST: u64 = 255;

/// The number of WL rounds that give features.
const WL_ROUNDS: usize = 2;

/// The kind of a feature. The order is the order of the module table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    /// An n-gram of op tokens.
    Opcode = 0,
    /// A bucket of a CFG count.
    Cfg = 1,
    /// A Weisfeiler-Lehman label.
    Wl = 2,
    /// A constant.
    Const = 3,
    /// A reference to a string.
    String = 4,
    /// A reference to an import.
    Import = 5,
    /// The bucket of the direct callee count.
    Callees = 6,
}

impl Kind {
    /// Every kind in kind order.
    pub const ALL: [Self; 7] = [
        Self::Opcode,
        Self::Cfg,
        Self::Wl,
        Self::Const,
        Self::String,
        Self::Import,
        Self::Callees,
    ];

    /// Gives the code byte of the kind in the feature key.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Gives the output name, for example `opcode`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Opcode => "opcode",
            Self::Cfg => "cfg",
            Self::Wl => "wl",
            Self::Const => "const",
            Self::String => "string",
            Self::Import => "import",
            Self::Callees => "callees",
        }
    }
}

/// One occurrence of a feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Feature {
    /// The kind.
    pub kind: Kind,
    /// The output text, for example `op1:Add.64` or `str:0x2004`.
    pub text: String,
    /// The key: `fnv1a64(kind code, 0x00, key text)`.
    pub key: u64,
}

impl Feature {
    /// Makes a feature whose key text is its output text.
    #[must_use]
    pub fn new(kind: Kind, text: String) -> Self {
        let key = feature_key(kind, &text);
        Self { kind, text, key }
    }

    /// Makes a feature with a key text that differs from its output text.
    #[must_use]
    pub fn keyed(kind: Kind, text: String, key_text: &str) -> Self {
        Self {
            kind,
            text,
            key: feature_key(kind, key_text),
        }
    }
}

/// Gives the key of a feature: `fnv1a64(kind code, 0x00, key text)`.
#[must_use]
pub fn feature_key(kind: Kind, key_text: &str) -> u64 {
    let mut h = Fnv1a64::new();
    h.write_u8(kind.code());
    h.write_u8(0);
    h.write(key_text.as_bytes());
    h.finish()
}

/// Gives the bucket of a count: `floor(log2(x + 1))`.
#[must_use]
pub const fn bucket(x: u64) -> u64 {
    let y = x as u128 + 1;
    y.ilog2() as u64
}

/// Gives the location class of a `Get` or `Put` token.
const fn class(loc: Loc) -> &'static str {
    match loc {
        Loc::Flags => "flags",
        Loc::Stack(_) => "stack",
        _ if loc.is_gpr() => "gpr",
        _ if loc.is_xmm() => "xmm",
        Loc::FS_BASE | Loc::GS_BASE => "seg",
        Loc::Reg(_) => "reg",
    }
}

/// Gives the token of an op, or `None` for a `Nop` op.
#[must_use]
pub fn token(op: &Op) -> Option<String> {
    let mut out = String::from(op.opc.name());
    out.push('.');
    match (op.opc, op.a[0].as_loc()) {
        (Opc::Nop, _) => return None,
        (Opc::Get | Opc::Put, Some(loc)) => out.push_str(class(loc)),
        _ => out.push_str(&op.w.to_string()),
    }
    if op.a.iter().any(|a| matches!(a, Arg::K(_))) {
        out.push_str(".k");
    }
    Some(out)
}

/// The facts of one program that every stream reads.
#[derive(Debug)]
pub struct Context<'a> {
    program: &'a Program,
    imports: BTreeMap<Address, &'a ImportId>,
}

impl<'a> Context<'a> {
    /// Makes the context of `program`: the EXTERNAL address and the stub of each import.
    #[must_use]
    pub fn new(program: &'a Program) -> Self {
        let mut imports = BTreeMap::new();
        for row in program.imports().values() {
            imports.insert(row.ext, &row.id);
            if let Some(stub) = row.stub {
                imports.insert(stub, &row.id);
            }
        }
        Self { program, imports }
    }

    /// Gives the program.
    #[must_use]
    pub const fn program(&self) -> &'a Program {
        self.program
    }

    /// Gives the import of a reference target: its EXTERNAL address or its stub.
    #[must_use]
    pub fn import_at(&self, to: Address) -> Option<&'a ImportId> {
        self.imports.get(&to).copied()
    }
}

/// Gives the feature stream of the function `func`.
///
/// The stream builds the L0 IR of the function. A function whose IR does not build gives an
/// empty stream.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out. The IR build takes one unit for each
/// instruction, and the stream takes one more unit for each instruction.
pub fn stream(ctx: &Context<'_>, func: FuncId, fuel: &mut Fuel) -> Result<Vec<Feature>, OutOfFuel> {
    match fir::build(ctx.program(), func, &Opts::DEFAULT, fuel) {
        Ok(ir) => of_ir(ctx, &ir, fuel),
        Err(FirError::Fuel(e)) => Err(e),
        Err(_) => Ok(Vec::new()),
    }
}

/// Gives the feature stream of a built function IR.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out. The stream takes one unit for each
/// instruction.
pub fn of_ir(ctx: &Context<'_>, ir: &FuncIr, fuel: &mut Fuel) -> Result<Vec<Feature>, OutOfFuel> {
    fuel.take(u64::try_from(ir.arena.insns().len()).unwrap_or(u64::MAX))?;
    let blocks = block_ops(ir);
    let mut out = Vec::new();
    grams(&blocks, &mut out);
    shape(ir, &mut out);
    wl(ir, &blocks, &mut out);
    operands(ctx, ir, &mut out);
    Ok(out)
}

/// The ops of one block without `Nop` ops, and the number of calls of the block.
struct BlockOps<'a> {
    ops: Vec<&'a Op>,
    calls: u64,
    term: FlowKind,
}

/// Gives the ops of each block in block order.
fn block_ops(ir: &FuncIr) -> Vec<BlockOps<'_>> {
    let insns = ir.arena.insns();
    let mut out = Vec::with_capacity(ir.body.blocks.len());
    for b in &ir.body.blocks {
        let first = usize::try_from(b.first).unwrap_or(usize::MAX);
        let end = first.saturating_add(usize::try_from(b.count).unwrap_or(0));
        let spans = insns.get(first..end).unwrap_or_default();
        let mut block = BlockOps {
            ops: Vec::new(),
            calls: 0,
            term: FlowKind::Seq,
        };
        for span in spans {
            let flow = ir.units.get(&span.addr).map_or(FlowKind::Seq, |u| u.flow);
            if matches!(flow, FlowKind::Call | FlowKind::ICall) {
                block.calls = block.calls.saturating_add(1);
            }
            block.term = flow;
            let ops = ir.arena.span_ops(span).unwrap_or_default();
            block.ops.extend(ops.iter().filter(|o| o.opc != Opc::Nop));
        }
        out.push(block);
    }
    out
}

/// Adds the op n-grams of each block, n = 1 to 3.
fn grams(blocks: &[BlockOps<'_>], out: &mut Vec<Feature>) {
    for block in blocks {
        let tokens: Vec<String> = block.ops.iter().filter_map(|o| token(o)).collect();
        for n in 1..=3 {
            for gram in tokens.windows(n) {
                out.push(Feature::new(
                    Kind::Opcode,
                    format!("op{n}:{}", gram.join(",")),
                ));
            }
        }
    }
}

/// Adds the CFG buckets: blocks, edges, natural loops and the largest loop depth.
fn shape(ir: &FuncIr, out: &mut Vec<Feature>) {
    let cfg = &ir.body.cfg;
    let nodes = (0..cfg.len()).filter_map(|i| u32::try_from(i).ok().map(Node));
    let edges: usize = nodes.clone().map(|n| cfg.succs(n).len()).sum();
    let found = loops(cfg, &dominators(cfg));
    let depth = nodes
        .map(|n| found.iter().filter(|l| l.body.contains(&n)).count())
        .max()
        .unwrap_or(0);
    for (name, x) in [
        ("blocks", cfg.len()),
        ("edges", edges),
        ("loops", found.len()),
        ("depth", depth),
    ] {
        let b = bucket(u64::try_from(x).unwrap_or(u64::MAX));
        out.push(Feature::new(Kind::Cfg, format!("cfg:{name}={b}")));
    }
}

/// Adds the WL labels of rounds 1 and 2 of each block.
fn wl(ir: &FuncIr, blocks: &[BlockOps<'_>], out: &mut Vec<Feature>) {
    let cfg = &ir.body.cfg;
    let preds = cfg.preds();
    let mut labels: Vec<u64> = blocks
        .iter()
        .map(|b| {
            let mut h = Fnv1a64::new();
            h.write(b.term.name().as_bytes());
            h.write_u8(0);
            h.write(&bucket(u64::try_from(b.ops.len()).unwrap_or(u64::MAX)).to_le_bytes());
            h.write(&b.calls.to_le_bytes());
            h.finish()
        })
        .collect();
    for round in 1..=WL_ROUNDS {
        let next: Vec<u64> = (0..labels.len())
            .map(|i| {
                let node = Node(u32::try_from(i).unwrap_or(u32::MAX));
                let around = |list: &[Node]| -> Vec<u64> {
                    let mut l: Vec<u64> = list
                        .iter()
                        .filter_map(|n| labels.get(n.index()).copied())
                        .collect();
                    l.sort_unstable();
                    l
                };
                let mut h = Fnv1a64::new();
                h.write(&labels.get(i).copied().unwrap_or(0).to_le_bytes());
                for (tag, list) in [
                    (1, around(cfg.succs(node))),
                    (
                        2,
                        around(preds.get(i).map(Vec::as_slice).unwrap_or_default()),
                    ),
                ] {
                    h.write_u8(tag);
                    for l in list {
                        h.write(&l.to_le_bytes());
                    }
                }
                h.finish()
            })
            .collect();
        for l in &next {
            out.push(Feature::new(Kind::Wl, format!("wl{round}:{l:016x}")));
        }
        labels = next;
    }
}

/// Gives the text of a signed constant, for example `0x1000` or `-0x1000`.
fn signed_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", v.unsigned_abs())
    } else {
        format!("{v:#x}")
    }
}

/// Adds the constants, the strings, the imports and the callee bucket of the body.
fn operands(ctx: &Context<'_>, ir: &FuncIr, out: &mut Vec<Feature>) {
    let program = ctx.program();
    let mut callees: BTreeSet<u64> = BTreeSet::new();
    for (at, unit) in &ir.units {
        if let Some(insn) = decode_at(program, *at) {
            if unit.flow == FlowKind::Call
                && let Some(t) = insn.target()
            {
                callees.insert(t);
            }
            for op in insn.ops() {
                let v = match op {
                    Operand::Imm { value, .. } => value,
                    Operand::Mem(m) if m.base.is_none() && m.index.is_none() => m.disp,
                    _ => continue,
                };
                let mapped = program.mem().region_at(v.cast_unsigned()).is_some();
                if v.unsigned_abs() > MIN_CONST && !mapped {
                    out.push(Feature::new(
                        Kind::Const,
                        format!("const:{}", signed_hex(v)),
                    ));
                }
            }
        }
        let mut seen: BTreeSet<Address> = BTreeSet::new();
        for r in program.refs_from(Address::ram(*at)) {
            let to = r.value.key.to;
            if !seen.insert(to) {
                continue;
            }
            if let Some(id) = ctx.import_at(to) {
                let name = id
                    .name()
                    .map_or_else(|| format!("#{}", id.ordinal().unwrap_or(0)), str::to_owned);
                out.push(Feature::keyed(Kind::Import, id.to_string(), &name));
            } else if let Some(key) = string_key(program, to) {
                out.push(Feature::keyed(Kind::String, StringId(to).to_string(), &key));
            }
        }
    }
    let b = bucket(u64::try_from(callees.len()).unwrap_or(u64::MAX));
    out.push(Feature::new(Kind::Callees, format!("callees={b}")));
}

/// Gives the key text of the string at `to`: the hex of the FNV-1a 64 of its bytes.
fn string_key(program: &Program, to: Address) -> Option<String> {
    if !to.is_ram() {
        return None;
    }
    let info = program.string(to.off)?;
    let bytes = program
        .mem()
        .read(to.off, u64::from(info.len), &Limits::DEFAULT)
        .ok()?;
    Some(format!("{:016x}", ghidorah_base::fnv1a64(&bytes)))
}
