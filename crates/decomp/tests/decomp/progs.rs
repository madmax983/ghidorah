//! Random L0 programs and their L1 forms, and the L0 runs that the value oracle compares.
//!
//! The generator follows the generator of the `ghidorah-ir` SSA tests. A program has 1 to 7
//! blocks of random ops over a pool of locations, with loads, stores, flags, calls and effect
//! ops.

#![allow(
    clippy::many_single_char_names,
    reason = "the test programs name each IR value with one letter"
)]

use std::collections::BTreeSet;

use ghidorah_base::Fuel;
use ghidorah_decomp::interp_ast::{self, Outcome};
use ghidorah_decomp::{Decomp, Input, NoEnv, Opts};
use ghidorah_ir::ssa::{self, Block, Body, Opts as SsaOpts, Ssa};
use ghidorah_ir::{
    Arena, Arg, BuildError, Builder, Cc, Cfg, Config, Effect, FlagOp, FlatImage, Image, Interp,
    IntrinsicId, Loc, LocSet, MemEffect, Node, Opc, StopReason, Switches, Val,
};
use ghidorah_testkit::rng::{Rng, Xoshiro256ss, below};

const NIL: Arg = Arg::Nil;

/// The base address of the test RAM.
pub const RAM: u64 = 0x10000;

/// The size of the test RAM in bytes.
pub const RAM_SIZE: u64 = 256;

/// The fuel of each L0 run.
pub const RUN_FUEL: u64 = 300;

/// The locations of the random programs.
pub const POOL: [Loc; 8] = [
    Loc::RAX,
    Loc::RCX,
    Loc::RDX,
    Loc::RBX,
    Loc::Flags,
    Loc::Stack(-8),
    Loc::Stack(16),
    Loc::Reg(32),
];

/// The options of the random programs: a return and a call read the pool, and a call writes
/// `rax` and `rdx`.
pub fn pool_opts() -> SsaOpts {
    let pool: LocSet = POOL.iter().copied().collect();
    SsaOpts {
        ret_uses: pool,
        call_uses: pool,
        call_defs: [Loc::RAX, Loc::RDX].into_iter().collect(),
    }
}

/// A random L0 program with its body, its entry and its start state.
#[derive(Debug, Clone)]
pub struct Program {
    /// The arena.
    pub arena: Arena,
    /// The body.
    pub body: Body,
    /// The entry address.
    pub entry: u64,
    /// The start values of the pool locations.
    pub setup: Vec<(Loc, u128)>,
}

/// Gives the node of an index.
fn node(i: usize) -> Node {
    Node(u32::try_from(i).expect("small"))
}

/// Gives the addresses that the flow ops of one instruction can go to.
fn flow_targets(arena: &Arena, insn: usize) -> Vec<Option<u64>> {
    let span = arena.insns()[insn];
    let ops = arena.span_ops(&span).expect("the span is in the arena");
    let mut out = Vec::new();
    for op in ops {
        match op.opc {
            Opc::CJump => out.push(op.a[1].as_k()),
            Opc::Jump | Opc::JumpInd => {
                out.push(op.a[0].as_k());
                return out;
            }
            Opc::Ret | Opc::Unimpl => return out,
            _ => {}
        }
    }
    out.push(span.next_addr());
    out
}

/// Makes the body of `arena`: a block starts at each leader. The edges come from the flow
/// ops of the last instruction of each block, plus the `extra` edges between leaders.
pub fn body_with(arena: &Arena, leaders: &[u64], extra: &[(u64, u64)]) -> Body {
    let starts: Vec<usize> = leaders
        .iter()
        .map(|&a| arena.insn_index(a).expect("a leader is an instruction"))
        .collect();
    let mut blocks = Vec::new();
    for (i, &first) in starts.iter().enumerate() {
        let end = starts
            .get(i + 1)
            .copied()
            .unwrap_or_else(|| arena.insns().len());
        blocks.push(Block {
            first: u32::try_from(first).expect("small"),
            count: u32::try_from(end - first).expect("small"),
        });
    }
    let block_at = |addr: u64| leaders.iter().position(|&l| l == addr).map(node);
    let mut cfg = Cfg::new(blocks.len(), Node(0)).expect("a valid entry");
    for (i, b) in blocks.iter().enumerate() {
        let last = usize::try_from(b.first + b.count - 1).expect("small");
        for target in flow_targets(arena, last).into_iter().flatten() {
            if let Some(to) = block_at(target) {
                cfg.add_edge(node(i), to).expect("valid nodes");
            }
        }
    }
    for &(from, to) in extra {
        let (from, to) = (
            block_at(from).expect("leader"),
            block_at(to).expect("leader"),
        );
        cfg.add_edge(from, to).expect("valid nodes");
    }
    Body { blocks, cfg }
}

/// The constants of the random programs.
const EDGE_VALUES: [u64; 8] = [0, 1, 2, 0x7f, 0x80, 0xffff_ffff, 1 << 63, u64::MAX];

/// The generator state of one random block.
struct Gen<'a> {
    rng: &'a mut Xoshiro256ss,
    temps: Vec<(Val, u8)>,
}

impl Gen<'_> {
    fn below(&mut self, n: u64) -> u64 {
        below(self.rng, n)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let n = u64::try_from(items.len()).expect("small");
        items[usize::try_from(self.below(n)).expect("small")]
    }

    fn width(&mut self) -> u8 {
        self.pick(&[8, 16, 32, 64])
    }

    fn konst(&mut self) -> Arg {
        if self.below(2) == 0 {
            Arg::k(self.pick(&EDGE_VALUES))
        } else {
            Arg::k(self.rng.next_u64() >> self.below(64))
        }
    }

    fn arg(&mut self) -> Arg {
        if self.temps.is_empty() || self.below(10) < 3 {
            return self.konst();
        }
        let (v, _) = self.pick(&self.temps.clone());
        Arg::V(v)
    }

    fn cond(&mut self, b: &mut Builder) -> Result<Arg, BuildError> {
        let bits: Vec<Val> = self
            .temps
            .iter()
            .filter(|(_, w)| *w == 1)
            .map(|(v, _)| *v)
            .collect();
        if let Some(&v) = bits.get(usize::try_from(self.below(4)).expect("small")) {
            return Ok(Arg::V(v));
        }
        let (x, y) = (self.arg(), self.arg());
        let opc = self.pick(&[Opc::Eq, Opc::ULt, Opc::SLe, Opc::TestNZ]);
        let w = self.width();
        let v = b.binary(opc, w, x, y)?;
        self.temps.push((v, 1));
        Ok(Arg::V(v))
    }

    fn flags_word(&mut self, b: &mut Builder) -> Result<Arg, BuildError> {
        let words: Vec<Val> = self
            .temps
            .iter()
            .filter(|(_, w)| *w == 16)
            .map(|(v, _)| *v)
            .collect();
        if let Some(&v) = words.get(usize::try_from(self.below(3)).expect("small")) {
            return Ok(Arg::V(v));
        }
        let v = b.get(Loc::Flags)?;
        self.temps.push((v, 16));
        Ok(Arg::V(v))
    }

    fn addr(&mut self, b: &mut Builder) -> Result<Arg, BuildError> {
        let x = self.arg();
        if self.below(8) == 0 {
            return Ok(x);
        }
        let off = b.binary(Opc::And, 64, x, Arg::k(0xf0))?;
        Ok(Arg::V(b.binary(Opc::Add, 64, off.into(), Arg::k(RAM))?))
    }

    fn op(&mut self, b: &mut Builder) -> Result<(), BuildError> {
        match self.below(20) {
            0..=3 => {
                let loc = self.pick(&POOL);
                let v = b.get(loc)?;
                self.temps.push((v, loc.width()));
            }
            4..=6 => {
                let loc = self.pick(&POOL);
                let x = if loc == Loc::Flags {
                    self.flags_word(b)?
                } else {
                    self.arg()
                };
                b.put(loc, x)?;
            }
            7..=9 => {
                let opc = self.pick(&[
                    Opc::Add,
                    Opc::Sub,
                    Opc::Mul,
                    Opc::UMulHi,
                    Opc::SMulHi,
                    Opc::And,
                    Opc::Or,
                    Opc::Xor,
                    Opc::Shl,
                    Opc::LShr,
                    Opc::AShr,
                    Opc::Rol,
                    Opc::Ror,
                    Opc::Eq,
                    Opc::Ne,
                    Opc::ULt,
                    Opc::ULe,
                    Opc::SLt,
                    Opc::SLe,
                    Opc::TestZ,
                    Opc::TestNZ,
                ]);
                let w = if self.below(8) == 0 {
                    128
                } else {
                    self.width()
                };
                let (x, y) = (self.arg(), self.arg());
                let v = b.binary(opc, w, x, y)?;
                self.temps.push((v, if opc.is_compare() { 1 } else { w }));
            }
            10 => {
                let opc = self.pick(&[
                    Opc::Copy,
                    Opc::Neg,
                    Opc::Not,
                    Opc::Popcnt,
                    Opc::Clz,
                    Opc::Ctz,
                    Opc::Bswap,
                    Opc::Trunc,
                ]);
                let w = self.width();
                let x = self.arg();
                let v = b.unary(opc, w, x)?;
                self.temps.push((v, w));
            }
            11 => {
                let w = self.pick(&[16, 32, 64]);
                let from = self.pick(&[1, 8, 16]).min(w);
                let x = self.arg();
                let v = b.extend(self.below(2) == 0, w, from, x)?;
                self.temps.push((v, w));
            }
            _ => self.op_more(b)?,
        }
        Ok(())
    }

    fn op_more(&mut self, b: &mut Builder) -> Result<(), BuildError> {
        match self.below(10) {
            0 => {
                let x = self.arg();
                if self.below(2) == 0 {
                    let lo = u8::try_from(self.below(56)).expect("small");
                    let v = b.extract(8, x, lo)?;
                    self.temps.push((v, 8));
                } else {
                    let part = self.arg();
                    let lo = self.pick(&[0, 8, 16, 32]);
                    let v = b.insert(64, x, part, 8, lo)?;
                    self.temps.push((v, 64));
                }
            }
            1 => {
                let c = self.cond(b)?;
                let (t, f) = (self.arg(), self.arg());
                let w = self.width();
                let v = b.value(Opc::Ite, w, 0, [c, t, f])?;
                self.temps.push((v, w));
            }
            2 => {
                let opc = self.pick(&[Opc::UDiv, Opc::SDiv, Opc::URem, Opc::SRem]);
                let w = self.width();
                let x = self.arg();
                let y = if self.below(2) == 0 {
                    Arg::k(self.below(4))
                } else {
                    self.arg()
                };
                let v = b.binary(opc, w, x, y)?;
                self.temps.push((v, w));
            }
            3 | 4 => {
                let op = self.pick(FlagOp::ALL);
                let w = self.width();
                let (x, y) = (self.arg(), self.arg());
                let c = self.flags_word(b)?;
                let v = b.flags(op, w, x, y, c)?;
                self.temps.push((v, 16));
                if self.below(2) == 0 {
                    let cc =
                        Cc::x86(u8::try_from(self.below(16)).expect("small")).expect("a valid cc");
                    let c = b.cond(cc, v.into())?;
                    self.temps.push((c, 1));
                }
            }
            5 => {
                let cc = Cc::x86(u8::try_from(self.below(16)).expect("small")).expect("cc");
                let f = self.flags_word(b)?;
                let c = b.cond(cc, f)?;
                self.temps.push((c, 1));
            }
            6 => {
                let addr = self.addr(b)?;
                let w = self.pick(&[8, 16, 32, 64, 128]);
                let v = b.load(w, addr)?;
                self.temps.push((v, w));
            }
            7 => {
                let addr = self.addr(b)?;
                let w = self.pick(&[8, 32, 64]);
                let x = self.arg();
                b.store(w, addr, x)?;
            }
            _ => self.rare(b)?,
        }
        Ok(())
    }

    fn rare(&mut self, b: &mut Builder) -> Result<(), BuildError> {
        match self.below(6) {
            0 => {
                let f = self.flags_word(b)?;
                let v = b.value(Opc::FlagsGet, 64, 0, [f, NIL, NIL])?;
                self.temps.push((v, 64));
            }
            1 => {
                let x = self.arg();
                let v = b.value(Opc::FlagsSet, 16, 0, [x, NIL, NIL])?;
                self.temps.push((v, 16));
            }
            2 => {
                let c = self.cond(b)?;
                let (f1, f2) = (self.flags_word(b)?, self.flags_word(b)?);
                let v = b.value(Opc::FlagsSel, 16, 0, [c, f1, f2])?;
                self.temps.push((v, 16));
            }
            3 => {
                let effect = Effect {
                    name: IntrinsicId(1),
                    uses: [Loc::RAX, Loc::RDX].into_iter().collect(),
                    defs: [Loc::RAX, Loc::RCX].into_iter().collect(),
                    mem: MemEffect::None,
                };
                b.effect_op(Opc::Syscall, effect, NIL)?;
            }
            4 => {
                let effect = Effect {
                    name: IntrinsicId(2),
                    uses: std::iter::once(Loc::Reg(32)).collect(),
                    defs: [Loc::Reg(32), Loc::Flags].into_iter().collect(),
                    mem: MemEffect::Read { size: 16 },
                };
                let addr = self.addr(b)?;
                b.effect_op(Opc::Intrinsic, effect, addr)?;
            }
            _ => b.flow(Opc::Call, Arg::k(0x9000), NIL)?,
        }
        Ok(())
    }
}

/// Adds the flow ops at the end of block `i`.
fn terminator(
    g: &mut Gen<'_>,
    b: &mut Builder,
    starts: &[u64],
    i: usize,
    extra: &mut Vec<(u64, u64)>,
) -> Result<(), BuildError> {
    let last = i + 1 == starts.len();
    let target = |g: &mut Gen<'_>| g.pick(starts);
    match g.below(6) {
        0 if !last => {}
        0 | 1 => {
            let c = g.cond(b)?;
            let t = target(g);
            b.flow(Opc::CJump, c, Arg::k(t))?;
            if last {
                b.flow(Opc::Ret, NIL, NIL)?;
            }
        }
        2 => {
            let t = target(g);
            b.flow(Opc::Jump, Arg::k(t), NIL)?;
        }
        3 => {
            let c = g.cond(b)?;
            let (t1, t2) = (target(g), target(g));
            let v = b.value(Opc::Ite, 64, 0, [c, Arg::k(t1), Arg::k(t2)])?;
            b.flow(Opc::JumpInd, v.into(), NIL)?;
            extra.extend([(starts[i], t1), (starts[i], t2)]);
        }
        _ => b.flow(Opc::Ret, NIL, NIL)?,
    }
    Ok(())
}

/// Makes one random program of 1 to 7 blocks.
pub fn random_program(rng: &mut Xoshiro256ss) -> Program {
    let count = usize::try_from(1 + below(rng, 7)).expect("small");
    let sizes: Vec<u64> = (0..count).map(|_| 1 + below(rng, 3)).collect();
    let mut starts = Vec::new();
    let mut addr = 0x1000u64;
    for size in &sizes {
        starts.push(addr);
        addr += 4 * size;
    }
    let mut extra = Vec::new();
    let mut b = Builder::new();
    for (i, size) in sizes.iter().enumerate() {
        let mut g = Gen {
            rng: &mut *rng,
            temps: Vec::new(),
        };
        for k in 0..*size {
            b.begin(starts[i] + 4 * k, 4).expect("in order");
            for _ in 0..g.below(5) {
                g.op(&mut b).expect("the op builds");
            }
        }
        terminator(&mut g, &mut b, &starts, i, &mut extra).expect("the terminator builds");
    }
    let arena = b.finish();
    let body = body_with(&arena, &starts, &extra);
    let setup = POOL
        .iter()
        .map(|&loc| {
            let hi = u128::from(rng.next_u64()) << 64;
            (loc, hi | u128::from(rng.next_u64()))
        })
        .collect();
    Program {
        arena,
        body,
        entry: starts[0],
        setup,
    }
}

/// A writable RAM image with the bytes of `seed`.
pub fn ram_image(seed: u64) -> FlatImage {
    let mut rng = Xoshiro256ss::seed_from_u64(seed);
    let mut bytes = vec![0u8; usize::try_from(RAM_SIZE).expect("small")];
    rng.fill_bytes(&mut bytes);
    FlatImage::new(RAM, bytes, true)
}

/// Builds the L1 form of a program with every pass on.
pub fn l1_of(p: &Program) -> Ssa {
    let mut ssa = ssa::build(
        p.arena.clone(),
        p.body.clone(),
        &pool_opts(),
        &mut Fuel::unlimited(),
    )
    .expect("the SSA build");
    let _ = ghidorah_ir::passes::run(&mut ssa, &Switches::all(), &mut Fuel::unlimited())
        .expect("the passes run");
    ssa
}

/// Decompiles the L1 form of a program with `opts`.
pub fn decompile(p: &Program, ssa: &Ssa, opts: &Opts) -> Decomp {
    let tails = BTreeSet::new();
    let input = Input {
        ssa,
        l0: &p.arena,
        tail_calls: &tails,
        conv: None,
    };
    ghidorah_decomp::from_input(&input, &NoEnv, opts, &mut Fuel::unlimited())
        .expect("the decompile")
}

/// The result of one run: the stop reason, the stop op, the uses and the RAM bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The reason.
    pub reason: StopReason,
    /// The stop op.
    pub at: ghidorah_ir::OpId,
    /// The locations that the stop op reads, with their values.
    pub uses: Vec<(Loc, Option<u128>)>,
    /// The bytes of the RAM after the run.
    pub ram: Vec<Option<u8>>,
}

/// Gives the locations that an L0 op reads under the pool options.
fn l0_uses(arena: &Arena, at: ghidorah_ir::OpId) -> Vec<Loc> {
    let Some(op) = arena.insn_ops(at.addr).get(usize::from(at.seq)) else {
        return Vec::new();
    };
    let opts = pool_opts();
    let set = match op.opc {
        Opc::Ret => opts.ret_uses,
        Opc::Call | Opc::CallInd => opts.call_uses,
        Opc::Syscall | Opc::Intrinsic => arena.effect(op).map_or(LocSet::EMPTY, |e| e.uses),
        _ => LocSet::EMPTY,
    };
    set.iter().collect()
}

/// Runs L0 from the entry of a program.
pub fn run_l0(p: &Program, image: &dyn Image) -> Seen {
    let mut interp = Interp::new(&p.arena, image, Config::default());
    for &(loc, value) in &p.setup {
        interp.set_loc(loc, value);
    }
    let stop = interp.run(p.entry, &mut Fuel::new(RUN_FUEL));
    let uses = l0_uses(&p.arena, stop.at)
        .into_iter()
        .map(|loc| (loc, Some(interp.loc(loc))))
        .collect();
    Seen {
        reason: stop.reason,
        at: stop.at,
        uses,
        ram: (RAM..RAM + RAM_SIZE).map(|a| interp.read(a)).collect(),
    }
}

/// Runs the tree of a decompile with values from the entry state of a program.
pub fn run_ast(p: &Program, d: &Decomp, image: &dyn Image) -> Seen {
    let out: Outcome = interp_ast::run(d, image, &Config::default(), &p.setup, 100_000);
    Seen {
        reason: out.reason,
        at: out.at,
        uses: out.uses.clone(),
        ram: (RAM..RAM + RAM_SIZE).map(|a| out.read(image, a)).collect(),
    }
}
