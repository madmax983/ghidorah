//! The IR of ghidorah: L0 ops, locations, flag semantics, fusion, the interpreter, graph
//! algorithms, L1 SSA and its passes (design Section 6, ADR-0009).
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//! It depends on `ghidorah-base` and `ghidorah-kernel`. ISA crates depend on it.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`loc`] | [`Loc`] and [`LocSet`] | Section 6.1 |
//! | [`op`] | [`Op`], [`Opc`], [`Val`], [`Arg`], [`FlagOp`], [`Cc`] and [`Effect`] | Section 6.1 |
//! | [`arena`] | [`Arena`] and [`Builder`] | Section 6.1 |
//! | [`sem`] | [`x86_flags`], [`x86_cond`] and [`undefined_mask`] | Section 6.2 |
//! | [`fuse`](mod@fuse) | [`fuse()`] through the verified table K5 | Section 6.2 |
//! | [`interp`] | [`Interp`], [`eval`] and the [`Stop`] reasons | Section 6.5 |
//! | [`graph`] | [`Cfg`], [`rpo`], [`dominators`], [`loops`], [`sccs`], [`irreducible`] | Section 6.4 |
//! | [`ssa`] | [`Ssa`], [`Body`] and [`ssa::build`]: L1 Braun SSA | Section 6.4 |
//! | [`passes`] | [`Pass`], [`Switches`] and [`passes::run`]: the L1 passes | Section 6.4 |
//! | [`check`](mod@check) | [`check()`]: the SSA checker | Section 6.4 |

pub mod arena;
pub mod check;
mod copyprop;
mod dce;
pub mod fuse;
pub mod graph;
pub mod interp;
pub mod loc;
pub mod op;
pub mod passes;
mod sccp;
pub mod sem;
pub mod ssa;

pub use arena::{Arena, BuildError, Builder, InsnSpan};
pub use check::{Rule, Violation, check};
pub use fuse::{Pred, fuse, pred_opc};
pub use graph::{Cfg, DomTree, GraphError, Loop, Node, dominators, irreducible, loops, rpo, sccs};
pub use interp::{Config, EvalError, FlatImage, Image, Interp, NoImage, Stop, StopReason, eval};
pub use loc::{Loc, LocSet};
pub use op::{Arg, Cc, Effect, FlagOp, Imm, IntrinsicId, MemEffect, Op, OpId, Opc, Val};
pub use passes::{Pass, PassRun, Report, Switches};
pub use sem::{undefined_mask, x86_cond, x86_flags};
pub use ssa::{Anchor, Block, Body, Opts, Ssa, SsaError};
