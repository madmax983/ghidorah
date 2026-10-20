//! Flag fusion of the L0 function IR (design Section 6.2).
//!
//! A `Cond` op can read the flags of a `Flags` thunk in the same block. It can also read them
//! up a chain of blocks with one predecessor. Then it becomes one compare op in place. A call
//! or an effect op that writes the flags ends the chain.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_ir::local;
use ghidorah_ir::ssa::Body;
use ghidorah_ir::{Arena, Arg, Cc, FlagOp, InsnSpan, Loc, Node, Opc, Val, fuse, rpo};

use super::Fusion;

/// Counts the `Cond` ops of an arena.
pub(super) fn count_reads(arena: &Arena) -> u64 {
    let n = arena.ops().iter().filter(|o| o.opc == Opc::Cond).count();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The flags thunk that a block leaves in the flags word, or `None` for an unknown thunk.
type Thunk = Option<u32>;

/// Runs flag fusion over the blocks in reverse postorder. Gives the counts.
pub(super) fn fuse_flags(arena: &mut Arena, body: &Body) -> Fusion {
    let mut out = Fusion::default();
    let preds = body.cfg.preds();
    let mut leave: BTreeMap<Node, Thunk> = BTreeMap::new();
    let insns: Vec<InsnSpan> = arena.insns().to_vec();
    let mut order = rpo(&body.cfg);
    let reached: BTreeSet<Node> = order.iter().copied().collect();
    for n in 0..body.blocks.len() {
        if let Ok(n) = u32::try_from(n)
            && !reached.contains(&Node(n))
        {
            order.push(Node(n));
        }
    }
    for node in order {
        let mut thunk: Thunk = match preds.get(node.index()).map(Vec::as_slice) {
            Some([p]) if *p != node && node != body.cfg.entry() => leave.get(p).copied().flatten(),
            _ => None,
        };
        let Some(block) = body.blocks.get(node.index()) else {
            continue;
        };
        let mut flag_vals: BTreeSet<Val> = BTreeSet::new();
        let first = usize::try_from(block.first).unwrap_or(usize::MAX);
        let count = usize::try_from(block.count).unwrap_or(0);
        for span in insns.iter().skip(first).take(count) {
            for k in 0..span.count {
                let Some(index) = span.first.checked_add(k) else {
                    continue;
                };
                fuse_op(arena, index, &mut thunk, &mut flag_vals, &mut out);
            }
        }
        leave.insert(node, thunk);
    }
    out
}

/// Runs one op of the fusion walk.
fn fuse_op(
    arena: &mut Arena,
    index: u32,
    thunk: &mut Thunk,
    flag_vals: &mut BTreeSet<Val>,
    out: &mut Fusion,
) {
    let Some(op) = arena.op(index).copied() else {
        return;
    };
    match op.opc {
        Opc::Put if op.a[0].as_loc() == Some(Loc::Flags) => {
            flag_vals.clear();
            *thunk = op.a[1]
                .as_v()
                .and_then(|v| arena.def_of(v))
                .filter(|d| arena.op(*d).is_some_and(|o| o.opc == Opc::Flags));
        }
        Opc::Get if op.a[0].as_loc() == Some(Loc::Flags) => {
            if let Some(v) = op.out {
                flag_vals.insert(v);
            }
        }
        Opc::Cond => {
            out.reads = out.reads.saturating_add(1);
            let from_flags = op.a[0].as_v().is_some_and(|v| flag_vals.contains(&v));
            let fused = thunk
                .filter(|_| from_flags)
                .and_then(|t| fused_compare(arena, t, op.sub));
            if let Some((opc, w, x, y)) = fused
                && let Some(slot) = usize::try_from(index)
                    .ok()
                    .and_then(|i| arena.ops_mut().get_mut(i))
            {
                slot.opc = opc;
                slot.w = w;
                slot.sub = 0;
                slot.a = [x, y, Arg::Nil];
                out.fused = out.fused.saturating_add(1);
            }
        }
        Opc::Call | Opc::CallInd => *thunk = None,
        Opc::Syscall | Opc::Intrinsic
            if arena
                .effect(&op)
                .is_none_or(|e| e.defs.contains(Loc::Flags)) =>
        {
            *thunk = None;
        }
        _ => {}
    }
}

/// The x86 condition codes of the sign reductions: `s`, `ns`, `l`, `ge`, `le` and `g`.
const SIGN_CODES: [u8; 6] = [8, 9, 12, 13, 14, 15];

/// The x86 condition codes that read only ZF and SF: `e`, `ne`, `s` and `ns`.
const ZF_SF_CODES: [u8; 4] = [4, 5, 8, 9];

/// Gives the compare op of a `Cond` with the code `cc` on the thunk op `thunk`.
///
/// The verified table K5 comes first. Two reductions follow. A `Logic` thunk of one value
/// `r` has CF and OF 0, so a sign condition is a signed compare of `r` with 0. A shift by a
/// constant count that is not 0 gives ZF and SF of its result `r`, so `e`, `ne`, `s` and
/// `ns` read the flags of `Logic(r, r)`.
fn fused_compare(arena: &Arena, thunk: u32, cc: u8) -> Option<(Opc, u8, Arg, Arg)> {
    let t = arena.op(thunk)?;
    let op = t.flag_op()?;
    if let Some((opc, x, y)) = fuse(op, Cc::x86(cc)?, t.w, t.a[0], t.a[1]) {
        return Some((opc, t.w, x, y));
    }
    let r = match op {
        FlagOp::X86Logic if local::same_value(arena, t.a[0], t.a[1]) => t.a[0],
        FlagOp::X86Shl | FlagOp::X86Shr | FlagOp::X86Sar if ZF_SF_CODES.contains(&cc) => {
            shift_result(arena, thunk)?
        }
        _ => return None,
    };
    if let Some((opc, x, y)) = fuse(FlagOp::X86Logic, Cc::x86(cc)?, t.w, r, r) {
        return Some((opc, t.w, x, y));
    }
    if !SIGN_CODES.contains(&cc) {
        return None;
    }
    let zero = Arg::k(0);
    let (opc, x, y) = match cc {
        8 | 12 => (Opc::SLt, r, zero),
        9 | 13 => (Opc::SLe, zero, r),
        14 => (Opc::SLe, r, zero),
        _ => (Opc::SLt, zero, r),
    };
    Some((opc, t.w, x, y))
}

/// Gives the result of the shift of the thunk op `thunk`. The shift op is in the same
/// instruction. It has the same input and a constant count that is not 0 after the width mask.
fn shift_result(arena: &Arena, thunk: u32) -> Option<Arg> {
    let t = arena.op(thunk)?;
    let mask = if t.w == 64 { 63 } else { 31 };
    if t.a[1].as_k()? & mask == 0 {
        return None;
    }
    let span = arena
        .insns()
        .iter()
        .find(|s| s.first <= thunk && thunk < s.first.saturating_add(s.count))?;
    let ops = arena.span_ops(span)?;
    ops.iter()
        .find(|o| {
            matches!(o.opc, Opc::Shl | Opc::LShr | Opc::AShr)
                && o.w == t.w
                && o.a[0] == t.a[0]
                && o.a[1] == t.a[1]
        })
        .and_then(|o| o.out)
        .map(Arg::V)
}
