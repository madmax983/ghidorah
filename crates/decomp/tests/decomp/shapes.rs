//! Random shapes for the structurer tests: any CFG, reducible CFGs and the deep chain.

use ghidorah_decomp::shape::{Exit, NodeKind, Shape, ShapeNode};
use ghidorah_ir::{Cfg, Node, dominators};
use ghidorah_testkit::rng::{Rng, Xoshiro256ss, below};

/// Gives the node of an index.
pub fn node(i: usize) -> Node {
    Node(u32::try_from(i).expect("small"))
}

/// Gives the address of node `i`.
pub fn addr(i: usize) -> u64 {
    0x1000 + 0x10 * u64::try_from(i).expect("small")
}

/// Makes a shape of block nodes with these exits and purity flags.
pub fn shape_of(exits: Vec<Exit>, pure: &[bool]) -> Shape {
    let nodes = exits
        .into_iter()
        .enumerate()
        .map(|(i, exit)| ShapeNode {
            addr: addr(i),
            kind: NodeKind::Block(node(i)),
            exit,
            pure: pure.get(i).copied().unwrap_or(false),
        })
        .collect();
    Shape {
        entry: Node(0),
        nodes,
    }
}

/// Gives a random target: a near forward node most of the time.
fn target(rng: &mut Xoshiro256ss, i: usize, n: usize) -> Node {
    let n64 = u64::try_from(n).expect("small");
    let i64 = u64::try_from(i).expect("small");
    let t = if below(rng, 4) == 0 {
        below(rng, n64)
    } else {
        (i64 + 1 + below(rng, 3)).min(n64 - 1)
    };
    node(usize::try_from(t).expect("small"))
}

/// Gives a random exit of node `i` of `n` with targets from `pick`.
fn exit(
    rng: &mut Xoshiro256ss,
    i: usize,
    n: usize,
    pick: &mut dyn FnMut(&mut Xoshiro256ss) -> Node,
) -> Exit {
    let last = i + 1 == n;
    match below(rng, 10) {
        0 => Exit::Stop,
        _ if last && below(rng, 2) == 0 => Exit::Stop,
        1..=3 => Exit::Fall(pick(rng)),
        4..=8 => Exit::Cond {
            t: pick(rng),
            f: pick(rng),
        },
        _ => {
            let k = 2 + usize::try_from(below(rng, 4)).expect("small");
            Exit::Switch((0..k).map(|_| pick(rng)).collect())
        }
    }
}

/// Makes a random shape of 1 to `max` nodes. Back edges and irreducible cycles can occur.
pub fn random(rng: &mut Xoshiro256ss, max: usize) -> Shape {
    let n = 1 + usize::try_from(below(rng, u64::try_from(max).expect("small"))).expect("small");
    let mut exits = Vec::new();
    let mut pure = Vec::new();
    for i in 0..n {
        let mut pick = |r: &mut Xoshiro256ss| target(r, i, n);
        exits.push(exit(rng, i, n, &mut pick));
        pure.push(below(rng, 2) == 0);
    }
    shape_of(exits, &pure)
}

/// Gives the CFG of a shape over its nodes.
pub fn cfg_of(shape: &Shape) -> Cfg {
    let mut cfg = Cfg::new(shape.len(), shape.entry).expect("a valid entry");
    for (i, n) in shape.nodes.iter().enumerate() {
        for s in n.exit.succs() {
            cfg.add_edge(node(i), s).expect("valid nodes");
        }
    }
    cfg
}

/// Gives the cycles of a shape with more than one entry node.
pub fn irreducible_of(shape: &Shape) -> Vec<Vec<Node>> {
    let cfg = cfg_of(shape);
    let dom = dominators(&cfg);
    ghidorah_ir::irreducible(&cfg, &dom)
}

/// Makes a random reducible shape of 1 to `max` nodes.
///
/// The forward edges make a DAG. Then some targets become a dominator of their source, so
/// each cycle has one entry: its header.
pub fn reducible(rng: &mut Xoshiro256ss, max: usize) -> Shape {
    let n = 1 + usize::try_from(below(rng, u64::try_from(max).expect("small"))).expect("small");
    let mut exits = Vec::new();
    let mut pure = Vec::new();
    for i in 0..n {
        let mut pick = |r: &mut Xoshiro256ss| {
            if i + 1 >= n {
                return node(i);
            }
            let ahead = u64::try_from(n - i - 1).expect("small");
            let step = 1 + below(r, ahead.min(4));
            node(i + usize::try_from(step).expect("small"))
        };
        let mut e = exit(rng, i, n, &mut pick);
        if i + 1 == n && e != Exit::Stop {
            e = Exit::Stop;
        }
        exits.push(e);
        pure.push(below(rng, 2) == 0);
    }
    let mut shape = shape_of(exits, &pure);
    let dom = dominators(&cfg_of(&shape));
    for i in 0..n {
        if below(rng, 3) != 0 || !dom.is_reachable(node(i)) {
            continue;
        }
        let mut doms = vec![node(i)];
        let mut cur = node(i);
        while let Some(d) = dom.idom(cur) {
            doms.push(d);
            cur = d;
        }
        let k =
            usize::try_from(below(rng, u64::try_from(doms.len()).expect("small"))).expect("small");
        let back = doms[k];
        let exit = &mut shape.nodes[i].exit;
        match exit {
            Exit::Stop => *exit = Exit::Cond { t: back, f: back },
            Exit::Fall(t) | Exit::Cond { t, .. } => *t = back,
            Exit::Switch(list) => list[0] = back,
        }
    }
    shape
}

/// Makes the chain of `n` nodes: each node falls to the next one, and the last one stops.
pub fn chain(n: usize) -> Shape {
    let exits = (0..n)
        .map(|i| {
            if i + 1 == n {
                Exit::Stop
            } else {
                Exit::Fall(node(i + 1))
            }
        })
        .collect();
    shape_of(exits, &[])
}

/// Gives a random seed stream for the oracles of one shape.
pub fn seeds(rng: &mut Xoshiro256ss, count: usize) -> Vec<u64> {
    (0..count).map(|_| rng.next_u64()).collect()
}
