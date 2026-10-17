//! Strongly connected components and irreducible regions (iterative Tarjan).

use std::collections::BTreeSet;

use super::{Cfg, DomTree, Node, node};

/// The state of an iterative Tarjan walk over a part of a graph.
struct Tarjan {
    index: Vec<u32>,
    low: Vec<u32>,
    on_stack: Vec<bool>,
}

/// The index of a node that the walk did not visit.
const UNSEEN: u32 = u32::MAX;

impl Tarjan {
    fn new(count: usize) -> Self {
        Self {
            index: vec![UNSEEN; count],
            low: vec![0; count],
            on_stack: vec![false; count],
        }
    }

    /// Gives the components of `nodes` over the edges between nodes for which `alive` is
    /// true. The roots go in the order of `nodes`.
    fn run(&mut self, cfg: &Cfg, nodes: &[Node], alive: &dyn Fn(Node) -> bool) -> Vec<Vec<Node>> {
        for n in nodes {
            if let Some(slot) = self.index.get_mut(n.index()) {
                *slot = UNSEEN;
            }
        }
        let mut next = 0u32;
        let mut stack: Vec<Node> = Vec::new();
        let mut found = Vec::new();
        for &root in nodes {
            if self.index.get(root.index()) != Some(&UNSEEN) {
                continue;
            }
            self.visit(root, &mut next, &mut stack);
            let mut call = vec![(root, 0usize)];
            while let Some(top) = call.last_mut() {
                let (v, i) = *top;
                if let Some(&w) = cfg.succs(v).get(i) {
                    top.1 = i + 1;
                    if !alive(w) {
                        continue;
                    }
                    let wi = self.index.get(w.index()).copied().unwrap_or(UNSEEN);
                    if wi == UNSEEN {
                        self.visit(w, &mut next, &mut stack);
                        call.push((w, 0));
                    } else if self.on_stack.get(w.index()) == Some(&true) {
                        self.lower(v, wi);
                    }
                    continue;
                }
                call.pop();
                let v_low = self.low.get(v.index()).copied().unwrap_or(0);
                if let Some(&(u, _)) = call.last() {
                    self.lower(u, v_low);
                }
                if Some(&v_low) == self.index.get(v.index()) {
                    found.push(self.pop_component(v, &mut stack));
                }
            }
        }
        found
    }

    fn visit(&mut self, n: Node, next: &mut u32, stack: &mut Vec<Node>) {
        let i = n.index();
        if let (Some(index), Some(low), Some(on)) = (
            self.index.get_mut(i),
            self.low.get_mut(i),
            self.on_stack.get_mut(i),
        ) {
            *index = *next;
            *low = *next;
            *on = true;
        }
        *next = next.saturating_add(1);
        stack.push(n);
    }

    fn lower(&mut self, n: Node, value: u32) {
        if let Some(low) = self.low.get_mut(n.index()) {
            *low = (*low).min(value);
        }
    }

    fn pop_component(&mut self, root: Node, stack: &mut Vec<Node>) -> Vec<Node> {
        let mut component = Vec::new();
        while let Some(w) = stack.pop() {
            if let Some(on) = self.on_stack.get_mut(w.index()) {
                *on = false;
            }
            component.push(w);
            if w == root {
                break;
            }
        }
        component.sort_unstable();
        component
    }
}

/// Gives the strongly connected components of all nodes (Tarjan).
///
/// Each component lists its nodes in node order. The list of components is in reverse
/// topological order: a component comes before each component that reaches it.
#[must_use]
pub fn sccs(cfg: &Cfg) -> Vec<Vec<Node>> {
    let all: Vec<Node> = (0..cfg.len()).map(node).collect();
    Tarjan::new(cfg.len()).run(cfg, &all, &|_| true)
}

/// Tells if a component has a cycle: more than one node, or a self loop.
fn has_cycle(cfg: &Cfg, component: &[Node]) -> bool {
    match component {
        [n] => cfg.succs(*n).contains(n),
        _ => component.len() > 1,
    }
}

/// Gives the irreducible regions of the reachable part of `cfg`.
///
/// A region is a cycle with more than one entry node. The search takes each strongly
/// connected component with a cycle. A component with one entry loses its header, and the
/// search goes on inside the rest. A component with more entries is a region, and the
/// search goes on without its entry nodes. Each region lists its nodes in node order.
#[must_use]
pub fn irreducible(cfg: &Cfg, dom: &DomTree) -> Vec<Vec<Node>> {
    let preds = cfg.preds();
    let mut tarjan = Tarjan::new(cfg.len());
    // `group[v]` names the current part of node `v`. A walk keeps to one part.
    let mut group = vec![0u32; cfg.len()];
    let reachable: Vec<Node> = (0..cfg.len())
        .map(node)
        .filter(|&n| dom.is_reachable(n))
        .collect();
    for n in &reachable {
        if let Some(slot) = group.get_mut(n.index()) {
            *slot = 1;
        }
    }
    let mut next_group = 1u32;
    let mut work: Vec<Vec<Node>> = {
        let g = &group;
        tarjan.run(cfg, &reachable, &|n| g.get(n.index()) == Some(&1))
    };
    let mut regions = Vec::new();
    while let Some(component) = work.pop() {
        if !has_cycle(cfg, &component) {
            continue;
        }
        next_group = next_group.saturating_add(1);
        for n in &component {
            if let Some(slot) = group.get_mut(n.index()) {
                *slot = next_group;
            }
        }
        let inside = |n: Node| group.get(n.index()) == Some(&next_group);
        let mut entries: BTreeSet<Node> = component
            .iter()
            .copied()
            .filter(|&v| {
                v == cfg.entry()
                    || preds
                        .get(v.index())
                        .is_some_and(|list| list.iter().any(|&p| dom.is_reachable(p) && !inside(p)))
            })
            .collect();
        if entries.is_empty() {
            entries.extend(component.first().copied());
        }
        if entries.len() > 1 {
            regions.push(component.clone());
        }
        let rest: Vec<Node> = component
            .iter()
            .copied()
            .filter(|n| !entries.contains(n))
            .collect();
        next_group = next_group.saturating_add(1);
        for n in &rest {
            if let Some(slot) = group.get_mut(n.index()) {
                *slot = next_group;
            }
        }
        let g = &group;
        let part = next_group;
        work.extend(tarjan.run(cfg, &rest, &|n| g.get(n.index()) == Some(&part)));
    }
    regions.sort();
    regions
}
