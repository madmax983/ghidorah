//! Tests of the model-based test module.

use std::collections::{BTreeSet, VecDeque};

use ghidorah_testkit::model::{self, Settings};
use ghidorah_testkit::pbt::Gen;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Insert(u64),
    Remove(u64),
    Contains(u64),
}

fn gen_op(g: &mut Gen) -> Op {
    let value = g.draw(20);
    match g.draw(3) {
        0 => Op::Insert(value),
        1 => Op::Remove(value),
        _ => Op::Contains(value),
    }
}

/// A sorted-vector set. With `bug`, it drops the insert of 13.
struct VecSet {
    items: Vec<u64>,
    bug: bool,
}

impl VecSet {
    fn apply(&mut self, op: &Op) -> (bool, Vec<u64>) {
        let hit = match *op {
            Op::Insert(v) => {
                if self.bug && v == 13 {
                    false
                } else {
                    match self.items.binary_search(&v) {
                        Ok(_) => false,
                        Err(i) => {
                            self.items.insert(i, v);
                            true
                        }
                    }
                }
            }
            Op::Remove(v) => match self.items.binary_search(&v) {
                Ok(i) => {
                    self.items.remove(i);
                    true
                }
                Err(_) => false,
            },
            Op::Contains(v) => self.items.binary_search(&v).is_ok(),
        };
        (hit, self.items.clone())
    }
}

fn model_apply(m: &mut BTreeSet<u64>, op: &Op) -> (bool, Vec<u64>) {
    let hit = match *op {
        Op::Insert(v) => m.insert(v),
        Op::Remove(v) => m.remove(&v),
        Op::Contains(v) => m.contains(&v),
    };
    (hit, m.iter().copied().collect())
}

const SETTINGS: Settings = Settings {
    cases: 200,
    max_steps: 40,
};

#[test]
fn model_check_passes_for_a_correct_system() {
    let result = model::try_model_check(
        "vecset_ok",
        SETTINGS,
        || {
            (
                VecSet {
                    items: Vec::new(),
                    bug: false,
                },
                BTreeSet::new(),
            )
        },
        gen_op,
        VecSet::apply,
        model_apply,
    );
    assert_eq!(result, Ok(200));
    model::model_check(
        "vecset_ok_panicking_form",
        SETTINGS,
        || {
            (
                VecSet {
                    items: Vec::new(),
                    bug: false,
                },
                BTreeSet::new(),
            )
        },
        gen_op,
        VecSet::apply,
        model_apply,
    );
}

#[test]
fn model_check_finds_and_shrinks_a_bug() {
    let result = model::try_model_check(
        "vecset_bug",
        SETTINGS,
        || {
            (
                VecSet {
                    items: Vec::new(),
                    bug: true,
                },
                BTreeSet::new(),
            )
        },
        gen_op,
        VecSet::apply,
        model_apply,
    );
    let Err(failure) = result else {
        panic!("the bug must show");
    };
    assert!(
        failure.message.contains("ops: [Insert(13)]"),
        "the sequence shrinks to one insert: {}",
        failure.message
    );
    assert!(failure.message.contains("step 0"), "{}", failure.message);
}

#[test]
fn model_check_runs_queue_against_vecdeque() {
    #[derive(Debug)]
    enum QOp {
        Push(u64),
        Pop,
    }
    let result = model::try_model_check(
        "queue",
        Settings {
            cases: 50,
            max_steps: 30,
        },
        || (Vec::<u64>::new(), VecDeque::<u64>::new()),
        |g| {
            if g.bool() {
                QOp::Push(g.draw(100))
            } else {
                QOp::Pop
            }
        },
        |s, op| match op {
            QOp::Push(v) => {
                s.push(*v);
                None
            }
            QOp::Pop => {
                if s.is_empty() {
                    None
                } else {
                    Some(s.remove(0))
                }
            }
        },
        |m, op| match op {
            QOp::Push(v) => {
                m.push_back(*v);
                None
            }
            QOp::Pop => m.pop_front(),
        },
    );
    assert_eq!(result, Ok(50));
}
