//! The shrink passes: chunk delete, value lowering and value moves.
//!
//! Each accepted change makes the sequence smaller in shortlex order, so the
//! passes stop. The budget caps the number of `fails` calls.

/// The chunk sizes of the delete pass, from large to small.
///
/// All sizes up to 8 occur, so the pass can delete one whole operation of up to 8 choices.
const CHUNKS: [usize; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

/// The largest distance between the two choices of a value move.
const MOVE_SPAN: usize = 8;

/// A failing predicate with a call budget.
struct Probe<F> {
    fails: F,
    calls: u32,
    budget: u32,
}

impl<F: FnMut(&[u64]) -> bool> Probe<F> {
    /// Returns `true` when `candidate` fails. A spent budget gives `false`.
    fn fails(&mut self, candidate: &[u64]) -> bool {
        if self.calls >= self.budget {
            return false;
        }
        self.calls += 1;
        (self.fails)(candidate)
    }

    const fn spent(&self) -> bool {
        self.calls >= self.budget
    }
}

/// Deletes chunks while the sequence still fails.
fn delete_chunks<F: FnMut(&[u64]) -> bool>(best: &mut Vec<u64>, probe: &mut Probe<F>) -> bool {
    let mut improved = false;
    for k in CHUNKS {
        let mut i = 0;
        while i + k <= best.len() && !probe.spent() {
            let mut candidate = Vec::with_capacity(best.len() - k);
            candidate.extend_from_slice(&best[..i]);
            candidate.extend_from_slice(&best[i + k..]);
            if probe.fails(&candidate) {
                *best = candidate;
                improved = true;
            } else {
                i += 1;
            }
        }
    }
    improved
}

/// Lowers each value to 0, or to the lowest failing value of a binary search.
fn lower_values<F: FnMut(&[u64]) -> bool>(best: &mut [u64], probe: &mut Probe<F>) -> bool {
    let mut improved = false;
    for i in 0..best.len() {
        let current = best[i];
        if current == 0 || probe.spent() {
            continue;
        }
        let mut candidate = best.to_vec();
        candidate[i] = 0;
        if probe.fails(&candidate) {
            best[i] = 0;
            improved = true;
            continue;
        }
        let (mut lo, mut hi) = (0, current);
        while lo + 1 < hi && !probe.spent() {
            let mid = lo + (hi - lo) / 2;
            candidate[i] = mid;
            if probe.fails(&candidate) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        if hi < current {
            best[i] = hi;
            improved = true;
        }
    }
    improved
}

/// Moves the value of choice `i` into a later choice `j`.
fn move_values<F: FnMut(&[u64]) -> bool>(best: &mut [u64], probe: &mut Probe<F>) -> bool {
    let mut improved = false;
    for i in 0..best.len() {
        for j in i + 1..best.len().min(i + 1 + MOVE_SPAN) {
            if best[i] == 0 || probe.spent() {
                break;
            }
            let mut candidate = best.to_vec();
            candidate[j] = candidate[j].saturating_add(candidate[i]);
            candidate[i] = 0;
            if probe.fails(&candidate) {
                best.copy_from_slice(&candidate);
                improved = true;
            }
        }
    }
    improved
}

/// Shrinks `choices` with at most `budget` calls of `fails`.
pub(super) fn run<F: FnMut(&[u64]) -> bool>(choices: &[u64], budget: u32, fails: F) -> Vec<u64> {
    let mut best = choices.to_vec();
    let mut probe = Probe {
        fails,
        calls: 0,
        budget,
    };
    loop {
        let deleted = delete_chunks(&mut best, &mut probe);
        let lowered = lower_values(&mut best, &mut probe);
        let moved = move_values(&mut best, &mut probe);
        if !(deleted || lowered || moved) || probe.spent() {
            return best;
        }
    }
}
