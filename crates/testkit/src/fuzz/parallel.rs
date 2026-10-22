//! The tier-1 run of the fuzz harness: one input generator and at most [`WORKERS`] case
//! threads (see the module doc of [`super`]).

use std::path::Path;

use super::{Config, FuzzError, Outcome, Report, WORKERS, batch_seed, mutate, run_case};
use crate::rng::{Xoshiro256ss, below};

/// Gives an empty report of the run `config`.
pub(super) fn empty_report(config: &Config) -> Report {
    Report {
        target: config.target.clone(),
        reached: vec![0; config.stages.len()],
        ..Report::default()
    }
}

/// Gives the input of the next case: a mutation of a random corpus input, or of an empty
/// input for an empty corpus.
pub(super) fn next_input(rng: &mut Xoshiro256ss, corpus: &[Vec<u8>], max_len: usize) -> Vec<u8> {
    let count = u64::try_from(corpus.len()).unwrap_or(u64::MAX);
    let seed: &[u8] = if count == 0 {
        &[]
    } else {
        let i = usize::try_from(below(rng, count)).unwrap_or(0);
        corpus.get(i).map_or(&[], Vec::as_slice)
    };
    mutate(rng, seed, max_len)
}

/// Runs the cases of a tier-1 run in at most [`WORKERS`] case threads (see the module doc).
/// Case thread `k` writes the pending file `pending-<k>.bin` in `pending_dir`.
pub(super) fn run_parallel<F>(
    config: &Config,
    corpus: &[Vec<u8>],
    target: &F,
    pending_dir: Option<&Path>,
) -> Result<Report, FuzzError>
where
    F: Fn(&[u8]) -> Outcome + Sync,
{
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, WORKERS);
    let (send, receive) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>)>(workers * 4);
    let receive = std::sync::Mutex::new(receive);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for k in 0..workers {
            let pending = pending_dir.map(|d| d.join(format!("pending-{k}.bin")));
            let receive = &receive;
            let body = move || -> Result<Report, FuzzError> {
                let mut report = empty_report(config);
                loop {
                    let next = receive
                        .lock()
                        .map_err(|_| FuzzError::Thread("the case queue is poisoned".to_string()))?
                        .recv();
                    let Ok((case, input)) = next else {
                        return Ok(report);
                    };
                    run_case(
                        pending.as_deref(),
                        case,
                        &input,
                        target,
                        &mut report,
                        config.max_crashes,
                    )?;
                }
            };
            let handle = std::thread::Builder::new()
                .name(format!("fuzz-{}-{k}", config.target))
                .stack_size(config.stack_size)
                .spawn_scoped(scope, body)
                .map_err(|e| FuzzError::Thread(e.to_string()))?;
            handles.push(handle);
        }
        let mut rng = Xoshiro256ss::seed_from_u64(batch_seed(config.seed, None));
        for case in 0..config.cases {
            let input = next_input(&mut rng, corpus, config.max_len);
            if send.send((case, input)).is_err() {
                break;
            }
        }
        drop(send);
        let mut report = empty_report(config);
        for handle in handles {
            let part = handle.join().map_err(|_| {
                FuzzError::Thread("a case thread stopped with a panic".to_string())
            })??;
            report.merge(part, config.max_crashes);
        }
        Ok(report)
    })
}

impl Report {
    /// Adds the counts and the crashes of `other`. Then the report keeps its first `max`
    /// crashes in case order.
    pub(super) fn merge(&mut self, other: Self, max: usize) {
        self.cases = self.cases.saturating_add(other.cases);
        self.panics = self.panics.saturating_add(other.panics);
        self.violations = self.violations.saturating_add(other.violations);
        if self.reached.len() < other.reached.len() {
            self.reached.resize(other.reached.len(), 0);
        }
        for (slot, n) in self.reached.iter_mut().zip(other.reached) {
            *slot = slot.saturating_add(n);
        }
        self.crashes.extend(other.crashes);
        self.crashes.sort_by_key(|c| c.case);
        self.crashes.truncate(max);
    }
}
