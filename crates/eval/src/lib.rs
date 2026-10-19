//! The offline agent-quality harness of ghidorah (design Section 12, ADR-0015).
//!
//! Without an LLM, the harness cannot measure an agent. It measures the tool surface with
//! deterministic metrics that have ground truth. Frozen questions, held-out intents, the
//! argument-provenance lint, the hint-follower robot and the abstain scenarios guard it
//! against self-grading.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`inputs`] | The frozen questions, the intents and the thresholds | Section 12.2 |
//! | [`scenario`] | The scenario call scripts | Section 12.2 |
//! | [`derive`] | Answer sources, derive steps and answer checks | Section 12.2 |
//! | [`expr`] | The C integer expressions of the `xor` derive step | Section 12.2 |
//! | [`host`] | Sessions, calls and sizes | Section 12.1 |
//! | [`runner`] | The scenario runner and the worker pool | Section 12.1 |
//! | [`lint`] | The argument-provenance lint | Section 12.2, AC-226 |
//! | [`repair`] | The repair robot and the mistake corpus | Section 12.4, AC-197 |
//! | [`follower`] | The hint-follower robot and the hint graph | Section 12.4, AC-227 |
//! | [`discover`] | Discoverability on held-out intents | Section 12.4, AC-198a |
//! | [`recall`] | Context-reset recall, with and without noise edits | Section 12.4, AC-199, AC-229 |
//! | [`survey`] | Survey fact recall | Section 12.4, AC-153b |
//! | [`checks`] | Catalog sizes, schema fuzz and metamorphic relations | Section 12.4 |
//! | [`ab`] | The A/B surface pairs and the ablation | Sections 12.4, 12.8 |
//! | [`report`] | One eval run over all metrics | Section 12.1 |
//! | [`scorecard`] | Metric values, gates and the scorecard JSON | Sections 12.5, 12.6 |
//! | [`gate`] | Gates, baselines, bless and the bless log | Section 12.6 |
//! | [`glob`], [`sha256`], [`milli`] | Glob match, hash locks and rates in thousandths | Section 12.6 |
//! | [`error`] | [`EvalError`] and the file readers | - |

pub mod ab;
pub mod card;
pub mod checks;
pub mod derive;
pub mod discover;
pub mod error;
pub mod explain;
pub mod expr;
pub mod follower;
pub mod gate;
pub mod glob;
pub mod host;
pub mod inputs;
pub mod lint;
pub mod milli;
pub mod recall;
pub mod repair;
pub mod report;
pub mod runner;
pub mod scenario;
pub mod scorecard;
pub mod sha256;
pub mod survey;

pub use error::EvalError;
pub use milli::Milli;
pub use report::{Report, evaluate};
