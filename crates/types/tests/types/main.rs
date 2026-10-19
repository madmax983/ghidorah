//! Tests of `ghidorah-types` (design Section 9, WP-10).
//!
//! | Module | Subject |
//! |---|---|
//! | `cparse` | C parser spec tables in both modes |
//! | `unsupported` | AC-110: features outside the MVP |
//! | `limits` | AC-111: parser bombs in a small stack |
//! | `layout` | AC-112a: SysV layouts, flexible arrays, by-value cycles |
//! | `tier0` | AC-109: Tier-0 prototypes |
//! | `store` | The type store, the C text and the type references |
//! | `data` | Noreturn lists, the syscall table, calling conventions, data models, license rows |
//! | `msx64` | The MS x64 convention, the `x86_64-win` model and the PE noreturn list (WP-30) |

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]

mod cparse;
mod data;
mod layout;
mod limits;
mod msx64;
mod store;
mod support;
mod tier0;
mod unsupported;
