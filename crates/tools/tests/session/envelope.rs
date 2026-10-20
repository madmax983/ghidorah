//! The envelope frame, `partial` and the repair hints of failures (design Sections 10.6
//! and 10.8).

use ghidorah_json::Value;

use crate::support::{call, fixture, text_at};

/// A binary with no analysis run gives partial results, an `analysis` member with the
/// state `none` and the `analysis_run` hint.
#[test]
fn regress_no_analysis_is_partial() {
    let (mut s, _) = fixture("hello.gcc-O0");
    let list = call(&mut s, "func_list", "{}");
    assert_eq!(list.get("ok"), Some(&Value::Bool(true)), "{list}");
    assert_eq!(list.get("partial"), Some(&Value::Bool(true)), "{list}");
    assert_eq!(text_at(&list, "/analysis/state"), "none", "{list}");
    assert_eq!(text_at(&list, "/next/0/tool"), "analysis_run", "{list}");
}
