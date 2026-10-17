//! AC-006b: a kernel function with a `cfg_attr` loop invariant and a `proof!{}` block
//! builds and passes under plain `cargo test`.

use ghidorah_kernel::{Endian, Reader, fit_prefix};

/// Gives the source text of the function `name` in `text`: from `fn name(` to the next `pub fn`.
fn function<'a>(text: &'a str, name: &str) -> &'a str {
    let start = text.find(&format!("fn {name}(")).unwrap_or(text.len());
    let rest = text.get(start..).unwrap_or_default();
    let end = rest
        .get(1..)
        .and_then(|r| r.find("pub fn "))
        .map_or(rest.len(), |i| i + 1);
    rest.get(..end).unwrap_or_default()
}

#[test]
fn ac_006b_loop_invariant_builds() {
    let reader = include_str!("../src/reader.rs");
    let uleb = function(reader, "uleb128");
    assert!(
        uleb.contains("#[cfg_attr(verus_only, verus_spec(") && uleb.contains("proof! {"),
        "uleb128 has a cfg_attr loop invariant and a proof! block"
    );
    let budget = include_str!("../src/budget.rs");
    let fit = function(budget, "fit_prefix");
    assert!(
        fit.contains("#[cfg_attr(verus_only, verus_spec(") && fit.contains("proof! {"),
        "fit_prefix has a cfg_attr loop invariant and a proof! block"
    );

    let mut r = Reader::new(&[0xe5, 0x8e, 0x26, 0x7f], Endian::Little);
    assert_eq!(r.uleb128(), Ok(624_485));
    assert_eq!(r.uleb128(), Ok(127));
    assert_eq!(fit_prefix(&[3, 4, 5], 2, 1, 10), 2);
}
