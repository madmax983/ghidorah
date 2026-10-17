//! Tests of `Glob` (design Section 10.4, AC-048).

use ghidorah_base::glob::MAX_PATTERN_CHARS;
use ghidorah_base::{Glob, GlobError};

fn glob(pattern: &str) -> Glob {
    Glob::new(pattern).unwrap_or_else(|e| panic!("{pattern}: {e}"))
}

#[test]
fn ac_048_glob_linear() {
    let text = "a".repeat(10_000);
    let pattern = "*a*a*a*a*b";
    let (matched, steps) = glob(pattern).matches_counted(&text);
    assert!(!matched);
    let bound = 4 * (text.len() + pattern.len()) as u64;
    assert!(steps <= bound, "{steps} steps, bound {bound}");
    assert!(steps >= text.len() as u64, "the matcher reads the text: {steps}");

    // Doubling the text at most doubles the work.
    let (_, steps_2x) = glob(pattern).matches_counted(&"a".repeat(20_000));
    assert!(steps_2x <= 2 * steps + 64, "{steps_2x} against {steps}");

    let (matched, steps) = glob("*a*a*a*a*a").matches_counted(&text);
    assert!(matched);
    assert!(steps <= bound);
    let (matched, steps) = glob("*?*?*?*b").matches_counted(&text);
    assert!(!matched);
    assert!(steps <= bound);
}

#[test]
fn glob_table() {
    let cases = [
        ("main", "main", true),
        ("main", "mains", false),
        ("", "", true),
        ("", "a", false),
        ("*", "", true),
        ("*", "anything", true),
        ("?", "", false),
        ("?", "\u{e9}", true),
        ("parse_*", "parse_cfg", true),
        ("parse_*", "xparse_cfg", false),
        ("*_cfg", "parse_cfg", true),
        ("*cfg*", "a_cfg_b", true),
        ("a*b*c", "aXbYc", true),
        ("a*b*c", "aXbY", false),
        ("a?c", "abc", true),
        ("a?c", "ac", false),
        ("**a", "a", true),
        ("*a*b", "ab", true),
        ("*a*b", "ba", false),
        ("str*", "strcmp", true),
        ("\\*", "*", true),
        ("\\*", "a", false),
        ("\\?x", "?x", true),
        ("a\\\\b", "a\\b", true),
        ("\\a", "a", true),
        ("puts@*", "puts@GLIBC_2.2.5", true),
        ("Main", "main", false),
        ("*.cold", "foo.cold", true),
    ];
    for (pattern, text, want) in cases {
        assert_eq!(glob(pattern).matches(text), want, "{pattern:?} on {text:?}");
    }
    assert!(glob("main").is_literal());
    assert!(glob("\\*").is_literal());
    assert!(!glob("m*").is_literal());
    assert!(!glob("m?").is_literal());
    assert_eq!(Glob::new("a\\"), Err(GlobError::TrailingEscape));
    let long = "a".repeat(MAX_PATTERN_CHARS + 1);
    assert_eq!(
        Glob::new(&long),
        Err(GlobError::TooLong {
            chars: MAX_PATTERN_CHARS + 1,
        })
    );
    assert!(Glob::new(&"a".repeat(MAX_PATTERN_CHARS)).is_ok());
    assert!(GlobError::TrailingEscape.to_string().ends_with('.'));
    assert!(GlobError::TooLong { chars: 2000 }.to_string().contains("2000"));
}
