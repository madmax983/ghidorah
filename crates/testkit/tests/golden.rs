//! Tests of the golden-file module.

use std::path::PathBuf;

use ghidorah_testkit::golden::{self, Format, GoldenError, Header, Outcome};

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("golden_tests");
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

fn header(version: &str) -> Header {
    Header::new("testkit-golden-test", version).with("fixture_sha256", "ab12")
}

#[test]
fn golden_header_mismatch_fails() {
    let path = tmp("header_mismatch.txt");
    assert_eq!(
        golden::compare(&path, &header("1"), "body line\n", true),
        Ok(Outcome::Blessed)
    );
    assert_eq!(
        golden::compare(&path, &header("1"), "body line\n", false),
        Ok(Outcome::Match)
    );
    match golden::compare(&path, &header("2"), "body line\n", false) {
        Err(GoldenError::HeaderMismatch {
            expected, found, ..
        }) => {
            assert!(expected.contains("version=2"), "{expected}");
            assert!(found.contains("version=1"), "{found}");
        }
        other => panic!("a header change must fail: {other:?}"),
    }
    let other_fixture = Header::new("testkit-golden-test", "1").with("fixture_sha256", "cd34");
    assert!(matches!(
        golden::compare(&path, &other_fixture, "body line\n", false),
        Err(GoldenError::HeaderMismatch { .. })
    ));
}

#[test]
fn golden_body_mismatch_names_the_line() {
    let path = tmp("body_mismatch.txt");
    let _ = golden::compare(&path, &header("1"), "a\nb\nc\n", true);
    match golden::compare(&path, &header("1"), "a\nB\nc\n", false) {
        Err(GoldenError::BodyMismatch { line, diff, .. }) => {
            assert_eq!(line, 2);
            assert!(diff.contains("- b"), "{diff}");
            assert!(diff.contains("+ B"), "{diff}");
        }
        other => panic!("a body change must fail: {other:?}"),
    }
}

#[test]
fn golden_missing_file_fails_without_bless() {
    let path = tmp("missing.txt");
    assert!(matches!(
        golden::compare(&path, &header("1"), "x\n", false),
        Err(GoldenError::Missing { .. })
    ));
    let message = GoldenError::Missing {
        path: "p".to_string(),
    }
    .to_string();
    assert!(message.contains("GHIDORAH_BLESS=1"), "{message}");
}

#[test]
fn golden_bless_writes_header_and_body() {
    let path = tmp("bless_text.txt");
    assert_eq!(
        golden::compare(&path, &header("3"), "one\ntwo", true),
        Ok(Outcome::Blessed)
    );
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        text,
        "# golden: generator=testkit-golden-test version=3 fixture_sha256=ab12\none\ntwo\n"
    );
    let read = golden::read(&path);
    assert_eq!(read, Ok((header("3"), "one\ntwo\n".to_string())));
}

#[test]
fn golden_json_header_form() {
    let path = tmp("bless_json.json");
    assert_eq!(Format::of_path(&path), Format::Json);
    assert_eq!(Format::of_path(&tmp("x.jsonl")), Format::Json);
    assert_eq!(Format::of_path(&tmp("x.txt")), Format::Text);
    let _ = golden::compare(&path, &header("1"), "{\"a\": 1}\n", true);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        text,
        "{\"golden\":\"generator=testkit-golden-test version=1 fixture_sha256=ab12\"}\n{\"a\": 1}\n"
    );
    golden::assert_json(&path, &header("1"), "{\"a\": 1}\n");
}

#[test]
fn golden_header_parse_roundtrip() {
    let h = Header::new("gen", "0.1").with("oracle", "readelf 2.42").with("b", "2");
    for format in [Format::Text, Format::Json] {
        let line = h.render(format);
        let back = Header::parse(&line, format);
        let want = Header::new("gen", "0.1").with("oracle", "readelf_2.42").with("b", "2");
        assert_eq!(back, Ok(want), "{line}");
    }
    assert_eq!(h.field("b"), Some("2"));
    assert_eq!(h.generator(), "gen");
    assert_eq!(h.version(), "0.1");
    assert!(Header::parse("not a header", Format::Text).is_err());
}

#[test]
fn golden_assert_text_passes_on_match() {
    let path = tmp("assert_match.txt");
    let _ = golden::compare(&path, &header("1"), "same\n", true);
    golden::assert_text(&path, &header("1"), "same\n");
}
