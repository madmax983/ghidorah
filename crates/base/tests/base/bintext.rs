//! Tests of `BinText` (design Section 10.16, ADR-0022).

use ghidorah_base::bintext::{HARD_CAP, SRC};
use ghidorah_base::{BinText, Caps, Rendered};

fn text(bytes: &[u8]) -> String {
    BinText::new(bytes).render(Caps::DEFAULT).text
}

#[test]
fn bintext_caps_and_escapes() {
    let escapes: [(&[u8], &str); 14] = [
        (b"hello", "hello"),
        (b"a\\b", "a\\\\b"),
        (b"\x00\x1b[31m", "\\x00\\x1b[31m"),
        (b"tab\there\nline\r", "tab\\x09here\\x0aline\\x0d"),
        (b"\x7f", "\\x7f"),
        ("\u{85}".as_bytes(), "\\u{85}"),
        ("\u{9f}".as_bytes(), "\\u{9f}"),
        ("a\u{2028}b\u{2029}".as_bytes(), "a\\u{2028}b\\u{2029}"),
        ("\u{202e}evil".as_bytes(), "\\u{202e}evil"),
        (
            "\u{2066}\u{2069}\u{200e}\u{200f}\u{61c}".as_bytes(),
            "\\u{2066}\\u{2069}\\u{200e}\\u{200f}\\u{61c}",
        ),
        ("caf\u{e9} \u{4e2d}".as_bytes(), "caf\u{e9} \u{4e2d}"),
        (b"\xff\xfe", "\\xff\\xfe"),
        (b"ok\xc3", "ok\\xc3"),
        (b"\"quote\"", "\"quote\""),
    ];
    for (input, want) in escapes {
        assert_eq!(text(input), want, "{input:?}");
    }

    // The text cap counts characters of the escaped text and never cuts an escape.
    let long = vec![b'a'; 300];
    let r = BinText::new(long).render(Caps::DEFAULT);
    assert_eq!(r.text.chars().count(), 256);
    assert_eq!(r.len, 300);
    assert!(r.truncated);
    assert_eq!(r.hex.len(), 600, "300 bytes fit under the hex cap of 512");
    let mut cut_before_escape = vec![b'a'; 253];
    cut_before_escape.push(0x1b);
    let r = BinText::new(cut_before_escape).render(Caps::DEFAULT);
    assert_eq!(
        r.text,
        "a".repeat(253),
        "the escape of 4 characters does not fit"
    );
    assert!(r.truncated);
    let mut fits = vec![b'a'; 252];
    fits.push(0x1b);
    let r = BinText::new(fits).render(Caps::DEFAULT);
    assert_eq!(r.text.chars().count(), 256);
    assert!(r.text.ends_with("\\x1b"));
    assert!(!r.truncated);

    // The hex cap counts input bytes.
    let big = vec![0xabu8; 600];
    let r = BinText::new(big).render(Caps::DEFAULT);
    assert_eq!(r.hex.len(), 1024);
    assert!(r.truncated);
    let r = BinText::new(vec![0u8; 4096]).render(Caps::DETAILED);
    assert_eq!(r.hex.len(), 8192);
    assert_eq!(
        r.text.chars().count(),
        4096,
        "4096 characters of escapes, cut at whole escapes"
    );
    assert!(r.truncated);

    let exact = BinText::new(b"hi".to_vec()).render(Caps::new(2, 2));
    assert_eq!(
        exact,
        Rendered {
            text: "hi".to_string(),
            hex: "6869".to_string(),
            len: 2,
            truncated: false,
        }
    );
    assert_eq!(Caps::new(1 << 20, 1 << 20), Caps::DETAILED);
    assert_eq!(
        Caps::new(10, 20),
        Caps {
            text_chars: 10,
            hex_bytes: 20
        }
    );
    assert_eq!(Caps::default(), Caps::DEFAULT);
    assert_eq!(HARD_CAP, 4096);
}

#[test]
fn bintext_json_shape() {
    let t = BinText::from("a\"b\\c\u{1}");
    assert_eq!(
        t.to_json(Caps::DEFAULT),
        r#"{"text":"a\"b\\\\c\\x01","hex":"6122625c6301","len":6,"src":"binary"}"#
    );
    let long = BinText::new(vec![b'x'; 3]);
    assert_eq!(
        long.to_json(Caps::new(2, 1)),
        r#"{"text":"xx","hex":"78","len":3,"truncated":true,"src":"binary"}"#
    );
    assert_eq!(SRC, "binary");
    let bytes: &[u8] = b"\xff";
    let t = BinText::from(bytes);
    assert_eq!(t.as_bytes(), b"\xff");
    assert_eq!(t.as_str(), None);
    assert_eq!(BinText::from("ok").as_str(), Some("ok"));
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
    assert!(BinText::default().is_empty());
}
