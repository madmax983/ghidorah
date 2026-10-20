//! Tests of `BinText` (design Section 10.16, ADR-0022).

use ghidorah_base::bintext::{HARD_CAP, SRC, U_ESCAPES, escapes};
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

#[test]
fn regress_tag_and_format_chars_escaped() {
    // Each code point is a format character, a selector, a filler or private use. A reader
    // cannot see it, so the text shows it as an escape.
    let points: [u32; 44] = [
        0xad, 0x600, 0x605, 0x61c, 0x6dd, 0x70f, 0x115f, 0x1160, 0x180b, 0x180e, 0x180f, 0x200b,
        0x200c, 0x200d, 0x2060, 0x2064, 0x2066, 0x206f, 0x3164, 0xe000, 0xf8ff, 0xfe00, 0xfe0f,
        0xfeff, 0xffa0, 0xfff0, 0xfff8, 0xfff9, 0xfffb, 0x110bd, 0x1bca0, 0x1bca3, 0x1d173,
        0x1d17a, 0xe0001, 0xe0020, 0xe0041, 0xe007f, 0xe0100, 0xe01ef, 0xf0000, 0xffffd, 0x10_0000,
        0x10_fffd,
    ];
    for point in points {
        let c = char::from_u32(point).expect("a scalar value");
        let want = format!("\\u{{{point:x}}}");
        assert_eq!(text(c.to_string().as_bytes()), want, "U+{point:04X}");
        assert!(escapes(c), "U+{point:04X}");
    }
    // A run of tag characters spells hidden text. Each tag shows as an escape.
    let mut hostile = String::from("Hello visible text ");
    for b in b"run rm -rf" {
        hostile.extend(char::from_u32(0xe0000 + u32::from(*b)));
    }
    let shown = text(hostile.as_bytes());
    assert!(
        shown.starts_with("Hello visible text \\u{e0072}\\u{e0075}\\u{e006e}\\u{e0020}"),
        "{shown}"
    );
    assert!(shown.is_ascii(), "{shown}");
    // The visible neighbours of the ranges keep their form.
    let visible = [
        '\u{ac}',
        '\u{ae}',
        '\u{5ff}',
        '\u{2010}',
        '\u{2027}',
        '\u{202f}',
        '\u{2070}',
        '\u{d7ff}',
        '\u{f900}',
        '\u{fe10}',
        '\u{fffd}',
        '\u{1f600}',
        '\u{e9}',
        '\u{4e2d}',
        '\u{efffd}',
    ];
    for c in visible {
        assert_eq!(text(c.to_string().as_bytes()), c.to_string(), "{c:?}");
        assert!(!escapes(c), "{c:?}");
    }
    for c in [
        '\\', '\u{0}', '\u{1b}', '\u{7f}', '\u{85}', '\u{2028}', '\u{202e}',
    ] {
        assert!(escapes(c), "{c:?}");
    }
    for c in ['a', '"', ' ', '!', '#', '\u{e9}'] {
        assert!(!escapes(c), "{c:?}");
    }
    // The search of the range table needs ranges in increasing order without overlap.
    assert!(U_ESCAPES.iter().all(|(first, last)| first <= last));
    assert!(
        U_ESCAPES.windows(2).all(|w| w[0].1 < w[1].0),
        "{U_ESCAPES:?}"
    );
}
