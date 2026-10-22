use super::{Class, MAX_CONVERSIONS, MAX_FORMAT, classes};

const I: Class = Class::Int;
const F: Class = Class::Float;

#[test]
fn format_classes() {
    let cases: [(&[u8], &[Class]); 14] = [
        (b"", &[]),
        (b"plain text\n", &[]),
        (b"%d %f\n", &[I, F]),
        (b"%f %d %f", &[F, I, F]),
        (b"%lld %lf %s %p %c %%", &[I, F, I, I, I]),
        (b"%-08.3e|%+g|% a|%#x", &[F, F, F, I]),
        (b"%*d %.*f", &[I, I, I, F]),
        (b"%hhu %zu %jd %td %qd %Zd", &[I, I, I, I, I, I]),
        (b"%m %n %ls %lc", &[I, I, I]),
        (b"%'d %I5d %10s", &[I, I, I]),
        (b"%E %F %G %A %X %o %i", &[F, F, F, F, I, I, I]),
        (b"%C %S", &[I, I]),
        (b"100%% sure: %u", &[I]),
        (b"%010.4f", &[F]),
    ];
    for (fmt, want) in cases {
        let text = String::from_utf8_lossy(fmt);
        assert_eq!(classes(fmt).as_deref(), Some(want), "{text}");
    }
}

#[test]
fn format_forms_with_no_order() {
    let long = vec![b'a'; MAX_FORMAT + 1];
    let many = "%d".repeat(MAX_CONVERSIONS + 1);
    let cases: [&[u8]; 8] = [
        b"%1$d %2$f",
        b"%*2$d",
        b"%Lf",
        b"%k",
        b"%",
        b"%5",
        &long,
        many.as_bytes(),
    ];
    for fmt in cases {
        let text = String::from_utf8_lossy(fmt);
        assert_eq!(classes(fmt), None, "{text}");
    }
    let max = "%d".repeat(MAX_CONVERSIONS);
    assert_eq!(
        classes(max.as_bytes()).map(|c| c.len()),
        Some(MAX_CONVERSIONS)
    );
}
