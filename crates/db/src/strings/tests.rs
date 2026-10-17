use ghidorah_base::Range;

use super::{Encoding, StrInfo, Strings};

fn info(len: u32) -> StrInfo {
    StrInfo {
        encoding: Encoding::Ascii,
        len,
        referenced: true,
    }
}

#[test]
fn insert_query_and_remove() {
    let mut s = Strings::default();
    assert_eq!(s.insert(0x2010, info(5)), None);
    assert_eq!(s.insert(0x2010, info(6)), Some(info(5)));
    s.insert(0x2000, info(4));
    s.insert(u64::MAX, info(4));
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
    assert_eq!(s.get(0x2010), Some(&info(6)));
    let got: Vec<u64> = s
        .in_range(Range {
            first: 0x2000,
            last: 0x2010,
        })
        .map(|(a, _)| a)
        .collect();
    assert_eq!(got, [0x2000, 0x2010]);
    assert_eq!(
        s.in_range(Range {
            first: 0x2011,
            last: u64::MAX
        })
        .count(),
        1
    );
    assert_eq!(s.iter().count(), 3);
    assert_eq!(s.remove(0x2000), Some(info(4)));
    assert_eq!(s.remove(0x2000), None);
}

#[test]
fn encoding_names() {
    let names: Vec<String> = [Encoding::Ascii, Encoding::Utf8, Encoding::Utf16Le]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(names, ["ascii", "utf8", "utf16le"]);
}
