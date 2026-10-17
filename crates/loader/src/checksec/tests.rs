use ghidorah_base::BinText;

use super::x86_features;
use crate::binary::Note;

fn property(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out
}

fn note(name: &[u8], kind: u32, desc: Vec<u8>) -> Note {
    Note {
        name: BinText::new(name.to_vec()),
        kind,
        desc_size: u64::try_from(desc.len()).unwrap_or(0),
        desc,
    }
}

#[test]
fn property_walk() {
    // An ISA property first, then the feature property.
    let mut desc = property(0xc000_8002, &[1, 0, 0, 0]);
    desc.extend(property(0xc000_0002, &[3, 0, 0, 0]));
    assert_eq!(x86_features(&[note(b"GNU", 5, desc.clone())]), 3);
    // The bits of two notes add up.
    let a = note(b"GNU", 5, property(0xc000_0002, &[1, 0, 0, 0]));
    let b = note(b"GNU", 5, property(0xc000_0002, &[2, 0, 0, 0]));
    assert_eq!(x86_features(&[a, b]), 3);
    // Another owner, another type, a cut property and a short value give no bits.
    assert_eq!(x86_features(&[note(b"XYZ", 5, desc.clone())]), 0);
    assert_eq!(x86_features(&[note(b"GNU", 3, desc)]), 0);
    let mut cut = property(0xc000_0002, &[3, 0, 0, 0]);
    cut.truncate(10);
    assert_eq!(x86_features(&[note(b"GNU", 5, cut)]), 0);
    assert_eq!(
        x86_features(&[note(b"GNU", 5, property(0xc000_0002, &[3, 0]))]),
        0
    );
    // A size past the descriptor stops the walk.
    let mut huge = 0xc000_0002u32.to_le_bytes().to_vec();
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(x86_features(&[note(b"GNU", 5, huge)]), 0);
}
