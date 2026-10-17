//! Tests of SHA-256 and FNV-1a (AC-043).

use ghidorah_base::sha256::{DIGEST_LEN, sha256_hex};
use ghidorah_base::{Fnv1a64, Sha256, fnv1a64, hex, sha256};

use crate::support::data_path;

/// The SHA-256 examples of FIPS 180-2 and the NIST test vectors.
const NIST: [(&[u8], &str); 4] = [
    (
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
];

/// The NIST digest of one million `a` bytes.
const MILLION_A: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

#[test]
fn ac_043_sha256_kat() {
    for (input, want) in NIST {
        assert_eq!(sha256_hex(input), want, "{:?}", String::from_utf8_lossy(input));
    }
    let mut hasher = Sha256::new();
    for _ in 0..1000 {
        hasher.update(&[b'a'; 1000]);
    }
    assert_eq!(hex::encode(&hasher.finalize()), MILLION_A);

    let path = data_path("sha256_lengths.txt");
    let table = std::fs::read_to_string(&path).unwrap();
    let mut rows = 0;
    for line in table.lines().filter(|l| !l.starts_with('#')) {
        let (n, want) = line.split_once(' ').unwrap();
        let n: usize = n.parse().unwrap();
        let message: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect();
        assert_eq!(sha256_hex(&message), want, "length {n}");
        rows += 1;
    }
    assert_eq!(rows, 201, "the table covers the lengths 0 to 200");
}

#[test]
fn sha256_streaming_split() {
    let message: Vec<u8> = (0..300u32).map(|i| u8::try_from(i % 256).unwrap()).collect();
    let whole = sha256(&message);
    // Python hashlib gives this digest for the bytes i % 256, i in 0..300.
    assert_eq!(
        hex::encode(&whole),
        "7728ae2f2c36e2aaafbe79ca14c87ae2f89e7c88c4390ecbbf82dce88706958d"
    );
    for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 299, 300] {
        let mut hasher = Sha256::default();
        hasher.update(&message[..split]);
        hasher.update(&message[split..]);
        assert_eq!(hasher.finalize(), whole, "split at {split}");
    }
    let mut bytewise = Sha256::new();
    for b in &message {
        bytewise.update(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finalize(), whole);
    assert_eq!(whole.len(), DIGEST_LEN);
}

#[test]
fn fnv1a64_vectors() {
    // The vectors of the FNV reference page.
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    let mut hasher = Fnv1a64::default();
    hasher.write(b"foo");
    hasher.write_u8(b'b');
    hasher.write(b"ar");
    assert_eq!(hasher.finish(), fnv1a64(b"foobar"));
}
