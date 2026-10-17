//! K1 tier-1 tests: boundaries, values and a model test (AC-028, AC-038).

use ghidorah_kernel::{Endian, ReadError, Reader};
use ghidorah_testkit::pbt::{Gen, check};

/// Encodes `v` as unsigned LEB128.
fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = u8::try_from(v & 0x7f).unwrap_or(0);
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Encodes `v` as signed LEB128.
fn sleb(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = u8::try_from(v & 0x7f).unwrap_or(0);
        v >>= 7;
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

#[test]
fn k1_reader_boundaries() {
    // Empty buffer: every read fails and the position stays at 0.
    let mut r = Reader::new(&[], Endian::Little);
    assert_eq!(r.remaining(), 0);
    assert_eq!(r.u8(), Err(ReadError::Eof));
    assert_eq!(r.u16(), Err(ReadError::Eof));
    assert_eq!(r.u32(), Err(ReadError::Eof));
    assert_eq!(r.u64(), Err(ReadError::Eof));
    assert_eq!(r.uleb128(), Err(ReadError::Eof));
    assert_eq!(r.sleb128(), Err(ReadError::Eof));
    assert_eq!(r.cstr(16), Err(ReadError::NoNul));
    assert_eq!(r.take(0), Ok(&[][..]));
    assert_eq!(r.take(1), Err(ReadError::Eof));
    assert_eq!(r.skip(0), Ok(()));
    assert_eq!(r.skip(1), Err(ReadError::Eof));
    assert_eq!(r.seek(0), Ok(()));
    assert_eq!(r.seek(1), Err(ReadError::Eof));
    assert_eq!(r.pos(), 0);

    // Seek to the end: reads fail, `take(0)` works, and the position stays.
    let data = [1u8, 2, 3, 4, 5];
    let mut r = Reader::new(&data, Endian::Big);
    assert_eq!(r.seek(5), Ok(()));
    assert_eq!(r.pos(), 5);
    assert_eq!(r.remaining(), 0);
    assert_eq!(r.rest(), &[] as &[u8]);
    assert_eq!(r.u8(), Err(ReadError::Eof));
    assert_eq!(r.take(0), Ok(&[][..]));
    assert_eq!(r.seek(6), Err(ReadError::Eof));
    assert_eq!(r.seek(usize::MAX), Err(ReadError::Eof));
    assert_eq!(r.pos(), 5);
    assert_eq!(r.seek(1), Ok(()));
    assert_eq!(r.rest(), &[2, 3, 4, 5]);
    assert_eq!(r.u32(), Ok(0x0203_0405));
    assert_eq!(r.u16(), Err(ReadError::Eof));
    assert_eq!(r.pos(), 5);

    // A partial read fails and keeps the position.
    let mut r = Reader::new(&data, Endian::Little);
    assert_eq!(r.skip(2), Ok(()));
    assert_eq!(r.u64(), Err(ReadError::Eof));
    assert_eq!(r.take(4), Err(ReadError::Eof));
    assert_eq!(r.skip(usize::MAX), Err(ReadError::Eof));
    assert_eq!(r.take(usize::MAX), Err(ReadError::Eof));
    assert_eq!(r.pos(), 2);
    assert_eq!(r.take(3), Ok(&[3, 4, 5][..]));
    assert_eq!(r.endian(), Endian::Little);

    // 10-byte ULEB: the 10th byte can only be 0 or 1.
    let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    assert_eq!(Reader::new(&max, Endian::Little).uleb128(), Ok(u64::MAX));
    let mut pad = [0x80u8; 10];
    pad[9] = 0x00;
    let mut r = Reader::new(&pad, Endian::Little);
    assert_eq!(r.uleb128(), Ok(0));
    assert_eq!(r.pos(), 10);
    for tenth in [0x02u8, 0x7f, 0x80, 0x81, 0xff] {
        let mut bad = max;
        bad[9] = tenth;
        let mut r = Reader::new(&bad, Endian::Little);
        assert_eq!(r.uleb128(), Err(ReadError::BadLeb), "10th byte {tenth:#x}");
        assert_eq!(r.pos(), 0);
    }
    let long = [0x80u8; 11];
    assert_eq!(
        Reader::new(&long, Endian::Little).uleb128(),
        Err(ReadError::BadLeb)
    );
    assert_eq!(
        Reader::new(&long[..9], Endian::Little).uleb128(),
        Err(ReadError::Eof)
    );

    // 10-byte SLEB: the 10th byte can only be 0x00 or 0x7f.
    let min = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
    assert_eq!(Reader::new(&min, Endian::Little).sleb128(), Ok(i64::MIN));
    let top = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
    assert_eq!(Reader::new(&top, Endian::Little).sleb128(), Ok(i64::MAX));
    for tenth in [0x01u8, 0x40, 0x7e, 0x80, 0xff] {
        let mut bad = min;
        bad[9] = tenth;
        let mut r = Reader::new(&bad, Endian::Little);
        assert_eq!(r.sleb128(), Err(ReadError::BadLeb), "10th byte {tenth:#x}");
        assert_eq!(r.pos(), 0);
    }
}

#[test]
fn k1_fixed_width_values() {
    check("k1_fixed_width_values", 2_000, |g: &mut Gen| {
        let data = g.bytes(20);
        let big = g.bool();
        let endian = if big { Endian::Big } else { Endian::Little };
        let mut r = Reader::new(&data, endian);
        let mut at = 0usize;
        while at < data.len() {
            let width = *g.pick(&[1usize, 2, 4, 8]).unwrap_or(&1);
            let Some(bytes) = data.get(at..at + width) else {
                return Ok(());
            };
            let got = match width {
                1 => r.u8().map(u64::from),
                2 => r.u16().map(u64::from),
                4 => r.u32().map(u64::from),
                _ => r.u64(),
            };
            let mut buf = [0u8; 8];
            if big {
                buf[8 - width..].copy_from_slice(bytes);
            } else {
                buf[..width].copy_from_slice(bytes);
            }
            let want = if big {
                u64::from_be_bytes(buf)
            } else {
                u64::from_le_bytes(buf)
            };
            if got != Ok(want) {
                return Err(format!("width {width} at {at}: {got:?} != {want:#x}"));
            }
            at += width;
            if r.pos() != at {
                return Err(format!("pos {} != {at}", r.pos()));
            }
        }
        Ok(())
    });
}

#[test]
fn k1_leb_known_vectors() {
    let unsigned: &[(&[u8], u64)] = &[
        (&[0x02], 2),
        (&[0x7f], 127),
        (&[0x80, 0x01], 128),
        (&[0x81, 0x01], 129),
        (&[0x82, 0x01], 130),
        (&[0xb9, 0x64], 12_857),
        (&[0xe5, 0x8e, 0x26], 624_485),
    ];
    for (bytes, want) in unsigned {
        let mut r = Reader::new(bytes, Endian::Little);
        assert_eq!(r.uleb128(), Ok(*want), "{bytes:x?}");
        assert_eq!(r.pos(), bytes.len());
    }
    let signed: &[(&[u8], i64)] = &[
        (&[0x02], 2),
        (&[0x7e], -2),
        (&[0xff, 0x00], 127),
        (&[0x81, 0x7f], -127),
        (&[0x80, 0x01], 128),
        (&[0x80, 0x7f], -128),
        (&[0x81, 0x01], 129),
        (&[0xff, 0x7e], -129),
        (&[0xc0, 0xbb, 0x78], -123_456),
    ];
    for (bytes, want) in signed {
        let mut r = Reader::new(bytes, Endian::Little);
        assert_eq!(r.sleb128(), Ok(*want), "{bytes:x?}");
        assert_eq!(r.pos(), bytes.len());
    }
}

#[test]
fn k1_leb_round_trip() {
    check("k1_leb_round_trip", 2_000, |g: &mut Gen| {
        let u = g.u64();
        let i = g.u64().cast_signed();
        let mut data = uleb(u);
        data.extend(sleb(i));
        let mut r = Reader::new(&data, Endian::Big);
        let got = (r.uleb128(), r.sleb128(), r.pos());
        if got == (Ok(u), Ok(i), data.len()) {
            Ok(())
        } else {
            Err(format!("{u:#x} {i:#x}: {got:?}"))
        }
    });
}

#[test]
fn k1_cstr_cases() {
    let data = b"ab\0\0xyz";
    let mut r = Reader::new(data, Endian::Little);
    assert_eq!(r.cstr(1), Err(ReadError::NoNul));
    assert_eq!(r.pos(), 0);
    assert_eq!(r.cstr(2), Ok(&b"ab"[..]));
    assert_eq!(r.pos(), 3);
    assert_eq!(r.cstr(0), Ok(&b""[..]));
    assert_eq!(r.pos(), 4);
    assert_eq!(r.cstr(usize::MAX), Err(ReadError::NoNul));
    assert_eq!(r.pos(), 4);
    assert_eq!(r.take(3), Ok(&b"xyz"[..]));
}

/// One reader operation of the model test.
#[derive(Debug, Clone, Copy)]
enum Op {
    U8,
    U16,
    U32,
    U64,
    Uleb,
    Sleb,
    Cstr(usize),
    Take(usize),
    Skip(usize),
    Seek(usize),
    Rest,
}

/// The observation of one operation: the result bytes or value, and the position after it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Value(Result<u64, ReadError>),
    Bytes(Result<Vec<u8>, ReadError>),
}

/// A plain model of the reader over `get` calls.
struct Model {
    data: Vec<u8>,
    pos: usize,
    big: bool,
}

impl Model {
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, ReadError> {
        let end = self.pos.checked_add(n).ok_or(ReadError::Eof)?;
        let out = self.data.get(self.pos..end).ok_or(ReadError::Eof)?.to_vec();
        self.pos = end;
        Ok(out)
    }

    fn int(&mut self, n: usize) -> Result<u64, ReadError> {
        let bytes = self.bytes(n)?;
        Ok(if self.big {
            bytes.iter().fold(0, |v, &b| (v << 8) | u64::from(b))
        } else {
            bytes.iter().rev().fold(0, |v, &b| (v << 8) | u64::from(b))
        })
    }

    /// Reads LEB128 bytes. Gives the bits, the byte count and the last byte.
    fn leb(&self) -> Result<(u64, usize, u8), ReadError> {
        let mut value = 0u64;
        for k in 0..10 {
            let b = *self.data.get(self.pos + k).ok_or(ReadError::Eof)?;
            let shift = u32::try_from(7 * k).unwrap_or(u32::MAX);
            value |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
            if b & 0x80 == 0 {
                return Ok((value, k + 1, b));
            }
        }
        Err(ReadError::BadLeb)
    }

    fn apply(&mut self, op: Op) -> Seen {
        match op {
            Op::U8 => Seen::Value(self.int(1)),
            Op::U16 => Seen::Value(self.int(2)),
            Op::U32 => Seen::Value(self.int(4)),
            Op::U64 => Seen::Value(self.int(8)),
            Op::Uleb => Seen::Value(self.leb().and_then(|(v, n, last)| {
                if n == 10 && last > 1 {
                    return Err(ReadError::BadLeb);
                }
                self.pos += n;
                Ok(v)
            })),
            Op::Sleb => Seen::Value(self.leb().and_then(|(v, n, last)| {
                if n == 10 && last != 0 && last != 0x7f {
                    return Err(ReadError::BadLeb);
                }
                self.pos += n;
                let shift = u32::try_from(7 * n).unwrap_or(u32::MAX);
                let v = if shift < 64 && last & 0x40 != 0 {
                    v | (u64::MAX << shift)
                } else {
                    v
                };
                Ok(v)
            })),
            Op::Cstr(max) => {
                let rest = self.data.get(self.pos..).unwrap_or_default();
                let nul = rest
                    .iter()
                    .take(max.saturating_add(1))
                    .position(|&b| b == 0);
                Seen::Bytes(nul.ok_or(ReadError::NoNul).map(|n| {
                    let s = rest[..n].to_vec();
                    self.pos += n + 1;
                    s
                }))
            }
            Op::Take(n) => Seen::Bytes(self.bytes(n)),
            Op::Skip(n) => Seen::Bytes(self.bytes(n).map(|_| Vec::new())),
            Op::Seek(off) => Seen::Bytes(if off <= self.data.len() {
                self.pos = off;
                Ok(Vec::new())
            } else {
                Err(ReadError::Eof)
            }),
            Op::Rest => Seen::Bytes(Ok(self.data.get(self.pos..).unwrap_or_default().to_vec())),
        }
    }
}

fn apply(r: &mut Reader<'_>, op: Op) -> Seen {
    match op {
        Op::U8 => Seen::Value(r.u8().map(u64::from)),
        Op::U16 => Seen::Value(r.u16().map(u64::from)),
        Op::U32 => Seen::Value(r.u32().map(u64::from)),
        Op::U64 => Seen::Value(r.u64()),
        Op::Uleb => Seen::Value(r.uleb128()),
        Op::Sleb => Seen::Value(r.sleb128().map(i64::cast_unsigned)),
        Op::Cstr(max) => Seen::Bytes(r.cstr(max).map(<[u8]>::to_vec)),
        Op::Take(n) => Seen::Bytes(r.take(n).map(<[u8]>::to_vec)),
        Op::Skip(n) => Seen::Bytes(r.skip(n).map(|()| Vec::new())),
        Op::Seek(off) => Seen::Bytes(r.seek(off).map(|()| Vec::new())),
        Op::Rest => Seen::Bytes(Ok(r.rest().to_vec())),
    }
}

fn gen_len(g: &mut Gen) -> usize {
    match g.draw(8) {
        0 => usize::MAX,
        1 => usize::MAX - usize::try_from(g.draw(4)).unwrap_or(0),
        _ => usize::try_from(g.draw(40)).unwrap_or(0),
    }
}

fn gen_op(g: &mut Gen) -> Op {
    match g.draw(11) {
        0 => Op::U8,
        1 => Op::U16,
        2 => Op::U32,
        3 => Op::U64,
        4 => Op::Uleb,
        5 => Op::Sleb,
        6 => Op::Cstr(gen_len(g)),
        7 => Op::Take(gen_len(g)),
        8 => Op::Skip(gen_len(g)),
        9 => Op::Seek(gen_len(g)),
        _ => Op::Rest,
    }
}

/// Gives a buffer with LEB128-like bytes: many bytes have the continuation bit.
fn gen_data(g: &mut Gen) -> Vec<u8> {
    g.vec(48, |g| match g.draw(4) {
        0 => 0x80 | g.u8(),
        1 => *g.pick(&[0x00, 0x01, 0x7f, 0x40]).unwrap_or(&0),
        _ => g.u8(),
    })
}

#[test]
fn ac_038_reader_props() {
    // The reader matches a model of `get` calls, so it never reads outside its buffer.
    // A panic fails the case, so the reader never panics.
    check("ac_038_reader_props", 3_000, |g: &mut Gen| {
        let data = gen_data(g);
        let big = g.bool();
        let endian = if big { Endian::Big } else { Endian::Little };
        let mut r = Reader::new(&data, endian);
        let mut model = Model {
            data: data.clone(),
            pos: 0,
            big,
        };
        let mut ops = Vec::new();
        while ops.len() < 24 && g.more() {
            let op = gen_op(g);
            ops.push(op);
            let before = r.pos();
            let got = apply(&mut r, op);
            let want = model.apply(op);
            if got != want || r.pos() != model.pos {
                return Err(format!(
                    "ops {ops:?}: {got:?} at {} != {want:?} at {}",
                    r.pos(),
                    model.pos
                ));
            }
            if seen_failed(&got) && r.pos() != before {
                return Err(format!("ops {ops:?}: a failed read moved the position"));
            }
            if r.pos() > data.len() || r.remaining() != data.len() - r.pos() {
                return Err(format!("ops {ops:?}: the position left the buffer"));
            }
        }
        Ok(())
    });

    // The 10th byte rule over every 10th byte value.
    for tenth in 0..=255u8 {
        let mut bytes = [0x80u8; 10];
        bytes[9] = tenth;
        let u = Reader::new(&bytes, Endian::Little).uleb128();
        assert_eq!(u.is_ok(), tenth <= 1, "uleb 10th byte {tenth:#x}");
        let s = Reader::new(&bytes, Endian::Little).sleb128();
        assert_eq!(
            s.is_ok(),
            tenth == 0 || tenth == 0x7f,
            "sleb 10th byte {tenth:#x}"
        );
    }
}

fn seen_failed(seen: &Seen) -> bool {
    matches!(seen, Seen::Value(Err(_)) | Seen::Bytes(Err(_)))
}

#[test]
fn k1_read_error_display() {
    let errors = [ReadError::Eof, ReadError::BadLeb, ReadError::NoNul];
    let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(
        texts,
        [
            "the data ends before the end of the read",
            "the LEB128 value is not valid",
            "the C string has no NUL byte in its limit",
        ]
    );
    let boxed: Box<dyn std::error::Error> = Box::new(ReadError::Eof);
    assert!(boxed.source().is_none());
}
