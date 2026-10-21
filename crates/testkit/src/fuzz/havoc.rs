//! AFL-style havoc mutation.

use crate::rng::{Xoshiro256ss, below};

/// Interesting values for each word width.
const INTERESTING: [&[u64]; 4] = [
    &[0, 1, 0x10, 0x20, 0x40, 0x64, 0x7f, 0x80, 0xff],
    &[
        0, 0x80, 0xff, 0x100, 0x200, 0x400, 0x1000, 0x7fff, 0x8000, 0xffff,
    ],
    &[
        0,
        0xfffe,
        0xffff,
        0x1_0000,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_fffe,
        0xffff_ffff,
    ],
    &[
        0,
        0xffff_ffff,
        0x1_0000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        u64::MAX - 1,
        u64::MAX,
    ],
];

/// The word widths in bytes, in the order of [`INTERESTING`].
const WIDTHS: [usize; 4] = [1, 2, 4, 8];

/// Returns a random index in `0..n`. `n` must not be 0.
fn index(rng: &mut Xoshiro256ss, n: usize) -> usize {
    let n = u64::try_from(n).unwrap_or(u64::MAX);
    usize::try_from(below(rng, n)).unwrap_or(0)
}

/// Returns a random byte.
fn byte(rng: &mut Xoshiro256ss) -> u8 {
    u8::try_from(below(rng, 256)).unwrap_or(0)
}

/// Reads a word of `width` bytes at `pos`.
fn read_word(data: &[u8], pos: usize, width: usize, big: bool) -> Option<u64> {
    let bytes = data.get(pos..pos.checked_add(width)?)?;
    let fold = |acc: u64, &b: &u8| (acc << 8) | u64::from(b);
    Some(if big {
        bytes.iter().fold(0, fold)
    } else {
        bytes.iter().rev().fold(0, fold)
    })
}

/// Writes the low `width` bytes of `value` at `pos`, when the word fits.
fn write_word(data: &mut [u8], pos: usize, width: usize, value: u64, big: bool) {
    let Some(end) = pos.checked_add(width) else {
        return;
    };
    let Some(slot) = data.get_mut(pos..end) else {
        return;
    };
    let le = value.to_le_bytes();
    for (i, b) in slot.iter_mut().enumerate() {
        let k = if big { width - 1 - i } else { i };
        *b = le.get(k).copied().unwrap_or(0);
    }
}

/// Returns a random word position for `width` bytes, or `None` when the data is too short.
fn word_pos(rng: &mut Xoshiro256ss, len: usize, width: usize) -> Option<usize> {
    let room = len.checked_sub(width)?;
    Some(index(rng, room + 1))
}

/// Applies one havoc step.
fn step(rng: &mut Xoshiro256ss, data: &mut Vec<u8>, max_len: usize) {
    let kind = below(rng, 6);
    let len = data.len();
    match kind {
        0 if len > 0 => {
            let i = index(rng, len);
            let bit = below(rng, 8);
            if let Some(b) = data.get_mut(i) {
                *b ^= 1 << bit;
            }
        }
        1 if len > 0 => {
            let i = index(rng, len);
            let v = byte(rng);
            if let Some(b) = data.get_mut(i) {
                *b = v;
            }
        }
        2 | 3 => {
            let w = index(rng, WIDTHS.len());
            let width = WIDTHS[w];
            let big = below(rng, 2) == 1;
            let Some(pos) = word_pos(rng, len, width) else {
                return;
            };
            let value = if kind == 2 {
                let table = INTERESTING[w];
                table[index(rng, table.len())]
            } else {
                let delta = 1 + below(rng, 35);
                let old = read_word(data, pos, width, big).unwrap_or(0);
                if below(rng, 2) == 0 {
                    old.wrapping_add(delta)
                } else {
                    old.wrapping_sub(delta)
                }
            };
            write_word(data, pos, width, value, big);
        }
        4 if len > 1 => {
            let start = index(rng, len);
            let n = 1 + index(rng, (len - start).min(32));
            data.drain(start..start + n);
        }
        _ if len < max_len => {
            let pos = index(rng, len + 1);
            let v = byte(rng);
            data.insert(pos, v);
        }
        _ => {}
    }
}

/// Applies 2 to 16 havoc steps.
pub(super) fn mutate(rng: &mut Xoshiro256ss, input: &[u8], max_len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = input.iter().copied().take(max_len).collect();
    let steps = 1u32 << (1 + below(rng, 4));
    for _ in 0..steps {
        step(rng, &mut data, max_len);
    }
    data.truncate(max_len);
    data
}
