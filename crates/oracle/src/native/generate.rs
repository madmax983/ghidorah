//! The vector generator: seeded inputs, the input rules, one native run and the address
//! translation of the outputs.

use super::{FILL, Form, Kind, MEM, R, Rule, STATUS, State, VBASE, VIP, Vector};

/// The edge values of the leaf driver (`fixtures/src/leaf_driver.c`).
const EDGES: [u64; 27] = [
    0x0,
    0x1,
    0x2,
    0x3,
    0x7,
    0x8,
    0x10,
    0x1f,
    0x20,
    0x3f,
    0x40,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x7fff,
    0x8000,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
];

/// The `SplitMix64` stream.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Gives a value below `n`, or 0 when `n` is 0.
    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap_or(0)
    }

    /// Case `i`, input `k`: small values, edge values and full random values in turn.
    fn pick(&mut self, i: usize, k: usize) -> u64 {
        let r = self.next();
        match i.wrapping_add(k) % 4 {
            0 => r % 16,
            1 => EDGES
                .get(usize::try_from(r % 27).unwrap_or(0))
                .copied()
                .unwrap_or(0),
            2 => r % 1024,
            _ => r,
        }
    }
}

/// The FNV-1a hash of a name, the seed of its stream.
fn seed(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The value mask of a width in bits.
const fn mask(w: u8) -> u64 {
    if w >= 64 { u64::MAX } else { (1 << w) - 1 }
}

/// Gives the edge value of case `i` at the width `w` in bits. The cases 0 to 3 take 0, 1,
/// the sign bit and the all-ones mask. The data registers of these cases take that value
/// before the input rule. The table [`EDGES`] holds each of them for 8 to 64 bits.
fn width_edge(w: u16, i: usize) -> Option<u128> {
    let ones = u128::MAX.checked_shr(128u32.saturating_sub(u32::from(w)))?;
    let sign = 1u128.checked_shl(u32::from(w).checked_sub(1)?)?;
    [0, 1, sign, ones].get(i).copied()
}

/// Puts the edge value of case `i` in each data register of `values`: each register but
/// `pc`, the flags and `rsp`. The pointer registers take their buffer address after this.
fn put_edge(form: &Form, i: usize, values: &mut [u128]) {
    let Some(edge) = width_edge(form.w, i) else {
        return;
    };
    for (r, v) in form.regs.iter().zip(values) {
        if !matches!(r, R::Pc | R::Flags | R::Rsp) {
            *v = edge;
        }
    }
}

/// The inputs of one vector before the run.
struct Inputs {
    values: Vec<u128>,
    mem: [u8; MEM],
}

impl Inputs {
    fn index(form: &Form, r: R) -> Option<usize> {
        form.regs.iter().position(|x| *x == r)
    }

    fn get(&self, form: &Form, r: R) -> u64 {
        Self::index(form, r)
            .and_then(|i| self.values.get(i))
            .map_or(0, |v| u64::try_from(*v & u128::from(u64::MAX)).unwrap_or(0))
    }

    fn set(&mut self, form: &Form, r: R, v: u64) {
        if let Some(slot) = Self::index(form, r).and_then(|i| self.values.get_mut(i)) {
            *slot = u128::from(v);
        }
    }

    /// Replaces the low `w` bits of a register.
    fn set_low(&mut self, form: &Form, r: R, w: u8, low: u64) {
        let old = self.get(form, r);
        self.set(form, r, (old & !mask(w)) | (low & mask(w)));
    }
}

/// Applies the input rule of a form.
fn apply(form: &Form, rng: &mut Rng, case: usize, x: &mut Inputs) {
    match form.rule {
        Rule::Free => {}
        Rule::Div(w) | Rule::Idiv(w) => divide(form, rng, x, w),
        Rule::Count16 => {
            let count = x.get(form, R::Rcx);
            x.set(form, R::Rcx, (count & !31) | ((count & 31) % 17));
        }
        Rule::SmallRcx(n) => {
            let count = x.get(form, R::Rcx);
            x.set(form, R::Rcx, count % u64::from(n.max(1)));
        }
        Rule::Small(r, n) => {
            let value = x.get(form, r);
            x.set(form, r, value % u64::from(n.max(1)));
        }
        Rule::Equal(w) => {
            if case.is_multiple_of(2) {
                let acc = x.get(form, R::Rax);
                x.set_low(form, R::Rcx, w, acc);
            }
        }
        Rule::BitIndex => {
            let offset = i64::try_from(rng.below(512)).unwrap_or(0) - 128;
            let low = u64::from(u32::from_ne_bytes(
                i32::try_from(offset).unwrap_or(0).to_ne_bytes(),
            ));
            x.set_low(form, R::Rcx, 32, low);
        }
        Rule::PopfWord => {
            let at = form
                .ptrs
                .iter()
                .find(|p| p.0 == R::Rsp)
                .map_or(0, |p| usize::from(p.1));
            let word = (rng.next() & STATUS) | 2;
            if let Some(slot) = x.mem.get_mut(at..at + 8) {
                slot.copy_from_slice(&word.to_le_bytes());
            }
        }
        Rule::SameMem => {
            let count = rng.below(17);
            x.set(form, R::Rcx, count);
            let (first, second) = x.mem.split_at_mut(32);
            second[..16].copy_from_slice(&first[..16]);
            if !case.is_multiple_of(3)
                && let Some(byte) = second.get_mut(case % 16)
            {
                *byte ^= 0x5a;
            }
        }
    }
}

/// Makes a divide input that does not fault: a divisor that is not 0 and a quotient that
/// fits in the destination.
fn divide(form: &Form, rng: &mut Rng, x: &mut Inputs, w: u8) {
    let signed = matches!(form.rule, Rule::Idiv(_));
    let mut d = x.get(form, R::Rcx) & mask(w);
    if d == 0 {
        d = rng.below(mask(w)).max(1);
    }
    let low = x.get(form, R::Rax) & mask(w);
    let top = 1u64 << (w - 1);
    if signed && low == top && d == mask(w) {
        d = 1;
    }
    x.set_low(form, R::Rcx, w, d);
    let high = if signed {
        if low & top == 0 { 0 } else { mask(w) }
    } else {
        let h = if w == 8 {
            (x.get(form, R::Rax) >> 8) & 0xff
        } else {
            x.get(form, R::Rdx) & mask(w)
        };
        h % d
    };
    if w == 8 {
        let a = x.get(form, R::Rax);
        x.set(form, R::Rax, (a & !0xff00) | (high << 8));
    } else {
        x.set_low(form, R::Rdx, w, high);
    }
}

/// Gives the virtual address of a host address in the buffer, or the value itself.
fn virt(v: u64, buf: u64) -> u64 {
    match v.checked_sub(buf) {
        Some(off) if off <= MEM as u64 => VBASE + off,
        _ => v,
    }
}

/// Makes the vector of case `i`.
pub(super) fn vector(form: &Form, i: usize) -> Vector {
    let mut rng = Rng(seed(form.name).wrapping_add(u64::try_from(i).unwrap_or(0)));
    let mut x = Inputs {
        values: Vec::with_capacity(form.regs.len()),
        mem: [0; MEM],
    };
    for b in &mut x.mem {
        *b = rng.next().to_le_bytes()[0];
    }
    for (k, r) in form.regs.iter().enumerate() {
        let v = match r {
            R::Pc => u128::from(VIP),
            R::Flags => u128::from(rng.next() & STATUS),
            _ if r.xmm().is_some() => {
                (u128::from(rng.pick(i, k)) << 64) | u128::from(rng.pick(i, k + 1))
            }
            _ => u128::from(rng.pick(i, k)),
        };
        x.values.push(v);
    }
    put_edge(form, i, &mut x.values);
    for (r, off) in form.ptrs {
        x.set(form, *r, VBASE + u64::from(*off));
    }
    apply(form, &mut rng, i, &mut x);
    let mut s = Box::new(State::default());
    s.mem = x.mem;
    let buf = s.mem.as_ptr() as u64;
    for (n, slot) in s.gpr.iter_mut().enumerate() {
        *slot = FILL + n as u64;
    }
    s.gpr[4] = buf + MEM as u64 - 8;
    s.gpr[14] = 0;
    for (r, v) in form.regs.iter().zip(&x.values) {
        let low = u64::try_from(*v & u128::from(u64::MAX)).unwrap_or(0);
        if let Some(n) = r.gpr() {
            s.gpr[n] = low;
        } else if let Some(n) = r.xmm() {
            s.xmm[n] = [low, u64::try_from(*v >> 64).unwrap_or(0)];
        } else if *r == R::Flags {
            s.flags = low | 2;
        }
    }
    for (r, off) in form.ptrs {
        if let Some(n) = r.gpr() {
            s.gpr[n] = buf + u64::from(*off);
        }
    }
    // SAFETY: the state lives on the heap for the whole run. Each form touches only its
    // registers and the buffer of the state, and the harness restores the host registers.
    unsafe { (form.run)(std::ptr::from_mut(&mut *s)) };
    let len = form.bytes.len() as u64;
    let outputs = form
        .regs
        .iter()
        .map(|r| match r {
            R::Pc => match form.kind {
                Kind::Branch if s.gpr[14] == 0 => u128::from(VIP + len + 4),
                _ => u128::from(VIP + len),
            },
            R::Flags => u128::from(s.flags & STATUS),
            _ if r.xmm().is_some() => {
                let [lo, hi] = s.xmm[r.xmm().unwrap_or(0)];
                (u128::from(hi) << 64) | u128::from(lo)
            }
            _ => u128::from(virt(s.gpr[r.gpr().unwrap_or(0)], buf)),
        })
        .collect();
    let mut mem_out = s.mem;
    let size = usize::from(form.mem);
    match form.kind {
        Kind::Call => {
            // The pushed return address is the host address after the call.
            let host = s.gpr[14].wrapping_sub(7);
            let at = usize::try_from(s.gpr[4].wrapping_sub(buf)).unwrap_or(MEM);
            if let Some(slot) = mem_out.get_mut(at..at + 8)
                && slot == host.to_le_bytes()
            {
                slot.copy_from_slice(&(VIP + len).to_le_bytes());
            }
        }
        Kind::Ret => {
            // The harness wrote the host return address to `[rsp]`.
            let at = form
                .ptrs
                .iter()
                .find(|p| p.0 == R::Rsp)
                .map_or(0, |p| usize::from(p.1));
            if let (Some(slot), Some(old)) = (mem_out.get_mut(at..at + 8), x.mem.get(at..at + 8)) {
                slot.copy_from_slice(old);
            }
        }
        Kind::Plain | Kind::Branch => {}
    }
    Vector {
        inputs: x.values,
        outputs,
        mem_in: x.mem[..size].to_vec(),
        mem_out: mem_out[..size].to_vec(),
    }
}
