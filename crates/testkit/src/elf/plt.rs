//! PLT and GOT sections: `.plt`, `.plt.sec`, `.plt.got`, `.got.plt` and `.got`.

use super::plan::{Ctx, ImportPlan};
use super::write::{p32, p64, pi32, rel32, u32_of, u64_of, usize_of};
use super::{ElfBuilder, PltStyle};

/// The size of one PLT entry in `.plt` and `.plt.sec`.
pub(crate) const ENTRY: u64 = 16;

/// The number of reserved slots at the start of `.got.plt`, in bytes.
pub(crate) const GOT_PLT_RESERVED: u64 = 24;

/// Returns the size of one `.plt.got` stub.
pub(crate) const fn plt_got_stride(style: PltStyle) -> u64 {
    match style {
        PltStyle::Lazy => 8,
        PltStyle::Ibt => 16,
    }
}

/// Returns the GOT slot address of an import, or 0.
fn slot(ctx: &Ctx, name: &str) -> u64 {
    ctx.got.get(name).copied().unwrap_or(0)
}

/// Writes `.plt`: PLT0 and one lazy entry for each PLT import.
pub(crate) fn plt_bytes(b: &ElfBuilder, plan: &ImportPlan, ctx: &Ctx) -> Vec<u8> {
    let base = ctx.addr_of(".plt");
    let got = ctx.addr_of(".got.plt");
    let ibt = b.plt_style == PltStyle::Ibt;
    let mut out = vec![0xff, 0x35];
    pi32(&mut out, rel32(got + 8, base + 6));
    if ibt {
        out.extend_from_slice(&[0xf2, 0xff, 0x25]);
        pi32(&mut out, rel32(got + 16, base + 13));
        out.extend_from_slice(&[0x0f, 0x1f, 0x00]);
    } else {
        out.extend_from_slice(&[0xff, 0x25]);
        pi32(&mut out, rel32(got + 16, base + 12));
        out.extend_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
    }
    for (i, name) in plan.plt.iter().enumerate() {
        let entry = base + ENTRY * (u64_of(i) + 1);
        if ibt {
            out.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0x68]);
            p32(&mut out, u32_of(u64_of(i)));
            out.extend_from_slice(&[0xf2, 0xe9]);
            pi32(&mut out, rel32(base, entry + 15));
            out.push(0x90);
        } else {
            out.extend_from_slice(&[0xff, 0x25]);
            pi32(&mut out, rel32(slot(ctx, name), entry + 6));
            out.push(0x68);
            p32(&mut out, u32_of(u64_of(i)));
            out.push(0xe9);
            pi32(&mut out, rel32(base, entry + 16));
        }
    }
    out
}

/// Writes `.plt.sec`: one IBT stub for each PLT import.
pub(crate) fn plt_sec_bytes(plan: &ImportPlan, ctx: &Ctx) -> Vec<u8> {
    let base = ctx.addr_of(".plt.sec");
    let mut out = Vec::new();
    for (i, name) in plan.plt.iter().enumerate() {
        let stub = base + ENTRY * u64_of(i);
        out.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25]);
        pi32(&mut out, rel32(slot(ctx, name), stub + 11));
        out.extend_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]);
    }
    out
}

/// Writes `.plt.got`: one stub for each `PltGot` import.
pub(crate) fn plt_got_bytes(b: &ElfBuilder, plan: &ImportPlan, ctx: &Ctx) -> Vec<u8> {
    let base = ctx.addr_of(".plt.got");
    let stride = plt_got_stride(b.plt_style);
    let mut out = Vec::new();
    for (i, name) in plan.plt_got.iter().enumerate() {
        let stub = base + stride * u64_of(i);
        match b.plt_style {
            PltStyle::Lazy => {
                out.extend_from_slice(&[0xff, 0x25]);
                pi32(&mut out, rel32(slot(ctx, name), stub + 6));
                out.extend_from_slice(&[0x66, 0x90]);
            }
            PltStyle::Ibt => {
                out.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25]);
                pi32(&mut out, rel32(slot(ctx, name), stub + 10));
                out.extend_from_slice(&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]);
            }
        }
    }
    out
}

/// Writes `.got.plt`: three reserved slots, then one lazy slot for each PLT import.
pub(crate) fn got_plt_bytes(b: &ElfBuilder, plan: &ImportPlan, ctx: &Ctx) -> Vec<u8> {
    let plt = ctx.addr_of(".plt");
    let mut out = Vec::new();
    p64(&mut out, ctx.addr_of(".dynamic"));
    out.resize(usize_of(GOT_PLT_RESERVED), 0);
    for i in 0..plan.plt.len() {
        let entry = plt + ENTRY * (u64_of(i) + 1);
        let lazy = match b.plt_style {
            PltStyle::Lazy => entry + 6,
            PltStyle::Ibt => entry,
        };
        p64(&mut out, lazy);
    }
    out
}

/// Writes `.got`: one empty slot for each `Got` and `PltGot` import.
pub(crate) fn got_bytes(plan: &ImportPlan) -> Vec<u8> {
    vec![0u8; plan.got_slots.len() * 8]
}
