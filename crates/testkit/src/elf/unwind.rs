//! Unwind sections: `.eh_frame` and `.eh_frame_hdr`.

use super::Fde;
use super::plan::Ctx;
use super::write::{p32, pi32, rel32, u32_of, u64_of};

/// The `DW_EH_PE_pcrel | DW_EH_PE_sdata4` encoding of the FDE pointers.
const PCREL_SDATA4: u8 = 0x1b;

/// Fills `buf` with `DW_CFA_nop` until `4 + len` is a multiple of 8.
fn pad_entry(buf: &mut Vec<u8>, start: usize) {
    let used = buf.len() - start;
    let total = (used + 4).div_ceil(8) * 8;
    buf.resize(start + total - 4, 0);
}

/// Writes the CIE: version 1, augmentation `zR`, the x86-64 initial rows.
fn cie() -> Vec<u8> {
    let mut out = Vec::new();
    p32(&mut out, 0);
    out.push(1);
    out.extend_from_slice(b"zR\0");
    out.extend_from_slice(&[1, 0x78, 16, 1, PCREL_SDATA4]);
    out.extend_from_slice(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
    pad_entry(&mut out, 0);
    out
}

/// Writes `.eh_frame` and returns the section offset of each FDE.
pub(crate) fn eh_frame(fdes: &[Fde], ctx: &Ctx) -> (Vec<u8>, Vec<u64>) {
    let base = ctx.addr_of(".eh_frame");
    let mut out = Vec::new();
    let cie = cie();
    p32(&mut out, u32_of(u64_of(cie.len())));
    out.extend_from_slice(&cie);
    let mut starts = Vec::new();
    for fde in fdes {
        let start = out.len();
        starts.push(u64_of(start));
        let field = base + u64_of(start) + 8;
        let mut body = Vec::new();
        p32(&mut body, u32_of(u64_of(start) + 4));
        pi32(&mut body, rel32(ctx.resolve(&fde.at), field));
        p32(&mut body, u32_of(fde.len));
        body.push(0);
        body.extend_from_slice(&fde.program);
        pad_entry(&mut body, 0);
        p32(&mut out, u32_of(u64_of(body.len())));
        out.extend_from_slice(&body);
    }
    p32(&mut out, 0);
    (out, starts)
}

/// Writes `.eh_frame_hdr` with the sorted FDE table.
pub(crate) fn eh_frame_hdr(fdes: &[Fde], ctx: &Ctx) -> Vec<u8> {
    let hdr = ctx.addr_of(".eh_frame_hdr");
    let frame = ctx.addr_of(".eh_frame");
    let (_, starts) = eh_frame(fdes, ctx);
    let mut out = vec![1, PCREL_SDATA4, 0x03, 0x3b];
    pi32(&mut out, rel32(frame, hdr + 4));
    p32(&mut out, u32_of(u64_of(fdes.len())));
    let mut table: Vec<(u64, u64)> = fdes
        .iter()
        .zip(&starts)
        .map(|(fde, start)| (ctx.resolve(&fde.at), frame + start))
        .collect();
    table.sort_unstable();
    for (pc, fde) in table {
        pi32(&mut out, rel32(pc, hdr));
        pi32(&mut out, rel32(fde, hdr));
    }
    out
}
