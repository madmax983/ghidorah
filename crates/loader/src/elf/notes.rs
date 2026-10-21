//! Notes of the `PT_NOTE` segments and the GNU build ID (design Section 4.3).
//!
//! A note has a 12-byte header: `namesz`, `descsz` and `type`. The name and the descriptor
//! start at multiples of the alignment. The alignment is 4 or 8 from `p_align`. A value
//! below 4 counts as 4. Any other value gives `E_BAD_ALIGN`, and the segment gives no notes.
//! Each step is at least 12 bytes, so the walk always advances.

use ghidorah_base::DiagCode;

use super::consts::{NOTE_HEADER, NT_GNU_BUILD_ID, PT_NOTE};
use super::view::{Cx, Fields};
use crate::binary::{Note, Segment, SegmentKind};
use crate::diag::Diagnostic;

/// Rounds `v` up to a multiple of `align`.
fn align_up(v: u64, align: u64) -> Option<u64> {
    let rest = v.checked_rem(align)?;
    if rest == 0 {
        Some(v)
    } else {
        v.checked_add(align.checked_sub(rest)?)
    }
}

/// Gives `len` bytes of `bytes` at `off`.
fn slice(bytes: &[u8], off: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(off).ok()?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    bytes.get(start..end)
}

/// Reads the notes of one segment.
fn walk(cx: &mut Cx<'_>, bytes: &[u8], align: u64, index: u32, out: &mut Vec<Note>) {
    let path = format!("elf.phdr[{index}].note");
    let limit = cx.budget.limits.notes_per_segment;
    let keep = cx.budget.limits.string_len;
    let end = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut off = 0u64;
    let mut count = 0u64;
    while off < end {
        if count >= limit {
            cx.diag(Diagnostic::new(DiagCode::Limit, path).have(limit));
            return;
        }
        let Some(head) = slice(bytes, off, NOTE_HEADER) else {
            cx.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(off)
                    .need(NOTE_HEADER),
            );
            return;
        };
        let mut f = Fields::new(head);
        let namesz = u64::from(f.u32());
        let descsz = u64::from(f.u32());
        let kind = f.u32();
        let name_at = off.saturating_add(NOTE_HEADER);
        let desc_at = name_at.checked_add(namesz).and_then(|v| align_up(v, align));
        let next = desc_at
            .and_then(|d| d.checked_add(descsz))
            .and_then(|v| align_up(v, align));
        let parts = desc_at.zip(next).and_then(|(d, _)| {
            let name = slice(bytes, name_at, namesz)?;
            let desc = slice(bytes, d, descsz)?;
            Some((name, desc))
        });
        let (Some((name, desc)), Some(next)) = (parts, next) else {
            cx.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(off)
                    .need(namesz.saturating_add(descsz))
                    .have(end.saturating_sub(off)),
            );
            return;
        };
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        let kept = desc
            .get(..usize::try_from(keep).unwrap_or(usize::MAX))
            .unwrap_or(desc);
        let cost = u64::try_from(
            size_of::<Note>()
                .saturating_add(name.len())
                .saturating_add(kept.len()),
        )
        .unwrap_or(u64::MAX);
        if !cx.budget.take_text(cost, &path, &mut cx.diags) {
            return;
        }
        out.push(Note {
            name: ghidorah_base::BinText::new(name),
            kind,
            desc: kept.to_vec(),
            desc_size: descsz,
        });
        count = count.saturating_add(1);
        off = next;
    }
}

/// Reads the notes of every `PT_NOTE` segment in header order.
pub(crate) fn load(cx: &mut Cx<'_>, segments: &[Segment]) -> Vec<Note> {
    let mut out = Vec::new();
    for s in segments
        .iter()
        .filter(|s| s.kind == SegmentKind::Elf(PT_NOTE))
    {
        let align = match s.align {
            0..=4 => 4,
            8 => 8,
            other => {
                cx.diag(
                    Diagnostic::new(DiagCode::BadAlign, format!("elf.phdr[{}].p_align", s.index))
                        .need(8)
                        .have(other),
                );
                continue;
            }
        };
        let path = format!("elf.phdr[{}]", s.index);
        if let Some(bytes) = cx.file_range(s.file_off, s.file_size, &path) {
            walk(cx, bytes, align, s.index, &mut out);
        }
    }
    out
}

/// Gives the GNU build ID in lower case hex.
pub(crate) fn build_id(notes: &[Note]) -> Option<String> {
    notes
        .iter()
        .find(|n| n.kind == NT_GNU_BUILD_ID && n.name.as_bytes() == b"GNU")
        .map(Note::desc_hex)
}
