//! TLS callbacks (design Section 4.13).
//!
//! The TLS directory of PE32+ has 40 bytes. `AddressOfCallBacks` at offset 24 is the VA of an
//! array of callback VAs that ends with 0. Each callback is an entry point of kind
//! `TlsCallback`. Above the TLS callback limit (256), the loader keeps the first callbacks and
//! gives `E_LIMIT`.

use ghidorah_base::DiagCode;

use super::Px;
use crate::binary::{Entry, EntryKind};
use crate::diag::Diagnostic;

/// Reads the TLS directory at `rva` and gives the callback entry points.
pub(crate) fn load(px: &mut Px<'_>, rva: u32) -> Vec<Entry> {
    let path = "pe.tls";
    let Some(array_va) = rva
        .checked_add(24)
        .and_then(|at| px.u64_at(at, "pe.tls.AddressOfCallBacks"))
    else {
        return Vec::new();
    };
    if array_va == 0 {
        return Vec::new();
    }
    let Some(array) = px.rva_of(array_va) else {
        px.diag(
            Diagnostic::new(DiagCode::Overflow, "pe.tls.AddressOfCallBacks")
                .at(array_va)
                .need(px.base),
        );
        return Vec::new();
    };
    let limit = px.budget.limits.pe_tls_callbacks;
    let mut out = Vec::new();
    let mut i = 0u64;
    while let Some(at) = u32::try_from(i.saturating_mul(8))
        .ok()
        .and_then(|o| array.checked_add(o))
    {
        let Some(va) = px.u64_at(at, path) else {
            break;
        };
        if va == 0 {
            break;
        }
        if i >= limit {
            px.diag(
                Diagnostic::new(DiagCode::Limit, path)
                    .need(i.saturating_add(1))
                    .have(limit),
            );
            break;
        }
        out.push(Entry {
            addr: va,
            kind: EntryKind::TlsCallback,
        });
        i = i.saturating_add(1);
    }
    out
}
