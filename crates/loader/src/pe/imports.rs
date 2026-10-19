//! Imports, delay imports and the IAT symbols (design Section 4.11).
//!
//! | Table | Rule |
//! |---|---|
//! | import descriptors (20 bytes) | end at an all-zero entry; the directory size does not count |
//! | ILT and IAT entries (8 bytes) | bit 63 set: an ordinal in the low 16 bits; else the RVA of a hint-name entry |
//! | `OriginalFirstThunk` 0 | the IAT holds the lookup entries |
//! | delay descriptors (32 bytes) | `Attributes` bit 0 set: RVAs; clear (VC6): VAs, less `ImageBase` |
//!
//! Each import gets `slot`: the VA of its IAT entry, or of its delay IAT entry. Each slot gets
//! the symbol `__imp_<name>`, or `__imp_<dll>!#<ordinal>` for an import by ordinal (table
//! `Iat`). `libraries` lists the DLLs in descriptor order, the delay DLLs last.

use ghidorah_base::{BinText, DiagCode};

use super::Px;
use crate::binary::{Binary, Import, Sym, SymBind, SymKind, SymTable, SymVis};
use crate::diag::Diagnostic;

/// Bit 63 of a lookup entry: an import by ordinal.
const BY_ORDINAL: u64 = 1 << 63;

/// The bits of a hint-name RVA in a lookup entry.
const NAME_RVA: u64 = 0x7fff_ffff;

/// One lookup entry: an ordinal, or a hint and a name.
enum Lookup {
    Ordinal(u16),
    Name(u16, BinText),
}

/// The tables of one DLL: its name, the lookup table and the address table.
struct Tables {
    dll: BinText,
    lookup: u32,
    iat: u32,
    delay: bool,
    /// The VA form of VC6: the lookup entries hold VAs.
    va_form: bool,
}

/// Reads the lookup entry `value` of `path`.
fn lookup(px: &mut Px<'_>, value: u64, va_form: bool, path: &str) -> Option<Lookup> {
    if value & BY_ORDINAL != 0 {
        return Some(Lookup::Ordinal(u16::try_from(value & 0xffff).unwrap_or(0)));
    }
    let rva = if va_form {
        let Some(rva) = value
            .checked_sub(px.base)
            .and_then(|r| u32::try_from(r).ok())
        else {
            px.diag(
                Diagnostic::new(DiagCode::Overflow, path)
                    .at(value)
                    .need(px.base),
            );
            return None;
        };
        rva
    } else {
        u32::try_from(value & NAME_RVA).unwrap_or(0)
    };
    let hint = px.u16_at(rva, path)?;
    let name = px.cstr(rva.checked_add(2)?, path)?;
    Some(Lookup::Name(hint, name))
}

/// Reads the imports of one DLL into `b`.
fn walk(px: &mut Px<'_>, t: &Tables, at: usize, kind: &str, b: &mut Binary) {
    let limit = px.budget.limits.pe_imports_per_dll;
    let mut count = 0u64;
    loop {
        let path = format!("pe.{kind}[{at}].ilt[{count}]");
        let Some(off) = u32::try_from(count.saturating_mul(8)).ok() else {
            break;
        };
        let (Some(entry_rva), Some(slot_rva)) = (t.lookup.checked_add(off), t.iat.checked_add(off))
        else {
            px.diag(Diagnostic::new(DiagCode::Overflow, path));
            break;
        };
        let Some(value) = px.u64_at(entry_rva, &path) else {
            break;
        };
        if value == 0 {
            break;
        }
        if count >= limit {
            px.diag(Diagnostic::new(DiagCode::Limit, path).have(limit));
            break;
        }
        count = count.saturating_add(1);
        let Some(entry) = lookup(px, value, t.va_form, &path) else {
            continue;
        };
        let slot = px.va(slot_rva, &path);
        add(px, t, entry, slot, b);
    }
}

/// Adds one import and the symbol of its slot.
fn add(px: &mut Px<'_>, t: &Tables, entry: Lookup, slot: Option<u64>, b: &mut Binary) {
    let (name, ordinal, hint) = match entry {
        Lookup::Ordinal(o) => (None, Some(o), None),
        Lookup::Name(h, n) => (Some(n), None, Some(h)),
    };
    let label = match (&name, ordinal) {
        (Some(n), _) => [b"__imp_".as_slice(), n.as_bytes()].concat(),
        (None, o) => {
            let dll = t.dll.as_bytes().to_ascii_lowercase();
            let tail = format!("!#{}", o.unwrap_or(0));
            [b"__imp_".as_slice(), &dll, tail.as_bytes()].concat()
        }
    };
    if let Some(addr) = slot {
        let size = u64::try_from(label.len()).unwrap_or(u64::MAX);
        if px.budget.take_text(size, "pe.iat", &mut px.diags) {
            let index = u32::try_from(b.symbols.len()).unwrap_or(u32::MAX);
            b.symbols.push(Sym {
                index,
                name: BinText::new(label),
                version: None,
                addr,
                size: 8,
                kind: SymKind::Object,
                bind: SymBind::Global,
                vis: SymVis::Default,
                shndx: 0,
                table: SymTable::Iat,
            });
        }
    }
    b.imports.push(Import {
        lib: Some(t.dll.clone()),
        name,
        ordinal,
        hint,
        slot,
        stub: None,
        reloc_kind: None,
        delay: t.delay,
    });
}

/// Reads the import descriptors at `rva` into `b`.
pub(crate) fn load(px: &mut Px<'_>, rva: u32, b: &mut Binary) {
    let limit = px.budget.limits.pe_import_dlls;
    for i in 0.. {
        let path = format!("pe.import[{i}]");
        let Some(at) = u32::try_from(i)
            .ok()
            .and_then(|n| n.checked_mul(20))
            .and_then(|o| rva.checked_add(o))
        else {
            px.diag(Diagnostic::new(DiagCode::Overflow, path));
            break;
        };
        let Some(raw) = px.read(at, 20, &path) else {
            break;
        };
        if raw.iter().all(|b| *b == 0) {
            break;
        }
        if u64::try_from(i).unwrap_or(u64::MAX) >= limit {
            px.diag(Diagnostic::new(DiagCode::Limit, path).have(limit));
            break;
        }
        let word = |k: usize| -> u32 {
            raw.get(k..k.saturating_add(4))
                .and_then(|w| <[u8; 4]>::try_from(w).ok())
                .map_or(0, u32::from_le_bytes)
        };
        let (ilt, name_rva, iat) = (word(0), word(12), word(16));
        let Some(dll) = px.cstr(name_rva, &path) else {
            continue;
        };
        b.libraries.push(dll.clone());
        let tables = Tables {
            dll,
            lookup: if ilt == 0 { iat } else { ilt },
            iat,
            delay: false,
            va_form: false,
        };
        walk(px, &tables, i, "import", b);
    }
}

/// Gives the RVA of a delay descriptor field: the value, or the value less `ImageBase` in the
/// VA form. A VA below `ImageBase` gives `E_OVERFLOW` and `None`.
fn delay_rva(px: &mut Px<'_>, value: u32, va_form: bool, path: &str) -> Option<u32> {
    if !va_form {
        return Some(value);
    }
    let rva = px.rva_of(u64::from(value));
    if rva.is_none() {
        px.diag(
            Diagnostic::new(DiagCode::Overflow, path)
                .at(u64::from(value))
                .need(px.base)
                .hint("a VC6 delay descriptor holds a VA below the image base"),
        );
    }
    rva
}

/// Reads the delay import descriptors at `rva` into `b`.
pub(crate) fn load_delay(px: &mut Px<'_>, rva: u32, b: &mut Binary) {
    let limit = px.budget.limits.pe_import_dlls;
    for i in 0.. {
        let path = format!("pe.delay[{i}]");
        let Some(at) = u32::try_from(i)
            .ok()
            .and_then(|n| n.checked_mul(32))
            .and_then(|o| rva.checked_add(o))
        else {
            px.diag(Diagnostic::new(DiagCode::Overflow, path));
            break;
        };
        let Some(raw) = px.read(at, 32, &path) else {
            break;
        };
        if raw.iter().all(|b| *b == 0) {
            break;
        }
        if u64::try_from(i).unwrap_or(u64::MAX) >= limit {
            px.diag(Diagnostic::new(DiagCode::Limit, path).have(limit));
            break;
        }
        let word = |k: usize| -> u32 {
            raw.get(k..k.saturating_add(4))
                .and_then(|w| <[u8; 4]>::try_from(w).ok())
                .map_or(0, u32::from_le_bytes)
        };
        let va_form = word(0) & 1 == 0;
        let (name, iat, int) = (word(4), word(12), word(16));
        let fields = (
            delay_rva(px, name, va_form, &path),
            delay_rva(px, iat, va_form, &path),
            delay_rva(px, int, va_form, &path),
        );
        let (Some(name), Some(iat), Some(int)) = fields else {
            continue;
        };
        if int == 0 {
            px.diag(Diagnostic::new(DiagCode::Oob, path).hint("the delay name table is 0"));
            continue;
        }
        let Some(dll) = px.cstr(name, &path) else {
            continue;
        };
        if !b.libraries.contains(&dll) {
            b.libraries.push(dll.clone());
        }
        let tables = Tables {
            dll,
            lookup: int,
            iat,
            delay: true,
            va_form,
        };
        walk(px, &tables, i, "delay", b);
    }
}
