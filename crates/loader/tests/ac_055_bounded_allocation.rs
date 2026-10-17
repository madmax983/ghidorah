//! AC-055: the peak heap of a load is at most 32 x file size + 16 MiB on every malformed fixture.
//!
//! This binary installs the counting allocator of `ghidorah-oracle`. Each load runs in
//! [`CountingAlloc::measure`], which counts only the heap of the calling thread.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]

use ghidorah_base::Limits;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_oracle::alloc::CountingAlloc;
use ghidorah_testkit::elf::{
    ElfBuilder, HashStyle, ImportKind, Loc, Malformed, Section, ShdrField, Symbol,
    malformed_variants,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

/// The heap bound of AC-055 for a file of `len` bytes.
fn bound(len: usize) -> usize {
    len.saturating_mul(32).saturating_add(16 << 20)
}

/// One program header.
fn phdr(p_type: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&p_type.to_le_bytes());
    out.extend_from_slice(&4u32.to_le_bytes());
    for v in [offset, vaddr, vaddr, filesz, memsz, align] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// One section header.
fn shdr(name: u32, ty: u32, offset: u64, size: u64, link: u32, entsize: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    for v in [0u64, 0, offset, size] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&link.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&8u64.to_le_bytes());
    out.extend_from_slice(&entsize.to_le_bytes());
    out
}

/// A hand-made ELF64 LE file: header, program headers, section headers, then `payload`.
fn hand_elf(phdrs: &[Vec<u8>], shdrs: &[Vec<u8>], shstrndx: u16, payload: &[u8]) -> Vec<u8> {
    let phoff = 64u64;
    let shoff = phoff + 56 * phdrs.len() as u64;
    let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&62u16.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&phoff.to_le_bytes());
    out.extend_from_slice(&(if shdrs.is_empty() { 0 } else { shoff }).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, u16::try_from(phdrs.len()).expect("phnum"), 64] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&u16::try_from(shdrs.len()).expect("shnum").to_le_bytes());
    out.extend_from_slice(&shstrndx.to_le_bytes());
    for p in phdrs {
        out.extend_from_slice(p);
    }
    for s in shdrs {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(payload);
    out
}

/// The offset of the payload of [`hand_elf`].
fn payload_at(phnum: usize, shnum: usize) -> u64 {
    64 + 56 * phnum as u64 + 64 * shnum as u64
}

const MIB: usize = 1 << 20;

/// Many `PT_NOTE` headers over the same 1 MiB of note-like bytes.
fn notes_everywhere() -> Vec<u8> {
    let n = 2000;
    let mut payload = Vec::with_capacity(MIB);
    while payload.len() < MIB {
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(&64u32.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"GNU\0");
        payload.extend_from_slice(&[0xab; 64]);
    }
    let at = payload_at(n, 0);
    let ph: Vec<Vec<u8>> = (0..n)
        .map(|_| phdr(4, at, 0x1000, MIB as u64, MIB as u64, 4))
        .collect();
    hand_elf(&ph, &[], 0, &payload)
}

/// Many RELA sections over the same 1 MiB of relocation entries.
fn relocs_everywhere() -> Vec<u8> {
    let n = 1000;
    let at = payload_at(0, n);
    let mut sh = vec![shdr(0, 0, 0, 0, 0, 0)];
    sh.extend((1..n).map(|_| shdr(0, 4, at, MIB as u64, 0, 24)));
    hand_elf(&[], &sh, 0, &vec![0x08; MIB])
}

/// One RELR section whose bitmaps each give 63 relocations.
fn relr_bitmaps() -> Vec<u8> {
    let at = payload_at(0, 2);
    let sh = vec![shdr(0, 0, 0, 0, 0, 0), shdr(0, 19, at, MIB as u64, 0, 8)];
    let mut payload = 0x1000u64.to_le_bytes().to_vec();
    while payload.len() < MIB {
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
    }
    hand_elf(&[], &sh, 0, &payload)
}

/// A symbol table whose names all point to one 4,095-byte string.
fn long_symbol_names() -> Vec<u8> {
    let count = MIB / 24;
    let sym_at = payload_at(0, 3);
    let str_at = sym_at + (count * 24) as u64;
    let sh = vec![
        shdr(0, 0, 0, 0, 0, 0),
        shdr(0, 2, sym_at, (count * 24) as u64, 2, 24),
        shdr(0, 3, str_at, 4096, 0, 0),
    ];
    let mut payload = vec![0u8; count * 24];
    payload.extend(std::iter::repeat_n(b'a', 4095));
    payload.push(0);
    hand_elf(&[], &sh, 0, &payload)
}

/// Section headers that all name one 4,095-byte string, with the escape count.
fn long_section_names() -> Vec<u8> {
    let n = 4000;
    let at = payload_at(0, n);
    let mut sh = vec![shdr(0, 0, 0, 0, 0, 0)];
    sh.extend((1..n).map(|_| shdr(0, 3, at, 4096, 0, 0)));
    let mut payload: Vec<u8> = std::iter::repeat_n(b's', 4095).collect();
    payload.push(0);
    hand_elf(&[], &sh, 1, &payload)
}

/// `ElfBuilder` files with huge counts.
fn builder_variants() -> Vec<Vec<u8>> {
    let base = || {
        ElfBuilder::dyn_object()
            .section(Section::code(".text", &[0xc3; 64]))
            .symbol(Symbol::func("f", Loc::section(".text", 0), 1))
            .export(Symbol::func("f", Loc::section(".text", 0), 1))
            .import("puts", ImportKind::Plt)
            .hash(HashStyle::Both)
    };
    vec![
        base()
            .malformed(Malformed::EscapeCounts)
            .malformed(Malformed::Patch(0, vec![0x7f]))
            .build(),
        base()
            .malformed(Malformed::Shdr(".dynsym".into(), ShdrField::Size, 1 << 40))
            .build(),
        base()
            .malformed(Malformed::Shdr(".symtab".into(), ShdrField::Size, 1 << 50))
            .build(),
        base()
            .strip_section_headers()
            .malformed(Malformed::Dynamic(4, 0))
            .build(),
        base().malformed(Malformed::Dynamic(0x6fff_fef5, 0)).build(),
    ]
}

#[test]
fn ac_055_bounded_allocation() {
    let mut inputs: Vec<(String, Vec<u8>)> = malformed_variants()
        .into_iter()
        .map(|v| (v.name.to_string(), v.bytes))
        .collect();
    inputs.extend(
        builder_variants()
            .into_iter()
            .enumerate()
            .map(|(i, b)| (format!("builder_{i}"), b)),
    );
    inputs.push(("notes_everywhere".into(), notes_everywhere()));
    inputs.push(("relocs_everywhere".into(), relocs_everywhere()));
    inputs.push(("relr_bitmaps".into(), relr_bitmaps()));
    inputs.push(("long_symbol_names".into(), long_symbol_names()));
    inputs.push(("long_section_names".into(), long_section_names()));
    let mut problems = Vec::new();
    for (name, bytes) in &inputs {
        let (result, stats) = ALLOC.measure(|| {
            let loaded = load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT);
            loaded.map(|(b, m)| (b.diagnostics.len(), m.len()))
        });
        let limit = bound(bytes.len());
        let fatal = matches!(name.as_str(), "empty_file" | "truncated_ehdr" | "bad_magic");
        if result.is_err() != fatal {
            problems.push(format!("{name}: load result {result:?}"));
        }
        if stats.peak_bytes > limit {
            problems.push(format!(
                "{name}: peak {} above {limit} for {} bytes ({result:?})",
                stats.peak_bytes,
                bytes.len()
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn hostile_files_keep_their_tables_bounded() {
    let (b, _) = load(&relr_bitmaps(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("relr");
    let cap = MIB / 4 + 65_536;
    assert!(b.relocs.len() <= cap, "{} relocations", b.relocs.len());
    assert!(b.relocs.len() > 1000, "the cap keeps many relocations");
    assert!(b.diagnostics.iter().any(|d| d.code.name() == "E_LIMIT"));
    let (b, _) = load(&long_symbol_names(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("names");
    let text: usize = b.symbols.iter().map(|s| s.name.len()).sum();
    assert!(text <= 5 * MIB + 2 * MIB, "{text} name bytes");
    assert!(b.diagnostics.iter().any(|d| d.code.name() == "E_LIMIT"));
}
