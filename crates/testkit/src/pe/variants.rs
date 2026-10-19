//! The named `PeBuilder` variants of design Section 4.15: mapping knobs, table forms and
//! malformed tables. The PE tests and the `pe_load` fuzz seeds use them.
//!
//! The base file has `.text` at RVA 0x1000 (0x200 bytes, one function at 0x1000) and
//! `.data` at RVA 0x2000 (0x40 bytes of 0x11). The entry is 0x1000.

use super::{
    CodeView, DelayDll, Dll, ExportItem, Exports, PeBuilder, REL_DIR64, REL_HIGHLOW, RelocBlock,
    RtFunc, Section, Thunk, Unwind,
};

/// One named variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// The variant name, for example `vsize_zero`.
    pub name: &'static str,
    /// The file bytes.
    pub bytes: Vec<u8>,
}

/// The code of the base file: `sub rsp, 0x28; xor ecx, ecx; add rsp, 0x28; ret`, then `int3`.
fn code() -> Vec<u8> {
    let mut out = vec![
        0x48, 0x83, 0xec, 0x28, 0x31, 0xc9, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    out.resize(0x200, 0xcc);
    out
}

/// The base builder: `.text`, `.data` and the entry at 0x1000.
#[must_use]
pub fn base() -> PeBuilder {
    PeBuilder::exe()
        .entry(0x1000)
        .section(Section::code(".text", 0x1000, &code()))
        .section(Section::data(".data", 0x2000, &[0x11; 0x40]))
}

/// The base builder with a cold part: `test ecx, ecx; jne 0x1100; ret` at 0x1000 and
/// `xor eax, eax; ret` at 0x1100.
fn chained() -> PeBuilder {
    let mut text = vec![0x85, 0xc9, 0x0f, 0x85, 0xf8, 0x00, 0x00, 0x00, 0xc3];
    text.resize(0x100, 0xcc);
    text.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    text.resize(0x200, 0xcc);
    PeBuilder::exe()
        .entry(0x1000)
        .section(Section::code(".text", 0x1000, &text))
        .section(Section::data(".data", 0x2000, &[0x11; 0x40]))
}

/// The base builder of a DLL.
fn base_dll() -> PeBuilder {
    PeBuilder::dll()
        .section(Section::code(".text", 0x1000, &code()))
        .section(Section::data(".data", 0x2000, &[0x11; 0x40]))
}

/// The import descriptor of `k32.dll` with one import `Beep`, at file offset 0x300. The RVAs
/// point into the headers.
fn header_imports() -> Vec<u8> {
    let mut out = vec![0u8; 0xa0];
    let mut put = |at: usize, v: &[u8]| {
        if let Some(p) = out.get_mut(at..at + v.len()) {
            p.copy_from_slice(v);
        }
    };
    put(0x00, &0x340u32.to_le_bytes());
    put(0x0c, &0x380u32.to_le_bytes());
    put(0x10, &0x360u32.to_le_bytes());
    put(0x40, &0x390u64.to_le_bytes());
    put(0x60, &0x390u64.to_le_bytes());
    put(0x80, b"k32.dll\0");
    put(0x92, b"Beep\0");
    out
}

/// Gives the exports of the `exports` variant: two names, one ordinal-only export, an unused
/// slot and two forwarders.
fn dll_exports() -> Exports {
    Exports {
        dll: "test.dll".to_owned(),
        base: 1,
        items: vec![
            ExportItem::Code(0x1000),
            ExportItem::Code(0x1020),
            ExportItem::Forward("kernel32.ExitProcess".to_owned()),
            ExportItem::Unused,
            ExportItem::Forward("alpha.#5".to_owned()),
            ExportItem::Code(0x1040),
            ExportItem::Code(0x2000),
        ],
        names: vec![
            ("add".to_owned(), 0),
            ("mul".to_owned(), 1),
            ("ExitNow".to_owned(), 2),
            ("AlphaFive".to_owned(), 4),
            ("table".to_owned(), 6),
        ],
        number_of_names: None,
        number_of_functions: None,
    }
}

fn kernel32(null_ilt: bool, bound: bool) -> Dll {
    Dll {
        name: "KERNEL32.dll".to_owned(),
        thunks: vec![
            Thunk::name("ExitProcess", 0x167),
            Thunk::name("Sleep", 0x5a2),
        ],
        null_ilt,
        bound,
    }
}

fn mapping_variants() -> Vec<(&'static str, PeBuilder)> {
    vec![
        ("minimal", base()),
        (
            "vsize_zero",
            base().section(Section::data(".zv", 0x3000, &[0x22; 0x40]).vsize(0)),
        ),
        (
            "raw_ptr_low",
            base().section(
                Section::data(".low", 0x3000, &[])
                    .vsize(0x100)
                    .at_raw(0x1f0, 0x100),
            ),
        ),
        (
            "raw_ptr_unaligned",
            base().section(
                Section::data(".odd", 0x3000, &[])
                    .vsize(0x100)
                    .at_raw(0x401, 0x100),
            ),
        ),
        (
            "rva_in_headers",
            base()
                .size_of_headers(0x400)
                .dir(1, 0x300, 40)
                .patch(0x300, &header_imports()),
        ),
        (
            "overlap",
            PeBuilder::exe()
                .entry(0x1000)
                .section(Section::code(".a", 0x1000, &[0xaa; 0x10]).vsize(0x2000))
                .section(Section::data(".b", 0x2000, &[0xbb; 0x10]).vsize(0x1000)),
        ),
        (
            "past_eof",
            base().section(
                Section::data(".far", 0x3000, &[])
                    .vsize(0x100)
                    .at_raw(0x10000, 0x200),
            ),
        ),
        (
            "bss",
            base().section(Section::with(".bss", 0x3000, &[], super::SCN_BSS).vsize(0x80)),
        ),
        ("dirs_32", base().dir_count(32)),
        (
            "pe32_i386",
            base().machine(0x14c).magic(0x10b).image_base(0x40_0000),
        ),
        ("pe32plus_arm64", base().machine(0xaa64)),
        ("mz_no_pe", base().no_pe_signature()),
    ]
}

fn import_variants() -> Vec<(&'static str, PeBuilder)> {
    vec![
        ("imports", base().import(kernel32(false, false))),
        ("null_ilt", base().import(kernel32(true, false))),
        ("bound_iat", base().import(kernel32(false, true))),
        (
            "ordinal_import",
            base().import(Dll::new(
                "alpha.dll",
                vec![Thunk::Ordinal(5), Thunk::name("alpha_named", 1)],
            )),
        ),
        (
            "delay_rva",
            base().delay_import(DelayDll {
                name: "beta.dll".to_owned(),
                thunks: vec![Thunk::name("beta_delayed", 0), Thunk::Ordinal(9)],
                vc6: false,
            }),
        ),
        (
            "vc6_delay",
            base().image_base(0x40_0000).delay_import(DelayDll {
                name: "beta.dll".to_owned(),
                thunks: vec![Thunk::name("beta_delayed", 0), Thunk::Ordinal(9)],
                vc6: true,
            }),
        ),
    ]
}

fn table_variants() -> Vec<(&'static str, PeBuilder)> {
    let mut huge = dll_exports();
    huge.number_of_names = Some(0x7fff_ffff);
    huge.number_of_functions = Some(0x7fff_ffff);
    let cycle = Exports {
        dll: "self.dll".to_owned(),
        base: 1,
        items: vec![
            ExportItem::Forward("self.b".to_owned()),
            ExportItem::Forward("self.a".to_owned()),
        ],
        names: vec![("a".to_owned(), 0), ("b".to_owned(), 1)],
        number_of_names: None,
        number_of_functions: None,
    };
    let block = |size: u32| RelocBlock {
        page: 0x2000,
        entries: vec![REL_DIR64 << 12],
        size: Some(size),
    };
    let plain = |begin: u32, end: u32| RtFunc {
        begin,
        end,
        unwind: Unwind::Plain,
    };
    let chain = |begin: u32, end: u32, to: usize| RtFunc {
        begin,
        end,
        unwind: Unwind::Chain(to),
    };
    let mut out = import_variants();
    out.extend(vec![
        ("exports", base_dll().exports(dll_exports())),
        ("huge_names", base_dll().exports(huge)),
        ("forwarder_cycle", base_dll().exports(cycle)),
        (
            "relocs",
            base().reloc(RelocBlock {
                page: 0x2000,
                entries: vec![
                    REL_DIR64 << 12,
                    (REL_DIR64 << 12) | 8,
                    (REL_HIGHLOW << 12) | 0x10,
                    (4 << 12) | 0x18,
                    (4 << 12) | 0x20,
                    0,
                ],
                size: None,
            }),
        ),
        ("block_size_0", base().reloc(block(0)).reloc(block(16))),
        ("block_size_7", base().reloc(block(7)).reloc(block(16))),
        (
            "chain",
            chained()
                .pdata(plain(0x1000, 0x1009))
                .pdata(chain(0x1100, 0x1103, 0)),
        ),
        (
            "chain_cycle",
            chained()
                .pdata(chain(0x1000, 0x1009, 1))
                .pdata(chain(0x1100, 0x1103, 0)),
        ),
        (
            "pdata_bad",
            base()
                .pdata(plain(0x1010, 0x1010))
                .pdata(plain(0x2000, 0x2010))
                .pdata(plain(0x1000, 0x100b)),
        ),
        (
            "tls_257",
            base().tls((0..257).map(|i| super::EXE_BASE + 0x1000 + i).collect()),
        ),
        ("tls_one", base().tls(vec![super::EXE_BASE + 0x1000])),
        (
            "codeview",
            base().codeview(CodeView {
                guid: [
                    0x34, 0x7e, 0x8d, 0xf0, 0x17, 0x38, 0x43, 0x8a, 0x4c, 0x4c, 0x44, 0x20, 0x50,
                    0x44, 0x42, 0x2e,
                ],
                age: 3,
                pdb: "C:\\build\\test.pdb".to_owned(),
            }),
        ),
    ]);
    out
}

/// Gives the named builders of the variants in a fixed order.
#[must_use]
pub fn builders() -> Vec<(&'static str, PeBuilder)> {
    mapping_variants()
        .into_iter()
        .chain(table_variants())
        .collect()
}

/// Gives the builder of the variant `name`.
#[must_use]
pub fn builder(name: &str) -> Option<PeBuilder> {
    builders()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, b)| b)
}

/// Gives the named variants in a fixed order.
#[must_use]
pub fn variants() -> Vec<Variant> {
    builders()
        .into_iter()
        .map(|(name, b)| Variant {
            name,
            bytes: b.build(),
        })
        .collect()
}
