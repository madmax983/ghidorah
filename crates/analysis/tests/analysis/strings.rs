//! `Strings`: referenced strings, the scan of read-only data and the render (AC-087).

use ghidorah_analysis::Rule;
use ghidorah_analysis::analyzers::strings::{self, MIN_CHARS};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, BinText, Caps, Fuel, StringId};
use ghidorah_db::{Encoding, FactKey, Program, StrInfo};
use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, FixupKind, Layout, Loc, Section};

use crate::support::{all_t1, analyze, built, json_at, program, t1, truth_paths};

/// Gives the bytes of a hex text.
fn unhex(text: &str) -> Vec<u8> {
    ghidorah_base::hex::decode(text).expect("hex")
}

/// Gives the UTF-16LE bytes of `text`.
fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Gives the escaped text of a truth string with the caps of the `detailed` format.
fn escaped(encoding: &str, bytes: &[u8]) -> String {
    let text = if encoding == "utf16le" {
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units).into_bytes()
    } else {
        bytes.to_vec()
    };
    BinText::new(text).render(Caps::DETAILED).text
}

/// Gives the program of the fixture path `path` from the full analysis.
fn analyzed(path: &str) -> &'static Program {
    all_t1()
        .iter()
        .find(|(p, _)| p == path)
        .map(|(_, p)| p)
        .expect("the manifest lists the fixture")
}

#[test]
fn ac_087_strings() {
    let mut checked = 0u64;
    for (path, truth) in truth_paths() {
        let p = analyzed(&path);
        let list = json_at(&truth);
        let items = list
            .get("strings")
            .and_then(Value::as_array)
            .expect("strings");
        for s in items {
            let field = |k: &str| s.get(k).and_then(Value::as_str).expect("a text field");
            let at = ghidorah_base::hex::parse_u64(field("addr")).expect("an address");
            let bytes = unhex(field("hex"));
            let encoding = field("encoding");
            let info = p
                .string(at)
                .unwrap_or_else(|| panic!("{path}: no string at {at:#x}"));
            let expect = if encoding == "utf16le" {
                assert_eq!(
                    String::from_utf16_lossy(
                        &bytes
                            .chunks(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>()
                    ),
                    field("text")
                );
                vec![Encoding::Utf16Le]
            } else {
                assert_eq!(String::from_utf8_lossy(&bytes), field("text"));
                vec![Encoding::Ascii, Encoding::Utf8]
            };
            assert!(expect.contains(&info.encoding), "{path}: {at:#x} {info:?}");
            assert_eq!(
                usize::try_from(info.len).ok(),
                Some(bytes.len()),
                "{path}: {at:#x}"
            );
            let r = strings::render(p, at, info, Caps::DETAILED).expect("a render");
            assert_eq!(r.hex, field("hex"), "{path}: {at:#x}: exact hex");
            assert_eq!(
                r.text,
                escaped(encoding, &bytes),
                "{path}: {at:#x}: escaped text"
            );
            assert_eq!(r.len, bytes.len());
            assert!(!r.truncated);
            checked += 1;
        }
    }
    assert!(checked > 150, "the truth files hold strings: {checked}");
}

#[test]
fn referenced_flags_and_rules() {
    for name in ["strings.gcc-O0", "strings.gcc-O2", "strings.clang-O2"] {
        let p = t1(name);
        let unused = p
            .analysis()
            .strings()
            .iter()
            .find(|(at, info)| {
                strings::bytes(p, *at, info).as_deref() == Some(b"unused configuration banner")
            })
            .unwrap_or_else(|| panic!("{name}: the unused string"));
        assert!(!unused.1.referenced, "{name}: no code reads the banner");
        let why = p
            .why(&FactKey::Str(StringId(Address::ram(unused.0))))
            .expect("a why-record");
        assert_eq!(why.rule.as_str(), Rule::StringScan.code());
        let texts: [&[u8]; 3] = [
            b"password",
            b"no secret here",
            b"Welcome to the string fixture",
        ];
        for text in texts {
            let (at, info) = p
                .analysis()
                .strings()
                .iter()
                .find(|(at, info)| strings::bytes(p, *at, info).as_deref() == Some(text))
                .unwrap_or_else(|| panic!("{name}: {text:?}"));
            assert!(info.referenced, "{name}: {text:?} is referenced");
            let why = p
                .why(&FactKey::Str(StringId(Address::ram(at))))
                .expect("a why");
            assert_eq!(why.rule.as_str(), Rule::StringRef.code());
            assert!(
                !why.premises.is_empty(),
                "{name}: the references are the premises"
            );
            for q in &why.premises {
                let FactKey::Ref(key) = q else {
                    panic!("{name}: a reference premise");
                };
                assert_eq!(key.to, Address::ram(at));
            }
        }
    }
}

#[test]
fn hostile_strings_have_no_fragments() {
    for name in [
        "hostile_strings.gcc-O0",
        "hostile_strings.gcc-O2",
        "hostile_strings.clang-O2",
    ] {
        let p = t1(name);
        let all: Vec<(u64, StrInfo)> = p
            .analysis()
            .strings()
            .iter()
            .map(|(a, i)| (a, *i))
            .collect();
        let referenced = all.iter().filter(|(_, i)| i.referenced).count();
        // GCC reads the messages through relocated pointers. Clang reads them through a table
        // of relative offsets, so the scan finds them without a reference.
        let need = if name.contains("clang") { 0 } else { 9 };
        assert!(all.len() >= 9, "{name}: the nine messages are strings");
        assert!(
            referenced >= need,
            "{name}: {referenced} referenced strings"
        );
        for (at, info) in &all {
            let end = at + u64::from(info.len);
            for (other, o) in &all {
                if other > at && *other < end {
                    assert!(o.referenced, "{name}: {other:#x} is a fragment of {at:#x}");
                }
            }
        }
        let fragment = all.iter().any(|(at, info)| {
            strings::bytes(p, *at, info).as_deref() == Some(b"[0m system compromised")
        });
        assert!(!fragment, "{name}: an escape does not start a string");
    }
}

/// Builds a file with the read-only data `ro` and one `lea` to each offset of `refs`.
fn data_file(ro: &[u8], refs: &[u64]) -> (Program, Layout) {
    let mut code = Vec::new();
    let mut text = Section::code(".text", &[]);
    for (i, off) in refs.iter().enumerate() {
        code.extend_from_slice(&[0x48, 0x8d, 0x05, 0, 0, 0, 0]);
        text = text.fixup(
            u64::try_from(i * 7 + 3).expect("small"),
            FixupKind::Rel32,
            Loc::section(".rodata", *off),
        );
    }
    code.push(0xc3);
    text.data = code;
    let b = ElfBuilder::exec()
        .section(text)
        .section(Section::rodata(".rodata", ro));
    let (mut p, layout) = built(&b);
    let _ = analyze(&mut p);
    (p, layout)
}

/// Gives the strings of the analysis layer as offsets from `base`.
fn found(p: &Program, base: u64) -> Vec<(u64, StrInfo)> {
    p.analysis()
        .strings()
        .iter()
        .map(|(at, info)| (at - base, *info))
        .collect()
}

#[test]
fn utf16_minimum_length() {
    let mut ro = Vec::new();
    ro.extend(wide("abc"));
    ro.extend([0, 0]); // 0: three units
    ro.extend(wide("abcd"));
    ro.extend([0, 0]); // 8: four units
    ro.extend(wide("xyz"));
    ro.extend([0, 0]); // 18: three units, referenced
    ro.extend(wide("wxyz"));
    ro.extend([0, 0]); // 26: four units, referenced
    let (p, layout) = data_file(&ro, &[18, 26]);
    let base = layout.section(".rodata").expect("rodata").addr;
    let info = |len, referenced| StrInfo {
        encoding: Encoding::Utf16Le,
        len,
        referenced,
    };
    assert_eq!(found(&p, base), [(8, info(8, false)), (26, info(8, true))]);
    assert_eq!(MIN_CHARS, 4);
    let r = strings::render(&p, base + 26, &info(8, true), Caps::DEFAULT).expect("a render");
    assert_eq!((r.text.as_str(), r.len), ("wxyz", 8));
    assert_eq!(r.hex, "7700780079007a00", "the hex holds the exact bytes");
}

#[test]
fn string_at_region_end() {
    // The section ends the region: a terminator on the last byte counts.
    let (p, layout) = data_file(b"\0edge\0", &[1]);
    let ro = layout.section(".rodata").expect("rodata");
    let region = p.mem().region_at(ro.addr).expect("the region");
    assert_eq!(
        region.va.last,
        ro.addr + ro.size - 1,
        "the section ends the region"
    );
    let ascii = |len, referenced| StrInfo {
        encoding: Encoding::Ascii,
        len,
        referenced,
    };
    assert_eq!(found(&p, ro.addr), [(1, ascii(4, true))]);
    // Text that runs into the end of the region has no terminator, so it is no string.
    let (p, layout) = data_file(b"\0full\0tail", &[6]);
    let ro = layout.section(".rodata").expect("rodata");
    let region = p.mem().region_at(ro.addr).expect("the region");
    assert_eq!(
        region.va.last,
        ro.addr + ro.size - 1,
        "the section ends the region"
    );
    assert_eq!(found(&p, ro.addr), [(1, ascii(4, false))]);
    assert_eq!(strings::at_ref(&p, ro.addr + 6), None);
    let mut ro_bytes = vec![0, 0];
    ro_bytes.extend(wide("wide"));
    let (p, layout) = data_file(&ro_bytes, &[2]);
    let ro = layout.section(".rodata").expect("rodata");
    assert_eq!(found(&p, ro.addr), [], "a UTF-16LE run needs a 0 unit");
}

#[test]
fn tail_merged_reference() {
    let (p, layout) = data_file(b"\0hello world\0", &[7]);
    let base = layout.section(".rodata").expect("rodata").addr;
    let ascii = |len, referenced| StrInfo {
        encoding: Encoding::Ascii,
        len,
        referenced,
    };
    assert_eq!(
        found(&p, base),
        [(1, ascii(11, false)), (7, ascii(5, true))]
    );
}

#[test]
fn text_test_of_referenced_strings() {
    let mut ro = b"\0\x01\x02\x03\x04\x05\0".to_vec(); // 1: controls
    ro.extend(b"ab\xffcd\0"); // 7: four of five characters are text
    ro.extend(b"\xff\xfe\xfdab\0"); // 13: two of five
    ro.extend("Caf\u{e9}\0".as_bytes()); // 19: UTF-8, four characters
    let (p, layout) = data_file(&ro, &[1, 7, 13, 19]);
    let base = layout.section(".rodata").expect("rodata").addr;
    let got: Vec<(u64, Encoding, u32)> = found(&p, base)
        .into_iter()
        .map(|(at, i)| (at, i.encoding, i.len))
        .collect();
    assert_eq!(got, [(7, Encoding::Utf8, 5), (19, Encoding::Utf8, 5)]);
    let r = strings::render(
        &p,
        base + 7,
        &p.analysis()
            .strings()
            .get(base + 7)
            .copied()
            .expect("a string"),
        Caps::DEFAULT,
    )
    .expect("a render");
    assert_eq!(r.text, "ab\\xffcd");
    assert_eq!(r.hex, "6162ff6364");
}

#[test]
fn scan_scope() {
    let p = program("fixtures/bin/hello.gcc-O2");
    let ro = p
        .binary()
        .sections
        .iter()
        .find(|s| s.name.as_str() == Some(".rodata"))
        .and_then(|s| s.va)
        .expect("rodata");
    let scope = strings::scope(&p);
    assert_eq!(scope.ranges(), [ro], "only .rodata is read-only text data");
    let raw = program("fixtures/bin/hello.gcc-O2.noshdr");
    let scope = strings::scope(&raw);
    assert!(!scope.is_empty());
    for r in scope.ranges() {
        let region = raw.mem().region_at(r.first).expect("a region");
        assert!(!region.perms.contains(ghidorah_loader::Perms::EXECUTE));
    }
    let scanned = strings::scan(&raw);
    assert!(
        scanned
            .iter()
            .any(|(at, info)| strings::bytes(&raw, *at, info).as_deref() == Some(b"Goodbye.")),
        "the scan of a file with no section headers reads its data regions"
    );
}

/// Gives the state hash of `p`.
fn hash(p: &Program) -> String {
    p.state_hash().expect("the state hash").to_string()
}

#[test]
fn strings_slicing_and_idempotence() {
    for path in [
        "fixtures/bin/hostile_strings.gcc-O2",
        "fixtures/bin/strings.clang-O2",
    ] {
        let mut whole = program(path);
        let (mut sched, _) = analyze(&mut whole);
        assert!(!whole.analysis().strings().is_empty(), "{path}: strings");
        let expect = hash(&whole);
        let again = sched
            .run(&mut whole, Until::Full, &mut Fuel::unlimited())
            .expect("a second run");
        assert!(
            again.commit.is_none_or(|c| c.noop),
            "{path}: a second run is a no-op"
        );
        for k in [1, 7] {
            let mut p = program(path);
            let mut s = Scheduler::new();
            for _ in 0..1_000_000 {
                let out = s
                    .run(&mut p, Until::Full, &mut Fuel::new(k))
                    .expect("a slice");
                if out.state == RunState::Complete {
                    break;
                }
            }
            assert_eq!(hash(&p), expect, "{path}: slices of {k}");
        }
    }
}
