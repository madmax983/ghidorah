//! Tests of the parsers and helpers of `xtask fixtures` on small inline inputs.

use std::collections::BTreeMap;

use xtask::fixtures::elfinfo::{self, Reloc, Section};
use xtask::fixtures::jumptab::{self, Object, TableKind};
use xtask::fixtures::leaf::{self, IntType};
use xtask::fixtures::manifest::{self, Entry, Manifest};
use xtask::fixtures::{facts, objdump, pretty, questions, toolchain, truth};
use xtask::golden;
use xtask::json::{self, Value};

const READELF: &str = "ELF Header:
  Type:                              DYN (Position-Independent Executable file)
  Entry point address:               0x1090

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  INTERP         0x000318 0x0000000000000318 0x0000000000000318 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x0001a9 0x0001a9 R E 0x1000
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002db8 0x0000000000003db8 0x0000000000003db8 0x000248 0x000248 R   0x1

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [16] .text             PROGBITS        0000000000001060 001060 00013a 00  AX  0   0 16
  [18] .rodata           PROGBITS        0000000000002000 002000 000016 00   A  0   0  4
  [28] .symtab           SYMTAB          0000000000000000 003040 000378 18     29  18  8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),

Dynamic section at offset 0x2dc8 contains 3 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE

Relocation section '.rela.plt' at offset 0x630 contains 2 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000003fd0  0000000400000007 R_X86_64_JUMP_SLOT     0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
0000000000003db8  0000000000000008 R_X86_64_RELATIVE                         1170

Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (3)

Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    23: 0000000000001180    26 FUNC    GLOBAL DEFAULT   16 greet
    24: 0000000000001060 0x186a0 FUNC    GLOBAL DEFAULT   16 big

Displaying notes found in: .note.gnu.property
  GNU                  0x00000020	NT_GNU_PROPERTY_TYPE_0	      Properties: x86 feature: IBT, SHSTK, x86 ISA needed: x86-64-baseline
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)	    Build ID: 8b533637
";

#[test]
fn readelf_text_parses() {
    let info = elfinfo::parse(READELF);
    assert_eq!(info.elf_type, "DYN");
    assert_eq!(info.entry, 0x1090);
    assert_eq!(info.segments.len(), 4);
    assert_eq!(info.segments[1].flags, "RE");
    assert_eq!(info.segments[1].vaddr, 0x1000);
    assert_eq!(info.sections.len(), 4);
    assert_eq!(info.sections[0].name, "");
    assert_eq!(info.sections[1].name, ".text");
    assert!(info.sections[1].is_exec());
    assert_eq!(info.sections[3].flags, "");
    assert_eq!(
        info.section_at(0x2004).map(|s| s.name.as_str()),
        Some(".rodata")
    );
    assert_eq!(info.libraries(), vec!["libc.so.6".to_owned()]);
    assert_eq!(info.imports(), vec!["__stack_chk_fail".to_owned()]);
    assert_eq!(
        info.slot_import(0x3fd0).as_deref(),
        Some("__stack_chk_fail")
    );
    assert_eq!(info.relocs[1].addend, 0x1170);
    assert_eq!(info.relocs[1].sym, "");
    let greet = info
        .symbols
        .iter()
        .find(|s| s.name == "greet")
        .expect("greet");
    assert_eq!((greet.value, greet.size), (0x1180, 26));
    assert!(greet.is_defined());
    let big = info.symbols.iter().find(|s| s.name == "big").expect("big");
    assert_eq!(big.size, 100_000);
    assert_eq!(info.build_id.as_deref(), Some("8b533637"));
    assert_eq!(
        info.x86_features,
        vec!["IBT".to_owned(), "SHSTK".to_owned()]
    );
    let p = info.protections();
    for (key, want) in [
        ("pie", true),
        ("nx", true),
        ("canary", true),
        ("ibt", true),
        ("shstk", true),
        ("fortify", false),
    ] {
        assert_eq!(p.get(key).and_then(Value::as_bool), Some(want), "{key}");
    }
    assert_eq!(p.get("relro").and_then(Value::as_str), Some("full"));
    assert_eq!(elfinfo::unversioned("puts@GLIBC_2.2.5 (2)"), "puts");
    assert_eq!(elfinfo::hex("0x1f"), Some(31));
}

#[test]
fn variant_protections_hold_the_fields_that_differ() {
    let base = elfinfo::parse(READELF).protections();
    assert!(
        elfinfo::parse(READELF)
            .variant_protections(&base)
            .is_empty()
    );
    // `objcopy` drops PT_GNU_RELRO and the execute bit of the stack changes.
    let noeh = READELF
        .replace(
            "  GNU_RELRO      0x002db8 0x0000000000003db8 0x0000000000003db8 0x000248 0x000248 R   0x1\n",
            "",
        )
        .replace("0x000000 RW  0x10", "0x000000 RWE 0x10");
    let own = elfinfo::parse(&noeh).variant_protections(&base);
    let keys: Vec<&str> = own.keys().map(String::as_str).collect();
    assert_eq!(keys, ["nx", "relro"]);
    assert_eq!(own.get("relro").and_then(Value::as_str), Some("none"));
    assert_eq!(own.get("nx").and_then(Value::as_bool), Some(false));
    // A text with no symbol table keeps the import fields of the build.
    let start = READELF
        .find("Symbol table '.dynsym'")
        .expect("the dynsym part");
    let end = READELF.find("Displaying notes").expect("the notes part");
    let noshdr = format!("{}{}", &READELF[..start], &READELF[end..]);
    assert!(elfinfo::parse(&noshdr).imports().is_empty());
    assert!(
        elfinfo::parse(&noshdr)
            .variant_protections(&base)
            .is_empty()
    );
}

const OBJDUMP: &str = "hello.gcc-O2:     file format elf64-x86-64


Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:\tf3 0f 1e fa          \tendbr64
    1054:\tff 25 76 2f 00 00    \tjmp    QWORD PTR [rip+0x2f76]        # 3fd0 <puts@GLIBC_2.2.5>

Disassembly of section .text:

0000000000001060 <main>:
    1060:\tf3 0f 1e fa          \tendbr64
    1064:\te8 17 01 00 00       \tcall   1180 <greet>
    1069:\tff 15 23 2f 00 00    \tcall   QWORD PTR [rip+0x2f23]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    106f:\t3e ff e0             \tnotrack jmp rax
    1072:\te9 d9 ff ff ff       \tjmp    1050 <puts@plt>
";

#[test]
fn objdump_listing_parses() {
    let listing = objdump::parse(OBJDUMP);
    assert_eq!(listing.labels.len(), 2);
    assert_eq!(listing.labels[0].section, ".plt.sec");
    assert_eq!(listing.insns.len(), 7);
    let call = listing.at(0x1064).expect("call");
    assert_eq!(call.len, 5);
    assert_eq!(call.text, "call 1180 <greet>");
    assert_eq!(call.mnemonic(), "call");
    assert_eq!(call.direct_target(), Some(0x1180));
    let got = listing.at(0x1069).expect("got call");
    assert!(got.is_memory_indirect());
    assert_eq!(got.comment_target(), Some(0x3fd8));
    assert_eq!(got.direct_target(), None);
    assert_eq!(listing.at(0x106f).map(objdump::Insn::mnemonic), Some("jmp"));
    assert_eq!(listing.holding(0x1066).map(|i| i.addr), Some(0x1064));
    assert_eq!(
        listing.plt_label(0x1050).map(|l| l.name.as_str()),
        Some("puts@plt")
    );
    assert_eq!(listing.next_label(0x1060, ".text"), None);
    assert_eq!(listing.section_end(".text"), Some(0x1077));
    assert_eq!(listing.range(0x1060, 0x1070).count(), 4);
}

const MAP: &str = "Discarded input sections

 .note.GNU-stack
                0x0000000000000000        0x0 sw.o

Linker script and memory map

.text           0x0000000000001060      0x13a
 *(.text.unlikely .text.*_unlikely .text.unlikely.*)
 .text.unlikely
                0x0000000000001100       0x20 sw.o
 .text          0x0000000000001180      0x168 sw.o
                0x0000000000001180                apply_op
 .text          0x00000000000012e8        0x0 /usr/lib/crtn.o
 .rodata        0x0000000000002004       0x50 sw.o
";

fn section(name: &str, flags: &str) -> Section {
    Section {
        index: 1,
        name: name.to_owned(),
        kind: "PROGBITS".to_owned(),
        addr: 0,
        offset: 0,
        size: 0x100,
        flags: flags.to_owned(),
    }
}

fn reloc(sec: &str, offset: u64, kind: &str, sym: &str, addend: i64) -> Reloc {
    Reloc {
        section: sec.to_owned(),
        offset,
        kind: kind.to_owned(),
        sym: sym.to_owned(),
        addend,
    }
}

#[test]
fn relocations_give_jump_tables() {
    let objects = vec!["sw.o".to_owned()];
    let map = jumptab::parse_map(MAP, &objects);
    assert_eq!(
        map.get(&(".text".to_owned(), "sw.o".to_owned())),
        Some(&0x1180)
    );
    assert_eq!(
        map.get(&(".text.unlikely".to_owned(), "sw.o".to_owned())),
        Some(&0x1100)
    );
    assert_eq!(
        map.get(&(".rodata".to_owned(), "sw.o".to_owned())),
        Some(&0x2004)
    );
    assert!(!map.contains_key(&(".note.GNU-stack".to_owned(), "sw.o".to_owned())));
    let sections = vec![
        section(".text", "AX"),
        section(".rodata", "A"),
        section(".rodata.str1.1", "AMS"),
    ];
    // Two rel32 tables side by side (0x0 with 2 entries, 0x8 with 1 entry), one abs64 table at
    // 0x10 and a string table at 0x20 that is no jump table.
    let relocs = vec![
        reloc(".rela.text", 0x0d, "R_X86_64_PC32", ".rodata", -4),
        reloc(".rela.text", 0x40, "R_X86_64_PC32", ".rodata", 4),
        reloc(".rela.text", 0x60, "R_X86_64_32S", ".rodata", 0x10),
        reloc(".rela.text", 0x70, "R_X86_64_PC32", ".rodata", 0x1c),
        reloc(".rela.rodata", 0x0, "R_X86_64_PC32", ".text", 0x30),
        reloc(".rela.rodata", 0x4, "R_X86_64_PC32", ".text", 0x3c),
        reloc(".rela.rodata", 0x8, "R_X86_64_PC32", ".text", 0x50),
        reloc(".rela.rodata", 0x10, "R_X86_64_64", ".text", 0x90),
        reloc(".rela.rodata", 0x18, "R_X86_64_64", ".text", 0x98),
        reloc(".rela.rodata", 0x20, "R_X86_64_PC32", ".rodata.str1.1", 0),
    ];
    let obj = Object {
        file: "sw.o",
        sections: &sections,
        relocs: &relocs,
    };
    let tables = jumptab::tables(&obj, &map);
    assert_eq!(tables.len(), 3, "{tables:?}");
    assert_eq!(tables[0].table, 0x2004);
    assert_eq!(tables[0].kind, TableKind::Rel32);
    assert_eq!(tables[0].targets, vec![0x1180 + 0x30, 0x1180 + 0x38]);
    assert_eq!(tables[0].refs, vec![0x1180 + 0x0d]);
    assert_eq!(tables[1].table, 0x2004 + 8);
    assert_eq!(tables[1].targets, vec![0x1180 + 0x50]);
    assert_eq!(tables[2].kind, TableKind::Abs64);
    assert_eq!(tables[2].targets, vec![0x1180 + 0x90, 0x1180 + 0x98]);
    assert_eq!(TableKind::Abs64.name(), "abs64");
}

#[test]
fn leaf_lines_parse() {
    let src = "#include <stdint.h>\nLEAF uint64_t gcd(uint64_t a, uint64_t b) {\n    return a;\n}\nLEAF int8_t neg(int8_t x) {\n";
    let fns = leaf::parse_source(src).expect("the LEAF lines parse");
    assert_eq!(fns.len(), 2);
    assert_eq!(fns[0].sig(), "u64(u64,u64)");
    assert_eq!(fns[1].sig(), "i8(i8)");
    assert_eq!(
        fns[0].list_line(),
        "LEAF2(gcd, uint64_t, uint64_t, uint64_t)"
    );
    assert_eq!(leaf::list_header(&fns).lines().count(), 2);
    assert_eq!(IntType::from_c("int32_t"), Some(IntType::I32));
    assert_eq!(IntType::I16.bits(), 16);
    let err = leaf::parse_source("LEAF float f(float x) {\n").expect_err("float is no leaf type");
    assert_eq!(err.line, 1);
    let err = leaf::parse_source("LEAF uint8_t f(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {\n")
        .expect_err("four arguments");
    assert!(err.to_string().contains("1 to 3"));
    assert_eq!(
        leaf::vector_path("loops.gcc-O0"),
        "tests/golden/semantics/leaf/loops.gcc-O0.jsonl"
    );
}

#[test]
fn leaf_vector_lines_check() {
    let fns = leaf::parse_source("LEAF uint8_t inc(uint8_t a) {\n").expect("parse");
    let line = r#"{"fn":"inc","args":["0xff"],"ret":"0x0"}"#;
    let body = format!("{line}\n").repeat(leaf::CASES);
    assert!(leaf::check_lines("v.jsonl", &body, &fns).is_empty());
    let short = format!("{line}\n").repeat(10);
    assert_eq!(leaf::check_lines("v.jsonl", &short, &fns).len(), 1);
    let wide = format!("{body}{{\"fn\":\"inc\",\"args\":[\"0x100\"],\"ret\":\"0x1\"}}\n");
    assert_eq!(
        leaf::check_lines("v.jsonl", &wide, &fns).len(),
        2,
        "a wide value and a count"
    );
    let unknown = format!("{body}{{\"fn\":\"dec\",\"args\":[\"0x1\"],\"ret\":\"0x0\"}}\n");
    assert_eq!(leaf::check_lines("v.jsonl", &unknown, &fns).len(), 1);
}

#[test]
fn section_headers_drop() {
    let mut elf = vec![0u8; 0x80];
    elf[0x28..0x30].copy_from_slice(&0x40u64.to_le_bytes());
    elf[0x3a..0x3c].copy_from_slice(&0x20u16.to_le_bytes());
    elf[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes());
    elf[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());
    let out = toolchain::drop_section_headers(&elf).expect("the table is at the end");
    assert_eq!(out.len(), 0x40);
    assert!(out[0x28..0x30].iter().all(|b| *b == 0));
    assert!(out[0x3c..0x40].iter().all(|b| *b == 0));
    let mut tail = elf.clone();
    tail.push(0);
    assert!(toolchain::drop_section_headers(&tail).is_err());
    assert!(toolchain::drop_section_headers(&elf[..0x20]).is_err());
}

#[test]
fn glob_matches() {
    let cases = [
        ("mov*eax*0x1337", "mov eax,0x1337", true),
        ("mov*eax*0x1337", "mov    eax, 0x1337", true),
        ("mov*eax*0x1337", "xor eax,0x1337", false),
        ("a?c", "abc", true),
        ("a?c", "ac", false),
        ("*", "", true),
        ("", "x", false),
        ("*.cold", "die.cold", true),
        ("a*b*c", "aXbYbZc", true),
        ("a*b*c", "aXbYbZ", false),
    ];
    for (pattern, text, want) in cases {
        assert_eq!(
            questions::glob_match(pattern, text),
            want,
            "{pattern} on {text}"
        );
    }
}

#[test]
fn golden_changes_count_per_area() {
    let before: golden::Snapshot = BTreeMap::from([
        ("tests/golden/loader/a.txt".to_owned(), [1; 32]),
        ("tests/golden/loader/b.txt".to_owned(), [2; 32]),
        ("tests/golden/tools.json".to_owned(), [3; 32]),
    ]);
    let mut after = before.clone();
    after.insert("tests/golden/loader/a.txt".to_owned(), [9; 32]);
    after.remove("tests/golden/loader/b.txt");
    after.insert("tests/golden/semantics/leaf/x.jsonl".to_owned(), [4; 32]);
    let changes = golden::changes(&before, &after);
    assert_eq!(changes.get("loader"), Some(&2));
    assert_eq!(changes.get("semantics"), Some(&1));
    assert_eq!(changes.get("."), None);
    assert_eq!(golden::area("tests/golden/tools.json"), ".");
    assert!(golden::changes(&before, &before).is_empty());
}

#[test]
fn golden_x86_runs_the_x86_tests_with_tier2() {
    let args = golden::X86_ARGS;
    let package = args
        .iter()
        .position(|a| *a == "-p")
        .expect("a package flag");
    assert_eq!(args.get(package + 1), Some(&"ghidorah-x86"));
    assert_eq!(args.first(), Some(&"test"));
    assert!(!args.contains(&"--workspace"), "{args:?}");
    let split = args
        .iter()
        .position(|a| *a == "--")
        .expect("test binary arguments");
    assert_eq!(args.get(split + 1..), Some(&["--include-ignored"][..]));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the workspace root");
    let extra = golden::run(root, &["x86".to_owned(), "extra".to_owned()]);
    assert!(
        matches!(&extra, Err(xtask::Error::Usage(u)) if u.ends_with("|headers|x86>")),
        "{extra:?}"
    );
}

#[test]
fn pretty_json_is_stable() {
    let value =
        json::parse(r#"{"b":[1,2],"a":{"x":[{"k":"v"}],"e":[],"o":{}},"s":"t\n"}"#).expect("json");
    let text = pretty::write(&value);
    let want = "{\n  \"a\": {\n    \"e\": [],\n    \"o\": {},\n    \"x\": [\n      {\n        \"k\": \"v\"\n      }\n    ]\n  },\n  \"b\": [1,2],\n  \"s\": \"t\\n\"\n}\n";
    assert_eq!(text, want);
    assert_eq!(json::parse(&text).expect("round trip"), value);
}

#[test]
fn fact_strings_encode() {
    let text = json::parse(r#"{"text":"Hi"}"#).expect("json");
    assert_eq!(
        facts::string_bytes(&text),
        Ok((b"Hi".to_vec(), facts::Encoding::Bytes))
    );
    let raw = json::parse(r#"{"hex":"fffe41"}"#).expect("json");
    let (bytes, enc) = facts::string_bytes(&raw).expect("hex");
    assert_eq!(bytes, vec![0xff, 0xfe, 0x41]);
    assert_eq!(facts::string_text(&bytes, enc), "\u{fffd}\u{fffd}A");
    let wide = json::parse(r#"{"text":"Ab","encoding":"utf16le"}"#).expect("json");
    let (bytes, enc) = facts::string_bytes(&wide).expect("utf16");
    assert_eq!(bytes, vec![0x41, 0, 0x62, 0]);
    assert_eq!(enc.terminator(), &[0, 0]);
    assert_eq!(facts::string_text(&bytes, enc), "Ab");
    assert!(facts::string_bytes(&json::parse(r#"{"hex":"f"}"#).expect("json")).is_err());
    assert!(facts::string_bytes(&json::parse("{}").expect("json")).is_err());
}

#[test]
fn truth_schema_reports_faults() {
    let good = truth::read(&xtask::workspace::root(), "hello.gcc-O2").expect("hello truth");
    assert!(truth::check_value("hello.gcc-O2", &good).is_empty());
    assert!(
        !truth::check_value("other", &good).is_empty(),
        "the fixture name differs"
    );
    let mut broken = good.as_object().cloned().expect("object");
    broken.remove("functions");
    broken.insert("function_count".to_owned(), Value::from(1u64));
    let found = truth::check_value("hello.gcc-O2", &Value::Object(broken));
    assert!(found.iter().any(|m| m.contains("`functions`")), "{found:?}");
    // `variant_protections` names variants of `binaries` with fields that differ.
    let own = good
        .get("variant_protections")
        .expect("the noeh variant of hello.gcc-O2 has no PT_GNU_RELRO");
    assert_eq!(
        own.pointer("/noeh/relro").and_then(Value::as_str),
        Some("none")
    );
    for (bad, message) in [
        (r#"{"debug":{"relro":"none"}}"#, "not a variant"),
        (r#"{"noeh":{}}"#, "not an object with a field"),
        (r#"{"noeh":{"relro":1}}"#, "wrong type"),
        (r#"{"noeh":{"color":true}}"#, "unknown"),
        (r#"{"noeh":{"pie":true}}"#, "equals `protections`"),
        (r#"{"noeh":{"build_id":null}}"#, ""),
        ("[]", "not an object"),
    ] {
        let mut t = good.as_object().cloned().expect("object");
        t.insert(
            "variant_protections".to_owned(),
            json::parse(bad).expect("json"),
        );
        let found = truth::check_value("hello.gcc-O2", &Value::Object(t));
        if message.is_empty() {
            assert!(found.is_empty(), "{bad}: {found:?}");
        } else {
            assert!(
                found.iter().any(|m| m.contains(message)),
                "{bad}: {found:?}"
            );
        }
    }
}

#[test]
fn manifest_round_trips() {
    let entry = Entry {
        name: "hello.gcc-O2".to_owned(),
        path: "fixtures/bin/hello.gcc-O2".to_owned(),
        sha256: "00".repeat(32),
        size: 16_000,
        tier: "T1".to_owned(),
        program: "hello".to_owned(),
        build: "gcc-O2".to_owned(),
        variant: "none".to_owned(),
        compiler: "gcc 13.3.0".to_owned(),
        cflags: vec!["-O2".to_owned()],
        ldflags: Vec::new(),
        truth: "fixtures/truth/hello.gcc-O2.json".to_owned(),
    };
    let m = Manifest {
        tools: BTreeMap::from([("gcc".to_owned(), "13.3.0".to_owned())]),
        entries: vec![entry],
    };
    let text = pretty::write(&m.to_value());
    assert_eq!(manifest::parse(&text), Ok(m.clone()));
    assert_eq!(m.total_bytes(), 16_000);
    assert!(m.entry("hello.gcc-O2").is_some());
    assert!(manifest::parse("{}").is_err());
}
