//! Tests of the ID grammar (design Section 3.5, ADR-0008, AC-045).

use ghidorah_base::bintext::escapes;
use ghidorah_base::id::{MAX_ID_TEXT, MAX_NAME_LEN};
use ghidorah_base::{
    Address, BinaryId, BlockId, ExportId, FileOffset, FuncId, Id, IdError, IdKind, ImportId,
    JumpTableId, NoteId, OpId, RefId, RegVar, Rev, SectionId, SegmentId, SetName, Storage,
    StringId, SymId, SyscallId, TxId, TypeRef, VarId, sha256,
};
use ghidorah_testkit::pbt::{self, Gen};

/// Pieces of names. They hold the separators of every ID form, and characters that the quoted
/// form escapes.
const PIECES: [&str; 20] = [
    "a",
    "Z",
    "_",
    "0",
    "7",
    "!",
    "#",
    ":",
    "/",
    "@",
    ">",
    "+",
    "-",
    ".",
    " ",
    "\u{e9}",
    "\"",
    "\\",
    "\u{1b}",
    "\u{e0041}",
];

fn name(g: &mut Gen, max_pieces: usize) -> String {
    let n = usize::try_from(g.range(1, u64::try_from(max_pieces).unwrap_or(1))).unwrap_or(1);
    let mut out = String::new();
    for _ in 0..n {
        out.push_str(g.pick(&PIECES).copied().unwrap_or("a"));
    }
    out
}

fn ident(g: &mut Gen, first: &[u8], rest: &[u8], max: u64) -> String {
    let len = usize::try_from(g.range(1, max)).unwrap_or(1);
    let mut out = String::new();
    for i in 0..len {
        let set = if i == 0 { first } else { rest };
        out.push(char::from(*g.pick(set).unwrap_or(&b'a')));
    }
    out
}

fn address(g: &mut Gen) -> Address {
    if g.draw(4) == 0 {
        Address::external(g.u64())
    } else {
        Address::ram(g.u64())
    }
}

fn storage(g: &mut Gen) -> Option<Storage> {
    let lower = b"abcdefghijklmnopqrstuvwxyz";
    let alnum = b"abcdefghijklmnopqrstuvwxyz0123456789";
    match g.draw(4) {
        0 => Some(Storage::Param(u16::try_from(g.draw(65_536)).unwrap_or(0))),
        1 => Some(Storage::Stack(g.u64().cast_signed())),
        2 => RegVar::new(&ident(g, lower, alnum, 16), g.u64())
            .ok()
            .map(Storage::Reg),
        _ => Some(Storage::Ret),
    }
}

/// Draws one ID of a random kind. A constructor can refuse the drawn name.
fn random_id(g: &mut Gen) -> Option<Id> {
    let kinds = IdKind::ALL;
    let kind = *g.pick(&kinds)?;
    let small = u16::try_from(g.draw(65_536)).unwrap_or(0);
    Some(match kind {
        IdKind::Func => Id::Func(FuncId(address(g))),
        IdKind::Block => Id::Block(BlockId(address(g))),
        IdKind::Op => Id::Op(OpId {
            addr: g.u64(),
            seq: small,
        }),
        IdKind::Import => Id::Import(match g.draw(3) {
            0 => ImportId::elf(&name(g, 8)).ok()?,
            1 => ImportId::pe_by_name(&name(g, 6), &name(g, 8)).ok()?,
            _ => ImportId::pe_by_ordinal(&name(g, 6), small).ok()?,
        }),
        IdKind::Export => Id::Export(if g.bool() {
            ExportId::by_name(&name(g, 8)).ok()?
        } else {
            ExportId::by_ordinal(u32::try_from(g.draw(1 << 32)).unwrap_or(0))
        }),
        IdKind::Syscall => Id::Syscall(if g.bool() {
            SyscallId::by_number(small)
        } else {
            SyscallId::by_name(&ident(
                g,
                b"abcdefghijklmnopqrstuvwxyz_",
                b"abcdefghijklmnopqrstuvwxyz0123456789_",
                64,
            ))
            .ok()?
        }),
        IdKind::Section => Id::Section(SectionId::new(small, &name(g, 8)).ok()?),
        IdKind::Segment => Id::Segment(SegmentId(small)),
        IdKind::Str => Id::Str(StringId(address(g))),
        IdKind::JumpTable => Id::JumpTable(JumpTableId(address(g))),
        IdKind::External => Id::External(g.u64()),
        IdKind::File => Id::File(FileOffset(g.u64())),
        IdKind::Sym => Id::Sym(SymId::new(&name(g, 8)).ok()?),
        IdKind::Var => Id::Var(VarId {
            func: FuncId(address(g)),
            storage: storage(g)?,
        }),
        IdKind::Note => Id::Note(NoteId(g.u64())),
        IdKind::Set => Id::Set(SetName::new(&ident(g, b"aZ09_.-", b"abcXYZ0189_.-", 64)).ok()?),
        IdKind::Type => Id::Type(if g.bool() {
            TypeRef::anon(g.u64())
        } else {
            TypeRef::named(&name(g, 8)).ok()?
        }),
        IdKind::Tx => Id::Tx(TxId(g.u64())),
        IdKind::Ref => Id::Ref(
            RefId::new(
                address(g),
                address(g),
                &ident(g, b"abcxyz", b"abcxyz019_", 32),
            )
            .ok()?,
        ),
    })
}

#[test]
fn ac_045_id_roundtrip() {
    pbt::check("ac_045_id_roundtrip", 20_000, |g| {
        let Some(id) = random_id(g) else {
            return Ok(());
        };
        let text = id.to_string();
        let prefix = id.kind().prefix();
        if !text.starts_with(prefix) {
            return Err(format!("{text:?} lacks the prefix {prefix}"));
        }
        match Id::parse(&text) {
            Ok(back) if back == id => Ok(()),
            Ok(back) => Err(format!("{text:?} parses as {back:?}, not {id:?}")),
            Err(e) => Err(format!("{text:?} does not parse: {e}")),
        }
    });
    // Each kind round-trips at least once on a fixed value.
    let mut kinds_seen = std::collections::BTreeSet::new();
    let mut g = Gen::random(45);
    for _ in 0..20_000 {
        if let Some(id) = random_id(&mut g) {
            kinds_seen.insert(id.kind());
        }
    }
    assert_eq!(
        kinds_seen.len(),
        IdKind::ALL.len(),
        "kinds seen: {kinds_seen:?}"
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of text forms")]
fn id_text_table() {
    let table: Vec<(&str, Id)> = vec![
        ("fn:0x401130", Id::Func(FuncId(Address::ram(0x40_1130)))),
        ("fn:ext:0x3", Id::Func(FuncId(Address::external(3)))),
        ("bb:0x401145", Id::Block(BlockId(Address::ram(0x40_1145)))),
        (
            "op:0x401a2c:3",
            Id::Op(OpId {
                addr: 0x40_1a2c,
                seq: 3,
            }),
        ),
        (
            "op:0x0:65535",
            Id::Op(OpId {
                addr: 0,
                seq: u16::MAX,
            }),
        ),
        ("imp:puts", Id::Import(ImportId::elf("puts").unwrap())),
        (
            "imp:kernel32.dll!ExitProcess",
            Id::Import(ImportId::pe_by_name("kernel32.dll", "ExitProcess").unwrap()),
        ),
        (
            "imp:alpha.dll!#7",
            Id::Import(ImportId::pe_by_ordinal("alpha.dll", 7).unwrap()),
        ),
        ("imp:!a!b", Id::Import(ImportId::elf("a!b").unwrap())),
        ("exp:main", Id::Export(ExportId::by_name("main").unwrap())),
        ("exp:#7", Id::Export(ExportId::by_ordinal(7))),
        ("exp:#x", Id::Export(ExportId::by_name("#x").unwrap())),
        (
            "sys:openat",
            Id::Syscall(SyscallId::by_name("openat").unwrap()),
        ),
        ("sys:257", Id::Syscall(SyscallId::by_number(257))),
        (
            "sec:14:.text",
            Id::Section(SectionId::new(14, ".text").unwrap()),
        ),
        ("sec:0:", Id::Section(SectionId::new(0, "").unwrap())),
        ("sec:3:a:b", Id::Section(SectionId::new(3, "a:b").unwrap())),
        ("seg:2", Id::Segment(SegmentId(2))),
        ("str:0x402010", Id::Str(StringId(Address::ram(0x40_2010)))),
        (
            "jt:0x401200",
            Id::JumpTable(JumpTableId(Address::ram(0x40_1200))),
        ),
        ("ext:0x3", Id::External(3)),
        ("file:0x1040", Id::File(FileOffset(0x1040))),
        (
            "sym:puts@GLIBC_2.2.5",
            Id::Sym(SymId::new("puts@GLIBC_2.2.5").unwrap()),
        ),
        ("sym:sym:x", Id::Sym(SymId::new("sym:x").unwrap())),
        (
            "var:0x401130/stack:-0x14",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Stack(-0x14),
            }),
        ),
        (
            "var:0x401130/stack:0x8",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Stack(8),
            }),
        ),
        (
            "var:0x401130/stack:-0x8000000000000000",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Stack(i64::MIN),
            }),
        ),
        (
            "var:0x401130/param:2",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Param(2),
            }),
        ),
        (
            "var:0x401130/reg:rax@0x401136",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Reg(RegVar::new("rax", 0x40_1136).unwrap()),
            }),
        ),
        (
            "var:0x401130/ret",
            Id::Var(VarId {
                func: FuncId(Address::ram(0x40_1130)),
                storage: Storage::Ret,
            }),
        ),
        ("note:7", Id::Note(NoteId(7))),
        ("set:parsers", Id::Set(SetName::new("parsers").unwrap())),
        (
            "t:sockaddr_in",
            Id::Type(TypeRef::named("sockaddr_in").unwrap()),
        ),
        (
            "t:struct in_addr *",
            Id::Type(TypeRef::named("struct in_addr *").unwrap()),
        ),
        ("t:#00000000deadbeef", Id::Type(TypeRef::anon(0xdead_beef))),
        ("tx:42", Id::Tx(TxId(42))),
        (
            "ref:0x401136>0x402010:read",
            Id::Ref(RefId::new(Address::ram(0x40_1136), Address::ram(0x40_2010), "read").unwrap()),
        ),
        (
            "ref:0x401136>ext:0x3:call",
            Id::Ref(RefId::new(Address::ram(0x40_1136), Address::external(3), "call").unwrap()),
        ),
    ];
    for (text, id) in table {
        assert_eq!(Id::parse(text), Ok(id.clone()), "{text}");
        assert_eq!(id.to_string(), text, "display of {id:?}");
    }
}

#[test]
fn id_lenient_input() {
    // Input accepts leading zeros, either letter case in hex and an upper case DLL name.
    let table: Vec<(&str, &str)> = vec![
        ("fn:0x00401130", "fn:0x401130"),
        ("fn:0x40113A", "fn:0x40113a"),
        (
            "imp:KERNEL32.DLL!ExitProcess",
            "imp:kernel32.dll!ExitProcess",
        ),
        ("t:#DEADBEEF", "t:#00000000deadbeef"),
        ("note:007", "note:7"),
    ];
    for (input, canonical) in table {
        let id = Id::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(id.to_string(), canonical, "{input}");
    }
}

#[test]
fn id_rejects_table() {
    let long_name = "a".repeat(MAX_NAME_LEN + 1);
    let too_long = format!("sym:{}", "a".repeat(MAX_ID_TEXT));
    let sym_long = format!("sym:{long_name}");
    let cases: Vec<(&str, IdError)> = vec![
        ("", IdError::Empty),
        ("foo", IdError::UnknownPrefix),
        ("fn", IdError::UnknownPrefix),
        ("FN:0x1", IdError::UnknownPrefix),
        (
            too_long.as_str(),
            IdError::TooLong {
                len: too_long.len(),
            },
        ),
    ];
    for (text, want) in cases {
        assert_eq!(Id::parse(text), Err(want), "{text:.40}");
    }
    let bad = [
        "fn:",
        "fn:401130",
        "fn:0x",
        "fn:0x1+0x2",
        "bb:main",
        "op:0x401a2c",
        "op:0x401a2c:",
        "op:0x401a2c:65536",
        "op:0x401a2c:-1",
        "op:ext:0x3:1",
        "imp:",
        "imp:!",
        "imp:k.dll!",
        "imp:k.dll!#",
        "imp:k.dll!#65536",
        "exp:",
        "exp:#4294967296",
        "sys:",
        "sys:Open",
        "sys:65536",
        "sys:9a",
        "sec:",
        "sec:14",
        "sec:x:.text",
        "sec:65536:.text",
        "seg:",
        "seg:-1",
        "seg:65536",
        "str:",
        "jt:x",
        "ext:3",
        "file:12",
        "sym:",
        "var:",
        "var:0x1",
        "var:0x1/",
        "var:0x1/stack:0x8000000000000000",
        "var:0x1/stack:-0x8000000000000001",
        "var:0x1/stack:8",
        "var:0x1/param:x",
        "var:0x1/reg:RAX@0x1",
        "var:0x1/reg:rax",
        "var:0x1/reg:rax@1",
        "var:0x1/rets",
        "var:main/ret",
        "note:",
        "note:x",
        "note:18446744073709551616",
        "set:",
        "set:a b",
        "t:",
        "t:#",
        "t:#xyz",
        "t:#00000000000000001",
        "tx:",
        "tx:-1",
        "ref:",
        "ref:0x1",
        "ref:0x1>0x2",
        "ref:0x1>0x2:",
        "ref:0x1>0x2:Read",
        "ref:x>0x2:read",
    ];
    for text in bad {
        assert!(
            matches!(Id::parse(text), Err(IdError::BadPart { .. })),
            "{text:?} gives {:?}",
            Id::parse(text)
        );
    }
    assert!(Id::parse(&sym_long).is_err());
}

#[test]
fn id_constructors_refuse() {
    let long_name = "a".repeat(MAX_NAME_LEN + 1);
    assert!(SymId::new("").is_err());
    assert!(SymId::new(&long_name).is_err());
    assert!(ImportId::elf("").is_err());
    assert!(ImportId::pe_by_name("", "x").is_err());
    assert!(ImportId::pe_by_name("a!b", "x").is_err());
    assert!(ImportId::pe_by_name("k.dll", "").is_err());
    assert!(ImportId::pe_by_name("k.dll", "#12").is_err());
    assert!(ImportId::pe_by_ordinal("", 1).is_err());
    assert!(ExportId::by_name("").is_err());
    assert!(ExportId::by_name("#12").is_err());
    assert!(SyscallId::by_name("Open").is_err());
    assert!(SyscallId::by_name("").is_err());
    assert!(SyscallId::by_name(&"a".repeat(65)).is_err());
    assert!(SectionId::new(1, &long_name).is_err());
    assert!(SetName::new("").is_err());
    assert!(SetName::new("a/b").is_err());
    assert!(SetName::new(&"a".repeat(65)).is_err());
    assert!(TypeRef::named("").is_err());
    assert!(TypeRef::named("#x").is_err());
    assert!(RegVar::new("", 1).is_err());
    assert!(RegVar::new("1ax", 1).is_err());
    assert!(RegVar::new(&"r".repeat(17), 1).is_err());
    let ram = Address::ram(1);
    assert!(RefId::new(ram, ram, "").is_err());
    assert!(RefId::new(ram, ram, "Read").is_err());
    assert!(RefId::new(ram, ram, &"r".repeat(33)).is_err());

    let import = ImportId::pe_by_name("KERNEL32.dll", "ExitProcess").unwrap();
    assert_eq!(import.lib(), Some("kernel32.dll"));
    assert_eq!(import.name(), Some("ExitProcess"));
    assert_eq!(import.ordinal(), None);
    let by_ordinal = ImportId::pe_by_ordinal("alpha.dll", 7).unwrap();
    assert_eq!(by_ordinal.name(), None);
    assert_eq!(by_ordinal.ordinal(), Some(7));
    assert_eq!(ImportId::elf("puts").unwrap().lib(), None);
    assert_eq!(ExportId::by_ordinal(9).ordinal(), Some(9));
    assert_eq!(ExportId::by_name("main").unwrap().name(), Some("main"));
    assert_eq!(SyscallId::by_number(3).number(), Some(3));
    assert_eq!(SyscallId::by_name("read").unwrap().name(), Some("read"));
    assert_eq!(TypeRef::anon(5).hash(), Some(5));
    assert_eq!(TypeRef::named("int").unwrap().name(), Some("int"));
    let section = SectionId::new(14, ".text").unwrap();
    assert_eq!((section.index(), section.name()), (14, ".text"));
    let reference = RefId::new(ram, Address::external(2), "call").unwrap();
    assert_eq!(
        (reference.from(), reference.to(), reference.kind()),
        (ram, Address::external(2), "call")
    );
}

#[test]
fn id_kind_prefixes() {
    let prefixes: Vec<&str> = IdKind::ALL.iter().map(|k| k.prefix()).collect();
    assert_eq!(
        prefixes,
        [
            "fn:", "bb:", "op:", "imp:", "exp:", "sys:", "sec:", "seg:", "str:", "jt:", "ext:",
            "file:", "sym:", "var:", "note:", "set:", "t:", "tx:", "ref:"
        ]
    );
    assert_eq!(IdKind::of_text("tx:4"), Some(IdKind::Tx));
    assert_eq!(IdKind::of_text("t:int"), Some(IdKind::Type));
    assert_eq!(IdKind::of_text("set:a"), Some(IdKind::Set));
    assert_eq!(IdKind::of_text("seg:1"), Some(IdKind::Segment));
    assert_eq!(IdKind::of_text("main"), None);
    assert_eq!(IdKind::Func.to_string(), "fn:");
}

#[test]
fn id_newtype_from_str() {
    assert_eq!("fn:0x10".parse::<FuncId>(), Ok(FuncId(Address::ram(0x10))));
    assert_eq!(
        "bb:0x10".parse::<FuncId>(),
        Err(IdError::WrongKind {
            expected: IdKind::Func,
            found: IdKind::Block,
        })
    );
    assert_eq!("tx:9".parse::<TxId>(), Ok(TxId(9)));
    assert_eq!("note:9".parse::<NoteId>(), Ok(NoteId(9)));
    assert_eq!("seg:9".parse::<SegmentId>(), Ok(SegmentId(9)));
    assert_eq!("file:0x9".parse::<FileOffset>(), Ok(FileOffset(9)));
    assert!("imp:puts".parse::<ImportId>().is_ok());
    assert!("exp:main".parse::<ExportId>().is_ok());
    assert!("sym:main".parse::<SymId>().is_ok());
    assert!("set:s".parse::<SetName>().is_ok());
    assert!("t:int".parse::<TypeRef>().is_ok());
    assert!("sys:read".parse::<SyscallId>().is_ok());
    assert!("sec:1:.a".parse::<SectionId>().is_ok());
    assert!("str:0x1".parse::<StringId>().is_ok());
    assert!("jt:0x1".parse::<JumpTableId>().is_ok());
    assert!("bb:0x1".parse::<BlockId>().is_ok());
    assert!("op:0x1:0".parse::<OpId>().is_ok());
    assert!("var:0x1/ret".parse::<VarId>().is_ok());
    assert!("ref:0x1>0x2:read".parse::<RefId>().is_ok());
    assert_eq!(
        Id::parse("fn:0x10").map(|id| id.address()),
        Ok(Some(Address::ram(0x10)))
    );
    assert_eq!(
        Id::parse("ext:0x10").map(|id| id.address()),
        Ok(Some(Address::external(0x10)))
    );
    assert_eq!(Id::parse("tx:1").map(|id| id.address()), Ok(None));
}

#[test]
fn binary_id_and_rev_forms() {
    let hash = sha256(b"abc");
    let id = BinaryId::from_sha256(&hash);
    assert_eq!(id.to_string(), "ba7816bf8f01cfea");
    assert_eq!(BinaryId::parse("ba7816bf8f01cfea"), Ok(id));
    assert_eq!(BinaryId::parse("BA7816BF8F01CFEA"), Ok(id));
    assert_eq!(
        BinaryId::parse("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        Ok(id)
    );
    assert_eq!("ba7816bf8f01cfea".parse::<BinaryId>(), Ok(id));
    for bad in [
        "",
        "ba7816bf8f01cfe",
        "ba7816bf8f01cfeag",
        "0xba7816bf8f01cfea",
        "ba78 6bf8f01cfea",
    ] {
        assert!(BinaryId::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(Rev(57).to_string(), "57");
    assert_eq!("57".parse::<Rev>(), Ok(Rev(57)));
    assert!("x".parse::<Rev>().is_err());
    assert!("".parse::<Rev>().is_err());
}

#[test]
fn id_error_text() {
    assert_eq!(IdError::Empty.to_string(), "The ID text is empty.");
    assert_eq!(
        IdError::BadPart {
            kind: Some(IdKind::Op),
            part: "sequence",
        }
        .to_string(),
        "The sequence part of the op: ID is not valid."
    );
    assert_eq!(IdError::Empty.code().name(), "INVALID_ARGUMENT");
    assert!(IdError::TooLong { len: 9000 }.to_string().contains("9000"));
    assert!(IdError::UnknownPrefix.to_string().contains("prefix"));
    assert!(
        IdError::WrongKind {
            expected: IdKind::Func,
            found: IdKind::Tx,
        }
        .to_string()
        .contains("tx:")
    );
    assert!(
        IdError::BadPart {
            kind: None,
            part: "address",
        }
        .to_string()
        .contains("address")
    );
}

/// Tells if `text` holds no character that `BinText` escapes, except the backslash of an
/// escape.
fn shows_clean(text: &str) -> bool {
    text.chars().all(|c| c == '\\' || !escapes(c))
}

/// Gives the name IDs of `name`: import, symbol, export and section forms.
fn name_ids(name: &str) -> Vec<Id> {
    let mut out = Vec::new();
    out.extend(ImportId::elf(name).ok().map(Id::Import));
    out.extend(
        ImportId::pe_by_name("kernel32.dll", name)
            .ok()
            .map(Id::Import),
    );
    out.extend(ImportId::pe_by_name(name, "puts").ok().map(Id::Import));
    out.extend(ImportId::pe_by_ordinal(name, 7).ok().map(Id::Import));
    out.extend(SymId::new(name).ok().map(Id::Sym));
    out.extend(ExportId::by_name(name).ok().map(Id::Export));
    out.extend(SectionId::new(3, name).ok().map(Id::Section));
    out
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of hostile names and text forms"
)]
fn regress_hostile_name_id_is_escaped() {
    let tag: String = "IGN"
        .chars()
        .filter_map(|c| char::from_u32(0xe0000 + u32::from(c)))
        .collect();
    let hostile = [
        "\u{1b}[2J".to_owned(),
        "\u{202e}IGN".to_owned(),
        "line\nbreak".to_owned(),
        format!("x{tag}"),
        "\"quoted".to_owned(),
        "back\\slash".to_owned(),
        "\\x1b".to_owned(),
        "\u{1b}!x".to_owned(),
        "a\"b\\c\u{85}\u{7f}\u{0}".to_owned(),
        "\"#12".to_owned(),
        "!\u{feff}".to_owned(),
        "\u{10fffd}\u{e000}\u{ad}".to_owned(),
        "\"".to_owned(),
    ];
    let mut checked = 0;
    for name in &hostile {
        for id in name_ids(name) {
            let text = id.to_string();
            assert!(shows_clean(&text), "{name:?} gives {text:?}");
            assert_eq!(Id::parse(&text), Ok(id.clone()), "{text:?}");
            checked += 1;
        }
    }
    assert!(checked >= 70, "{checked} IDs");
    // The quoted form: a double quote, the name with escapes, and a closing double quote.
    let quoted: [(Id, &str); 9] = [
        (
            Id::Sym(SymId::new("\u{1b}[2J").unwrap()),
            r#"sym:"\x1b[2J""#,
        ),
        (
            Id::Sym(SymId::new("\u{202e}IGN\n").unwrap()),
            r#"sym:"\u{202e}IGN\x0a""#,
        ),
        (Id::Sym(SymId::new("\"q").unwrap()), r#"sym:"\"q""#),
        (
            Id::Sym(SymId::new("back\\slash").unwrap()),
            r#"sym:"back\\slash""#,
        ),
        (
            Id::Import(ImportId::elf("x\u{1b}!y").unwrap()),
            r#"imp:"x\x1b!y""#,
        ),
        (
            Id::Import(ImportId::pe_by_name("Evil\u{1b}.DLL", "a\u{e0049}").unwrap()),
            r#"imp:"evil\x1b.dll"!"a\u{e0049}""#,
        ),
        (
            Id::Import(ImportId::pe_by_ordinal("\"x.dll", 7).unwrap()),
            r#"imp:"\"x.dll"!#7"#,
        ),
        (
            Id::Export(ExportId::by_name("e\u{9f}").unwrap()),
            r#"exp:"e\x9f""#,
        ),
        (
            Id::Section(SectionId::new(3, "s:\u{200b}").unwrap()),
            r#"sec:3:"s:\u{200b}""#,
        ),
    ];
    for (id, text) in quoted {
        assert_eq!(id.to_string(), text, "{id:?}");
        assert_eq!(Id::parse(text), Ok(id), "{text}");
    }
    // Every other name keeps its exact text.
    for (name, text) in [
        ("puts@GLIBC_2.2.5", "sym:puts@GLIBC_2.2.5"),
        ("a\"b", "sym:a\"b"),
        ("caf\u{e9} x!y", "sym:caf\u{e9} x!y"),
    ] {
        assert_eq!(SymId::new(name).unwrap().to_string(), text);
    }
    assert_eq!(ImportId::elf("a!b").unwrap().to_string(), "imp:!a!b");
    assert_eq!(SectionId::new(0, "").unwrap().to_string(), "sec:0:");
    // Input can quote a name that needs no quotes. A bad quoted form gives an error.
    assert_eq!(
        Id::parse(r#"sym:"puts""#),
        Ok(Id::Sym(SymId::new("puts").unwrap()))
    );
    assert_eq!(
        Id::parse(r#"sym:"\u{41}\x42""#),
        Ok(Id::Sym(SymId::new("AB").unwrap()))
    );
    for bad in [
        r#"sym:"open"#,
        r#"sym:"a"b"#,
        r#"sym:"\q""#,
        r#"sym:"\x4""#,
        r#"sym:"\u{d800}""#,
        r#"sym:"\u{110000}""#,
        r#"sym:"\u{41""#,
        r#"sym:"""#,
        r#"imp:"a"b"#,
        r#"imp:"k.dll"!"#,
        r#"exp:"x"y"#,
        r#"sec:1:"x"y"#,
    ] {
        assert!(Id::parse(bad).is_err(), "{bad}");
    }
    // The longest quoted name still parses back.
    let long = "\u{1}".repeat(MAX_NAME_LEN);
    for id in name_ids(&long) {
        assert_eq!(Id::parse(&id.to_string()), Ok(id));
    }
}

/// A name with ASCII white space at its start or end shows in the quoted form. The address
/// parser trims outer white space, so only the quoted form keeps the name (r3-surface-02).
/// White space inside a name keeps the exact text.
#[test]
fn regress_outer_space_name_is_quoted() {
    for (name, text) in [
        ("foo ", r#"sym:"foo ""#),
        (" bar", r#"sym:" bar""#),
        (" ", r#"sym:" ""#),
    ] {
        let id = SymId::new(name).unwrap();
        assert_eq!(id.to_string(), text, "{name:?}");
        assert_eq!(Id::parse(text), Ok(Id::Sym(id.clone())), "{text}");
        assert_eq!(
            ghidorah_base::addr_expr::parse(text),
            Ok(ghidorah_base::AddrExpr::Id(Id::Sym(id))),
            "{text}"
        );
    }
    let section = SectionId::new(2, "sp ").unwrap();
    assert_eq!(section.to_string(), r#"sec:2:"sp ""#);
    assert_eq!(
        ghidorah_base::addr_expr::parse(&section.to_string()),
        Ok(ghidorah_base::AddrExpr::Id(Id::Section(section)))
    );
    assert_eq!(SymId::new("a b").unwrap().to_string(), "sym:a b");
}
