//! Tests of the journal line codec and the journal parser.

use ghidorah_base::{Address, FuncId, Rev, TxId};

use super::{
    Journal, JournalError, Line, LineError, RunLine, RunState, TxLine, crc, decode, encode, parse,
};
use crate::edit::Edit;
use crate::meta::MetaLine;
use crate::migrate::ExtMap;
use crate::progress::FuncProgress;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::{seeded, session};

/// Gives one commit line with a rename, and one undo line of it.
fn lines() -> Vec<Line> {
    let mut p = seeded();
    let mut tx = p
        .begin("symbol_rename", Source::Agent, session("mcp-1"))
        .unwrap();
    let fact = tx.fact("alpha".to_string());
    tx.apply(Edit::SetName {
        addr: Address::ram(0x1084),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: vec!["fn:0x1080".to_string()],
    })
    .unwrap();
    let commit = tx.commit().unwrap();
    let original = TxLine::of_commit(&commit);
    let mut undo = original.clone();
    undo.rev = Rev(2);
    undo.tx = TxId(2);
    undo.of = vec![TxId(1)];
    undo.undo_of = vec![TxId(1)];
    vec![
        Line::Tx(Box::new(original)),
        Line::Tx(Box::new(undo)),
        Line::Run(RunLine {
            rev: Rev(3),
            tx: TxId(3),
            state: RunState::BudgetStopped,
            inputs_hash: [1; 32],
            fuel_used: 77,
            result_hash: [2; 32],
        }),
        Line::Meta(MetaLine::Progress {
            func: FuncId(Address::ram(0x1080)),
            row: FuncProgress {
                visited: true,
                named: true,
                typed: false,
                commented: false,
            },
        }),
        Line::Meta(MetaLine::Brief {
            session: session("mcp-1"),
            rev: Rev(3),
        }),
    ]
}

/// Gives the empty `ext:` map.
fn none() -> ExtMap {
    ExtMap::default()
}

/// Gives the line text `line` with a new checksum for its members.
fn with_crc(line: &str) -> String {
    let at = line.rfind(",\"crc\":\"").unwrap();
    let body = format!("{}}}", &line[..at]);
    format!("{},\"crc\":\"{}\"}}", &line[..at], crc(&body))
}

fn text(lines: &[Line]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(encode(line).as_bytes());
        out.push(b'\n');
    }
    out
}

#[test]
fn every_line_kind_roundtrips() {
    for line in lines() {
        let encoded = encode(&line);
        assert!(!encoded.contains('\n'));
        assert_eq!(decode(&encoded, &none()), Ok(line.clone()), "{encoded}");
    }
}

#[test]
fn crc_covers_the_line_text() {
    let line = encode(&lines()[0]);
    let at = line.rfind(",\"crc\":\"").unwrap();
    let body = format!("{}}}", &line[..at]);
    assert_eq!(&line[at + 8..at + 24], crc(&body));
    let changed = line.replacen("alpha", "alphb", 1);
    assert_eq!(decode(&changed, &none()), Err(LineError::Crc));
    let no_crc = body;
    assert_eq!(decode(&no_crc, &none()), Err(LineError::Crc));
}

#[test]
fn parse_reads_lines_and_a_torn_tail() {
    let all = lines();
    let bytes = text(&all);
    assert_eq!(
        parse(&bytes, &none()),
        Ok(Journal {
            lines: all.clone(),
            valid_len: bytes.len(),
            torn: false
        })
    );
    let mut torn = bytes.clone();
    torn.extend_from_slice(b"{\"v\":1,\"rev\"");
    let parsed = parse(&torn, &none()).unwrap();
    assert!(parsed.torn);
    assert_eq!(parsed.valid_len, bytes.len());
    assert_eq!(parsed.lines, all);
    assert_eq!(parse(b"", &none()), Ok(Journal::default()));
}

#[test]
fn parse_reports_the_first_bad_line() {
    let all = lines();
    let mut bytes = text(&all[..2]);
    bytes.extend_from_slice(b"not json\n");
    bytes.extend_from_slice(&text(&all[2..]));
    match parse(&bytes, &none()) {
        Err(JournalError::Corrupt { line: 3, .. }) => {}
        other => panic!("{other:?}"),
    }
    let mut empty = text(&all[..1]);
    empty.extend_from_slice(b"\n");
    empty.extend_from_slice(&text(&all[1..2]));
    assert!(matches!(
        parse(&empty, &none()),
        Err(JournalError::Corrupt { line: 2, .. })
    ));
    for v in ["\"v\":0", "\"v\":3"] {
        let other_version = with_crc(&encode(&all[0]).replacen("\"v\":2", v, 1));
        assert!(matches!(
            decode(&other_version, &none()),
            Err(LineError::Version(_))
        ));
    }
}

/// A version 1 line decodes. Each `ext:` address of its edits maps to its new address. A
/// version 2 line keeps its addresses.
#[test]
fn v1_line_gets_new_ext_addresses() {
    let map = ExtMap::from_pairs([(Address::external(1), Address::external(2))]);
    let v2 = with_crc(&encode(&lines()[0]).replacen("\"fn:0x1080\"", "\"ext:0x1\"", 1));
    let v1 = with_crc(&v2.replacen("\"v\":2", "\"v\":1", 1));
    let evidence = |text: &str| match decode(text, &map) {
        Ok(Line::Tx(t)) => match &t.edits[0].edit {
            Edit::SetName { evidence, .. } => evidence.clone(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    assert_eq!(evidence(&v1), ["ext:0x2"]);
    assert_eq!(evidence(&v2), ["ext:0x1"]);
}

#[test]
fn hostile_bytes_never_panic() {
    let mut g = ghidorah_testkit::rng::SplitMix64::new(7);
    let base = text(&lines());
    for _ in 0..300 {
        let mut bytes = base.clone();
        for _ in 0..4 {
            let at = usize::try_from(g.next_const() % u64::try_from(bytes.len()).unwrap()).unwrap();
            bytes[at] = u8::try_from(g.next_const() % 256).unwrap();
        }
        let _ = parse(&bytes, &none());
    }
}
