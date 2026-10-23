//! Tests of snapshots: the operation log (AC-120a), the round trip and the checks.

use std::path::Path;

use ghidorah_base::{Address, FuncId, Rev};
use ghidorah_json::Value;

use super::{SnapshotError, decode, encode, inputs_hash, result_hash, write, write_program};
use crate::fs::Fs;
use crate::meta::{MetaLine, apply};
use crate::migrate::ExtMap;
use crate::progress::FuncProgress;
use crate::project::tests::fs_sim::SimFs;
use crate::project::tests::{input, sim};
use crate::source::Source;
use crate::tests::{seeded, session, shard_reader};

#[test]
fn ac_120a_snapshot_op_log() {
    let fs = SimFs::new();
    let dir = Path::new("/p/0011223344556677");
    let mut handle = fs.boxed();
    handle.create_dir_all(dir).unwrap();
    let _ = fs.take_log();
    write(handle.as_mut(), dir, "{}").unwrap();
    let log = fs.take_log();
    // The temporary file has a name of this process: snapshot.json.tmp.<pid>.<n>.
    let tmp = log[0].strip_prefix("create_new ").unwrap();
    let own = format!("snapshot.json.tmp.{}.", std::process::id());
    assert!(tmp.starts_with(&own), "{tmp}");
    assert_eq!(
        log,
        vec![
            format!("create_new {tmp}"),
            format!("write_all {tmp}"),
            format!("sync_file {tmp}"),
            format!("rename {tmp} snapshot.json"),
            "sync_dir 0011223344556677".to_owned(),
        ]
    );
    assert_eq!(fs.get(&dir.join("snapshot.json")), Some(b"{}".to_vec()));
    // The project writes its snapshots with the same sequence.
    let fs = sim(&[100]);
    let (mut project, program, _) = crate::project::tests::create(&fs, 100);
    let _ = fs.take_log();
    project.snapshot(&program).unwrap();
    let log = fs.take_log();
    assert_eq!(log.len(), 5, "no shard: {log:?}");
    assert!(log[0].starts_with("create_new snapshot.json.tmp"));
    assert!(log[4].starts_with("sync_dir"));
}

/// Each new shard file goes in with the steps of AC-120a before the snapshot file. A shard
/// with no change keeps its file, and the file of an old shard goes after the snapshot file.
#[test]
fn ac_120a_shard_files_go_first() {
    let fs = sim(&[100]);
    let (mut project, _, _) = crate::project::tests::create(&fs, 100);
    let mut p = seeded();
    let _ = fs.take_log();
    project.snapshot(&p).unwrap();
    let log = fs.take_log();
    let names = super::files::names(p.analysis());
    assert_eq!(names.len(), 1, "the seeded facts are in shard 0");
    let tmp = log[1].strip_prefix("create_new ").unwrap().to_owned();
    assert!(tmp.starts_with("shard.json.tmp."), "{log:?}");
    let shard_ops = [
        "create_dir_all shards".to_owned(),
        format!("create_new {tmp}"),
        format!("write_all {tmp}"),
        format!("sync_file {tmp}"),
        format!("rename {tmp} {}", names[0]),
        "sync_dir shards".to_owned(),
    ];
    assert_eq!(log[..6], shard_ops, "{log:?}");
    assert!(
        log[6].starts_with("create_new snapshot.json.tmp"),
        "{log:?}"
    );
    assert_eq!(log.len(), 11, "{log:?}");

    project.snapshot(&p).unwrap();
    let log = fs.take_log();
    assert_eq!(
        log.len(),
        5,
        "a shard with no change keeps its file: {log:?}"
    );

    p.analysis_at_mut(Address::ram(0x1080))
        .comments
        .set(
            Address::ram(0x1080),
            crate::comments::CommentKind::Eol,
            Some("sys:write".to_owned()),
            &crate::fact::Origin::analysis(),
        )
        .unwrap();
    project.snapshot(&p).unwrap();
    let log = fs.take_log();
    let new = super::files::names(p.analysis());
    assert_ne!(new, names);
    assert_eq!(log.last(), Some(&format!("remove {}", names[0])), "{log:?}");
    assert!(log.iter().any(|l| l.ends_with(&new[0])), "{log:?}");
}

#[test]
fn snapshot_roundtrip_restores_the_state() {
    let mut p = seeded();
    let func = FuncId(Address::ram(0x1080));
    apply(
        &mut p,
        &MetaLine::Progress {
            func,
            row: FuncProgress {
                visited: true,
                ..FuncProgress::default()
            },
        },
    );
    apply(
        &mut p,
        &MetaLine::Brief {
            session: session("mcp-1"),
            rev: Rev(0),
        },
    );
    let text = encode(&p, 3, Some([5; 32])).unwrap();
    assert_eq!(
        ghidorah_json::write_jcs(&ghidorah_json::parse(&text, &super::SNAPSHOT_LIMITS).unwrap())
            .unwrap(),
        text,
        "JCS text"
    );
    let snap = decode(text.as_bytes(), &ExtMap::default(), &mut shard_reader(&p)).unwrap();
    assert_eq!(snap.journal_lines, 3);
    assert_eq!(snap.analysis_inputs_hash, Some([5; 32]));
    let (_, fresh) = input("hello.gcc-O2");
    let mut target = fresh.clone();
    // The seeded program has one more type than a fresh program.
    assert!(matches!(
        snap.clone().restore(&mut target),
        Err(SnapshotError::Types { .. })
    ));
    assert_eq!(
        target.state_hash(),
        fresh.state_hash(),
        "a failed restore changes nothing"
    );
    let mut same = seeded();
    snap.restore(&mut same).unwrap();
    assert_eq!(same.state_hash(), p.state_hash());
    assert_eq!(same.progress(), p.progress());
    assert_eq!(same.rev(), p.rev());
}

#[test]
fn decode_refuses_bad_snapshots() {
    let mut none = |_: &str| None;
    assert!(matches!(
        decode(b"[1", &ExtMap::default(), &mut none),
        Err(SnapshotError::Json(_))
    ));
    assert!(matches!(
        decode(b"{}", &ExtMap::default(), &mut none),
        Err(SnapshotError::Shape(_))
    ));
    let p = seeded();
    let text = encode(&p, 0, None).unwrap();
    for v in [0u64, 4] {
        let other = text.replacen(
            "\"format_version\":3",
            &format!("\"format_version\":{v}"),
            1,
        );
        assert_eq!(
            decode(other.as_bytes(), &ExtMap::default(), &mut none),
            Err(SnapshotError::Version(v))
        );
    }
    assert!(
        matches!(
            decode(text.as_bytes(), &ExtMap::default(), &mut none),
            Err(SnapshotError::Shard(_))
        ),
        "a missing shard file"
    );
    let (_, mut fresh) = input("crackme.gcc-O2");
    let snap = decode(text.as_bytes(), &ExtMap::default(), &mut shard_reader(&p)).unwrap();
    assert_eq!(snap.restore(&mut fresh), Err(SnapshotError::Binary));
}

#[test]
fn inputs_hash_follows_analysis_inputs() {
    let mut p = seeded();
    let engine = Value::from("v1");
    let config = Value::Null;
    let start = inputs_hash(&p, &engine, &config);
    assert_ne!(start, inputs_hash(&p, &Value::from("v2"), &config));
    // A name does not affect analysis.
    let mut tx = p.begin("t", Source::Agent, session("mcp-1")).unwrap();
    let fact = tx.fact("alpha".to_string());
    tx.apply(crate::edit::Edit::SetName {
        addr: Address::ram(0x1084),
        key: None,
        kind: crate::symbols::SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(inputs_hash(&p, &engine, &config), start);
    // A noreturn flag does.
    let mut tx = p.begin("t", Source::Agent, session("mcp-1")).unwrap();
    let flag = tx.fact(true);
    tx.apply(crate::edit::Edit::SetNoreturn {
        id: FuncId(Address::ram(0x1080)),
        noreturn: Some(flag),
    })
    .unwrap();
    tx.commit().unwrap();
    assert_ne!(inputs_hash(&p, &engine, &config), start);
    assert_ne!(
        result_hash(p.analysis()),
        result_hash(&crate::program::AnalysisSet::default())
    );
}

/// The result hash is the SHA-256 of the shard file names, and each name holds the SHA-256
/// of the JCS text of its shard.
#[test]
fn result_hash_names_the_shard_texts() {
    let mut p = seeded();
    p.analysis_at_mut(Address::ram(0x1080))
        .comments
        .set(
            Address::ram(0x1080),
            crate::comments::CommentKind::Eol,
            Some("sys:write".to_owned()),
            &crate::fact::Origin::analysis(),
        )
        .expect("a comment");
    let set = p.analysis();
    let mut lines = String::new();
    for (name, text) in super::shard_texts(set).unwrap() {
        let (_, hash) = super::parse_name(&name).unwrap();
        assert_eq!(hash, ghidorah_base::sha256(text.as_bytes()));
        lines.push_str(&name);
        lines.push('\n');
    }
    assert_eq!(result_hash(set), ghidorah_base::sha256(lines.as_bytes()));
}

#[test]
fn a_streamed_snapshot_is_the_encoded_text() {
    let p = seeded();
    let fs = SimFs::new();
    let dir = Path::new("/p/0011223344556677");
    let mut handle = fs.boxed();
    handle.create_dir_all(dir).unwrap();
    let inputs = Some([7u8; 32]);
    write_program(handle.as_mut(), dir, &p, 12, inputs).unwrap();
    let text = encode(&p, 12, inputs).unwrap();
    assert_eq!(fs.get(&dir.join("snapshot.json")), Some(text.into_bytes()));
}
