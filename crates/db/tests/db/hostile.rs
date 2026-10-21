//! `Program::from_binary` on hostile symbol tables, and a project directory with planted
//! entries.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ghidorah_base::{Address, Limits};
use ghidorah_db::{Access, LoadSpec, LockInfo, OpenOptions, Program, Project, ProjectMeta, RealFs};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{Loc, Symbol, minimal};

fn program(bytes: &[u8]) -> Program {
    let (binary, mem) = load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Gives the write settings of this process.
fn write_opts() -> OpenOptions {
    let me = ghidorah_db::lock::current(&mut RealFs).unwrap_or(LockInfo {
        pid: 1,
        start_time: 0,
        boot_id: String::new(),
    });
    OpenOptions {
        access: Access::Write { break_lock: false },
        me,
        limits: Limits::DEFAULT,
        engine: Value::Null,
    }
}

/// Plants the symbolic link `entry` -> `victim.txt` in a new project directory of
/// `hello.gcc-O2`. Then it runs `Project::create`. Gives the create result and the victim bytes.
#[cfg(unix)]
fn create_with_planted(name: &str, entry: &str) -> (bool, Vec<u8>) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/hello.gcc-O2");
    let bytes = std::fs::read(&fixture).expect("the fixture");
    let p = program(&bytes);
    let meta = ProjectMeta::new(&p, "hello.gcc-O2", LoadSpec::Auto);
    let base = std::env::temp_dir().join(format!("ghidorah-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("projects");
    let dir = Project::dir_of(&root, meta.binary_id);
    std::fs::create_dir_all(dir.join("bin")).expect("the project directory");
    let victim = base.join("victim.txt");
    std::fs::write(&victim, b"victim original\n").expect("the victim");
    std::os::unix::fs::symlink(&victim, dir.join(entry)).expect("the symbolic link");
    let created = Project::create(Box::new(RealFs), &root, meta, &bytes, &p, &write_opts());
    let refused = created.is_err();
    drop(created);
    let after = std::fs::read(&victim).expect("the victim");
    let _ = std::fs::remove_dir_all(&base);
    (refused, after)
}

#[cfg(unix)]
#[test]
fn regress_planted_journal_symlink_refused() {
    let (refused, victim) = create_with_planted("planted", "journal.jsonl");
    assert!(
        refused,
        "the create refuses a journal that is a symbolic link"
    );
    assert_eq!(
        victim, b"victim original\n",
        "the victim file does not change"
    );
    for entry in [".gitignore", "project.json.tmp", "project.lock"] {
        let (_, victim) = create_with_planted("planted-other", entry);
        assert_eq!(victim, b"victim original\n", "a link at {entry}");
    }
}

#[cfg(unix)]
#[test]
fn planted_project_dir_symlink_refused() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/hello.gcc-O2");
    let bytes = std::fs::read(&fixture).expect("the fixture");
    let p = program(&bytes);
    let meta = ProjectMeta::new(&p, "hello.gcc-O2", LoadSpec::Auto);
    let base = std::env::temp_dir().join(format!("ghidorah-planted-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("projects");
    let victim = base.join("victim");
    std::fs::create_dir_all(&root).expect("the projects root");
    std::fs::create_dir_all(&victim).expect("the victim directory");
    std::os::unix::fs::symlink(&victim, Project::dir_of(&root, meta.binary_id))
        .expect("the symbolic link");
    let created = Project::create(Box::new(RealFs), &root, meta, &bytes, &p, &write_opts());
    assert!(
        created.is_err(),
        "the create refuses a linked project directory"
    );
    let count = std::fs::read_dir(&victim)
        .expect("the victim directory")
        .count();
    assert_eq!(
        count, 0,
        "the create writes nothing in the victim directory"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// The time cap of one load. A linear load takes well below 1 s. The quadratic key search
/// of the parent commit takes about 20 s.
const FLOOD_CAP: Duration = Duration::from_secs(8);

#[test]
fn regress_symbol_flood_loads_in_linear_time() {
    let names = 70_000;
    let mut b = minimal();
    for i in 0..names {
        let name = format!("s{i}");
        b = b
            .symbol(Symbol::func(&name, Loc::section(".text", 0), 1))
            .export(Symbol::func(&name, Loc::section(".text", 0), 1));
    }
    let bytes = b.build();
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("load");
    let start = Instant::now();
    let p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary");
    let took = start.elapsed();
    assert!(took < FLOOD_CAP, "from_binary took {took:?}");

    let at = Address::ram(
        p.binary()
            .entry_points
            .first()
            .map(|e| e.addr)
            .expect("entry"),
    );
    let syms = p.base().symbols();
    let count = syms.at(at).count();
    assert_eq!(
        count,
        usize::from(u16::MAX) + 1,
        "the keys of one address end at u16::MAX"
    );
    assert_eq!(syms.at(at).filter(|s| s.primary).count(), 1);
    assert_eq!(p.addrs_named("_start"), [at]);
}

#[test]
fn bidi_names_keep_their_exact_text() {
    let text = "bad\u{202e}name";
    let b = minimal().symbol(Symbol::func(text, Loc::section(".text", 4), 1));
    let p = program(&b.build());
    let at = p.addrs_named(text);
    assert_eq!(at.len(), 1, "the name index holds the exact text");
    let name = p.name(at[0]).expect("a name");
    assert_eq!(name.text, text);
    assert!(!name.is_default());
}
