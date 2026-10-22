//! Tests of the project directory: replay (AC-117), the torn tail (AC-119a), a corrupt line
//! (AC-119b), crash consistency (AC-120b), the golden v1 project (AC-120c), the lock (AC-124),
//! project safety (AC-125), forward undo (AC-128b) and the snapshot cadence. The `migrate`
//! module tests a version 1 project.

mod migrate;

#[path = "../../tests/common/fs_sim.rs"]
pub(crate) mod fs_sim;

use std::path::{Path, PathBuf};

use ghidorah_base::{Address, ErrorCode, Limits, Rev, TxId};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::pbt::check;
use ghidorah_types::Prim;

use self::fs_sim::SimFs;
use super::{
    Access, LoadSpec, OpenOptions, Opened, Project, ProjectError, ProjectMeta, SNAPSHOT_EVERY,
    check_root, list,
};
use crate::edit::Edit;
use crate::fs::{EntryKind, Fs, FsError};
use crate::hash::StateHash;
use crate::history::{History, Scope};
use crate::journal::{JOURNAL_FILE, Line, TxLine};
use crate::lock::{BOOT_ID_FILE, LOCK_FILE, LockInfo};
use crate::meta::MetaLine;
use crate::migrate::ExtMap;
use crate::program::Program;
use crate::progress::FuncProgress;
use crate::snapshot::SNAPSHOT_FILE;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::ops::{Pools, base_edit};
use crate::tests::session;
use crate::tx::Commit;
use crate::undo::{UndoRequest, run};

/// The projects root of the simulated file system.
pub(crate) const ROOT: &str = "/data/projects";

/// The boot ID of the simulated process files.
pub(crate) const BOOT: &str = "4b2c0d6e-boot";

/// Gives the lock owner of the simulated process `pid`.
pub(crate) fn me(pid: u32) -> LockInfo {
    LockInfo {
        pid,
        start_time: 1000 + u64::from(pid),
        boot_id: BOOT.to_owned(),
    }
}

/// Gives a `/proc/<pid>/stat` text with the start time `start`. The name holds a `)`.
pub(crate) fn stat_line(pid: u32, start: u64) -> String {
    let middle: Vec<String> = (4..=21).map(|n| n.to_string()).collect();
    format!("{pid} (ghi (worker)) S {} {start} 0 0\n", middle.join(" "))
}

/// Makes the process `pid` alive in `fs`.
pub(crate) fn alive(fs: &SimFs, pid: u32) {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    fs.seed(&path, stat_line(pid, me(pid).start_time).as_bytes());
}

/// Gives a simulated file system with the boot ID and the live processes `pids`.
pub(crate) fn sim(pids: &[u32]) -> SimFs {
    let fs = SimFs::new();
    fs.seed(Path::new(BOOT_ID_FILE), format!("{BOOT}\n").as_bytes());
    for pid in pids {
        alive(&fs, *pid);
    }
    fs
}

/// Gives the bytes and a fresh program of a fixture.
pub(crate) fn input(name: &str) -> (Vec<u8>, Program) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bin")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).unwrap();
    let program = Program::from_binary(binary, mem, &Limits::DEFAULT).unwrap();
    (bytes, program)
}

/// Gives the open settings of the process `pid`.
pub(crate) fn opts(access: Access, pid: u32) -> OpenOptions {
    OpenOptions {
        access,
        me: me(pid),
        limits: Limits::DEFAULT,
        engine: Value::Null,
    }
}

fn write(pid: u32) -> OpenOptions {
    opts(Access::Write { break_lock: false }, pid)
}

/// Makes the project of `hello.gcc-O2` in `fs` for the process `pid`.
pub(crate) fn create(fs: &SimFs, pid: u32) -> (Project, Program, PathBuf) {
    let (bytes, program) = input("hello.gcc-O2");
    let meta = ProjectMeta::new(&program, "hello.gcc-O2", LoadSpec::Auto);
    let dir = Project::dir_of(Path::new(ROOT), meta.binary_id);
    let project = Project::create(
        fs.boxed(),
        Path::new(ROOT),
        meta,
        &bytes,
        &program,
        &write(pid),
    )
    .unwrap();
    (project, program, dir)
}

fn hash(p: &Program) -> StateHash {
    p.state_hash().unwrap()
}

/// Journals a commit and records it.
fn journal(project: &mut Project, h: &mut History, p: &Program, commit: &Commit) {
    let line = TxLine::of_commit(commit);
    project
        .append(&Line::Tx(Box::new(line.clone())), p)
        .unwrap();
    h.record(&line);
}

/// Commits a rename of `addr` and journals it.
pub(crate) fn rename(
    p: &mut Program,
    project: &mut Project,
    h: &mut History,
    addr: u64,
    name: &str,
) -> Commit {
    let mut tx = p
        .begin("symbol_rename", Source::Agent, session("mcp-1"))
        .unwrap();
    let fact = tx.fact(name.to_string());
    tx.apply(Edit::SetName {
        addr: Address::ram(addr),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .unwrap();
    let commit = tx.commit().unwrap();
    journal(project, h, p, &commit);
    commit
}

fn reopen(fs: &SimFs, dir: &Path, options: &OpenOptions) -> Result<Opened, ProjectError> {
    Project::open(fs.boxed(), dir, options)
}

#[test]
fn create_then_open_keeps_the_state() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut h = History::new();
    rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    rename(&mut p, &mut project, &mut h, 0x1088, "beta");
    drop(project);
    assert!(
        fs.get(&dir.join(LOCK_FILE)).is_none(),
        "a drop releases the lock"
    );
    let opened = reopen(&fs, &dir, &write(100)).unwrap();
    assert_eq!(hash(&opened.program), hash(&p));
    assert_eq!(opened.program.rev(), Rev(2));
    assert_eq!(opened.history.entries().count(), 2);
    assert!(!opened.tail_discarded);
    assert_eq!(opened.project.lines(), 2);
}

#[test]
fn ac_117_journal_replay() {
    let (_, start) = input("hello.gcc-O2");
    let long = start.types().store().prim(Prim::Long);
    let pools = Pools::of(&start, long);
    check("ac_117_journal_replay", 16, |g| {
        let fs = sim(&[100]);
        let (mut project, mut p, dir) = create(&fs, 100);
        let mut h = History::new();
        for _ in 0..=g.draw(30) {
            if g.draw(5) == 0 {
                let req = UndoRequest {
                    scope: Scope::All,
                    tx: None,
                    count: 1,
                    redo: g.bool(),
                    force: true,
                    dry_run: false,
                    source: Source::Agent,
                    session: session("mcp-2"),
                };
                if let Ok(out) = run(&mut p, &h, &req)
                    && let Some(line) = out.line
                {
                    project
                        .append(&Line::Tx(Box::new(line.clone())), &p)
                        .map_err(|e| e.to_string())?;
                    h.record(&line);
                }
                continue;
            }
            let mut tx = p.begin("model", Source::Agent, session("mcp-1")).unwrap();
            for _ in 0..=g.draw(2) {
                let kind = g.draw(14);
                let edit = base_edit(g, &tx, &pools, kind);
                let _ = tx.apply(edit);
            }
            let commit = tx.commit().map_err(|e| e.to_string())?;
            if !commit.noop {
                journal(&mut project, &mut h, &p, &commit);
            }
        }
        drop(project);
        let mut raw = fs.boxed();
        let _ = raw.remove(&dir.join(SNAPSHOT_FILE));
        let opened = reopen(&fs, &dir, &write(100)).map_err(|e| e.to_string())?;
        if hash(&opened.program) != hash(&p) || opened.program.rev() != p.rev() {
            return Err("replay from an empty project differs".to_owned());
        }
        if opened.history != h {
            return Err("the history of the journal differs".to_owned());
        }
        Ok(())
    });
}

#[test]
fn ac_119a_journal_tail() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut h = History::new();
    rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    rename(&mut p, &mut project, &mut h, 0x1088, "beta");
    let two = hash(&p);
    rename(&mut p, &mut project, &mut h, 0x108c, "gamma");
    drop(project);
    let path = dir.join(JOURNAL_FILE);
    let text = fs.get(&path).unwrap();
    let body = &text[..text.len() - 1];
    let start = body.iter().rposition(|b| *b == b'\n').unwrap() + 1;
    let last = body.len() - start;
    for k in 0..=last + 1 {
        let image = fs.crash_image();
        let mut cut = text[..start].to_vec();
        cut.extend_from_slice(&text[start..(start + k).min(text.len())]);
        image.boxed().write_all(&path, &cut).unwrap();
        let opened = reopen(&image, &dir, &write(100)).unwrap();
        let torn = k > 0 && k <= last;
        assert_eq!(opened.tail_discarded, torn, "cut at {k}");
        if k <= last {
            assert_eq!(hash(&opened.program), two, "cut at {k}");
            assert_eq!(
                image.get(&path).unwrap(),
                text[..start].to_vec(),
                "repair at {k}"
            );
        } else {
            assert_eq!(opened.program.rev(), Rev(3), "full line");
        }
    }
    // A read-only open drops the tail and writes nothing.
    let image = fs.crash_image();
    let mut cut = text[..start].to_vec();
    cut.extend_from_slice(&text[start..start + 9]);
    image.boxed().write_all(&path, &cut).unwrap();
    let opened = reopen(&image, &dir, &opts(Access::ReadOnly, 100)).unwrap();
    assert!(opened.tail_discarded);
    assert_eq!(image.get(&path).unwrap(), cut);
}

#[test]
fn ac_119b_journal_corrupt() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut h = History::new();
    for (i, addr) in [0x1084, 0x1088, 0x108c].into_iter().enumerate() {
        rename(&mut p, &mut project, &mut h, addr, &format!("n{i}"));
    }
    drop(project);
    let path = dir.join(JOURNAL_FILE);
    let mut text = fs.get(&path).unwrap();
    let second = text.iter().position(|b| *b == b'\n').unwrap() + 12;
    text[second] = if text[second] == b'1' { b'2' } else { b'1' };
    fs.boxed().write_all(&path, &text).unwrap();
    let _ = fs.boxed().remove(&dir.join(SNAPSHOT_FILE));
    let error = reopen(&fs, &dir, &write(100)).unwrap_err();
    assert_eq!(error, ProjectError::Corrupt { line: 2 });
    assert_eq!(error.code(), ErrorCode::JournalCorrupt);
}

/// Runs `step` on a copy of `base` with a crash after each operation count. Each reopen gives
/// the hash before or after.
fn crash_each(base: &SimFs, dir: &Path, step: &dyn Fn(&mut Project, &mut Program)) -> usize {
    let mut k = 0;
    loop {
        let fs = base.crash_image();
        let mut opened = reopen(&fs, dir, &write(100)).unwrap();
        let before = hash(&opened.program);
        let ops = fs.ops();
        fs.stop_after(k);
        step(&mut opened.project, &mut opened.program);
        let after = hash(&opened.program);
        let used = fs.ops() - ops;
        let image = fs.crash_image();
        let again = reopen(&image, dir, &opts(Access::ReadOnly, 200)).unwrap();
        let got = hash(&again.program);
        assert!(got == before || got == after, "crash after {k} operations");
        if used < k || k > 16 {
            assert_eq!(got, after, "a step with no crash keeps its effect");
            return k;
        }
        k += 1;
    }
}

#[test]
fn ac_120b_crash_consistency() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut h = History::new();
    rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    drop(project);
    let commit_ops = crash_each(&fs, &dir, &|project, p| {
        let mut tx = p
            .begin("symbol_rename", Source::Agent, session("mcp-1"))
            .unwrap();
        let fact = tx.fact("beta".to_string());
        tx.apply(Edit::SetName {
            addr: Address::ram(0x1088),
            key: None,
            kind: SymKind::Label,
            primary: true,
            name: Some(fact),
            evidence: Vec::new(),
        })
        .unwrap();
        let commit = tx.commit().unwrap();
        let line = TxLine::of_commit(&commit);
        let _ = project.append(&Line::Tx(Box::new(line)), p);
    });
    assert!(commit_ops >= 2, "{commit_ops}");
    let snapshot_ops = crash_each(&fs, &dir, &|project, p| {
        let _ = project.snapshot(p);
    });
    assert!(snapshot_ops >= 5, "{snapshot_ops}");
}

/// The golden v1 project: the demo binary with a rename, a note, an undone comment and two
/// meta lines.
fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/projects/v1")
}

/// The golden v1 project loads (AC-120c). A bless does not write it again: version 1 is
/// frozen. The `ext:` facts of its snapshot move to the address of their import ID.
#[test]
fn ac_120c_golden_v1() {
    let dir = golden_dir().join("467a43b75d95c826");
    let mut fs = crate::fs::RealFs;
    let opened = Project::open(fs.boxed(), &dir, &opts(Access::ReadOnly, 1)).unwrap();
    let p = &opened.program;
    assert_eq!(p.rev(), Rev(4));
    assert_eq!(opened.project.meta().format_version, 1);
    let name = p
        .base()
        .symbols()
        .primary(Address::ram(0x1090))
        .map(|s| s.name.value.clone());
    assert_eq!(name.as_deref(), Some("read_input"));
    assert_eq!(p.notes().iter().count(), 1);
    let comment = p
        .base()
        .comments()
        .get(Address::ram(0x11e4), crate::comments::CommentKind::Eol);
    assert!(comment.is_none(), "the undo removed the comment");
    let func = ghidorah_base::FuncId(Address::ram(0x11e0));
    assert!(p.progress().get(func).visited);
    assert_eq!(
        p.progress()
            .mark(&session("mcp-1"))
            .map(|m| m.last_brief_rev),
        Some(Rev(4))
    );
    assert_eq!(opened.history.mcp_labels(), 1);
    // The v1 snapshot holds the import labels in import order: `__libc_start_main` at
    // `ext:0x1`. Each one moves to the address of its import ID.
    assert!(
        !ExtMap::of(p).is_empty(),
        "the import order is not the ID order"
    );
    for row in p.imports().values() {
        let label = p
            .base()
            .symbols()
            .primary(row.ext)
            .map(|s| s.name.value.clone());
        assert_eq!(label.as_deref(), row.id.name(), "{}", row.id);
    }
    assert!(Project::exists(&mut fs, &dir));
    assert!(
        !dir.join(LOCK_FILE).exists(),
        "a read-only open takes no lock"
    );
}

#[test]
fn ac_124_project_lock() {
    let fs = sim(&[100, 200]);
    let (project, _, dir) = create(&fs, 100);
    let held = reopen(&fs, &dir, &write(200)).unwrap_err();
    assert_eq!(
        held,
        ProjectError::Locked {
            owner: Some(me(100)),
            stale: false
        }
    );
    assert_eq!(held.code(), ErrorCode::ProjectLocked);
    let mut reader = reopen(&fs, &dir, &opts(Access::ReadOnly, 200)).unwrap();
    assert!(reader.project.is_read_only());
    let line = Line::Meta(MetaLine::Brief {
        session: session("mcp-1"),
        rev: Rev(0),
    });
    assert_eq!(
        reader.project.append(&line, &reader.program),
        Err(ProjectError::ReadOnly)
    );
    // The owner stops with no clean close: the lock stays, and its process is gone.
    std::mem::forget(project);
    let _ = fs.boxed().remove(Path::new("/proc/100/stat"));
    let stale = reopen(&fs, &dir, &write(200)).unwrap_err();
    assert_eq!(
        stale,
        ProjectError::Locked {
            owner: Some(me(100)),
            stale: true
        }
    );
    let broken = reopen(&fs, &dir, &opts(Access::Write { break_lock: true }, 200)).unwrap();
    let lock = fs.get(&dir.join(LOCK_FILE)).unwrap();
    let owner = LockInfo::from_json(
        &ghidorah_json::parse(
            &String::from_utf8(lock).unwrap(),
            &ghidorah_json::Limits::DEFAULT,
        )
        .unwrap(),
    );
    assert_eq!(owner, Some(me(200)));
    drop(broken);
    assert!(
        fs.get(&dir.join(LOCK_FILE)).is_none(),
        "the new owner releases the lock"
    );
}

#[test]
fn ac_125_project_safety() {
    let fs = sim(&[100]);
    fs.seed(Path::new("/work/repo/.git/HEAD"), b"ref: main\n");
    let mut raw = fs.boxed();
    let inside = Path::new("/work/repo/.cache/projects");
    assert_eq!(
        check_root(raw.as_mut(), inside, false),
        Err(ProjectError::InsideGitTree(inside.to_path_buf()))
    );
    assert_eq!(check_root(raw.as_mut(), inside, true), Ok(()));
    assert_eq!(check_root(raw.as_mut(), Path::new(ROOT), false), Ok(()));
    let (_project, program, dir) = create(&fs, 100);
    assert_eq!(fs.get(&dir.join(".gitignore")), Some(b"*\n".to_vec()));
    let sha = ghidorah_base::hex::encode(&program.meta().sha256);
    let copy = dir.join("bin").join(&sha);
    assert!(fs.is_read_only(&copy), "the input copy has mode 0444");
    assert_eq!(fs.get(&copy), Some(input("hello.gcc-O2").0));
    // The real file system gives the input copy the mode 0444.
    let tmp = std::env::temp_dir().join(format!("ghidorah-ac125-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (bytes, real) = input("hello.gcc-O2");
    let meta = ProjectMeta::new(&real, "hello.gcc-O2", LoadSpec::Auto);
    let mut me_now = crate::fs::RealFs;
    let owner = crate::lock::current(&mut me_now).unwrap_or_else(|| me(1));
    let mut options = write(1);
    options.me = owner;
    let created = Project::create(
        Box::new(crate::fs::RealFs),
        &tmp,
        meta,
        &bytes,
        &real,
        &options,
    )
    .unwrap();
    let file = created.dir().join("bin").join(&sha);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(bits & 0o777, 0o444);
    }
    drop(created);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The number of rounds of the create race.
const RACE_ROUNDS: usize = 32;

/// The number of threads of one create race.
const RACE_THREADS: usize = 8;

/// Makes the project of `program` on the real file system, then commits one rename.
fn create_and_rename(
    root: &Path,
    bytes: &[u8],
    program: &mut Program,
    options: &OpenOptions,
) -> Result<(), String> {
    let meta = ProjectMeta::new(program, "hello.gcc-O2", LoadSpec::Auto);
    let mut project = Project::create(
        Box::new(crate::fs::RealFs),
        root,
        meta,
        bytes,
        program,
        options,
    )
    .map_err(|e| e.to_string())?;
    let mut tx = program
        .begin("symbol_rename", Source::Agent, session("mcp-1"))
        .map_err(|e| e.to_string())?;
    let fact = tx.fact("alpha".to_string());
    tx.apply(Edit::SetName {
        addr: Address::ram(0x1084),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .map_err(|e| e.to_string())?;
    let commit = tx.commit().map_err(|e| e.to_string())?;
    let line = Line::Tx(Box::new(TxLine::of_commit(&commit)));
    project.append(&line, program).map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn regress_concurrent_create_has_one_writer() {
    let (bytes, program) = input("hello.gcc-O2");
    let mut real = crate::fs::RealFs;
    let mut options = write(1);
    options.me = crate::lock::current(&mut real).unwrap_or_else(|| me(1));
    let id = program.meta().binary_id;
    for round in 0..RACE_ROUNDS {
        let root =
            std::env::temp_dir().join(format!("ghidorah-race-{}-{round}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let start = std::sync::Arc::new(std::sync::Barrier::new(RACE_THREADS));
        // All threads start before the first join, so the barrier opens.
        let mut threads = Vec::new();
        for _ in 0..RACE_THREADS {
            let (root, bytes, options) = (root.clone(), bytes.clone(), options.clone());
            let (start, mut program) = (start.clone(), program.clone());
            threads.push(std::thread::spawn(move || {
                start.wait();
                create_and_rename(&root, &bytes, &mut program, &options)
            }));
        }
        let results: Vec<Result<(), String>> =
            threads.into_iter().map(|t| t.join().unwrap()).collect();
        let writers = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(writers, 1, "round {round}: {results:?}");
        let dir = Project::dir_of(&root, id);
        let text = std::fs::read(dir.join(JOURNAL_FILE)).unwrap();
        let revs: Vec<Rev> = crate::journal::parse(&text, &crate::migrate::ExtMap::default())
            .unwrap()
            .lines
            .iter()
            .filter_map(Line::rev)
            .collect();
        assert_eq!(revs, vec![Rev(1)], "round {round}: one rev line");
        let opened = Project::open(Box::new(crate::fs::RealFs), &dir, &options).unwrap();
        assert_eq!(opened.program.rev(), Rev(1));
        drop(opened);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn regress_failed_append_leaves_no_partial_line() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let path = dir.join(JOURNAL_FILE);
    let visited = Line::Meta(MetaLine::Progress {
        func: ghidorah_base::FuncId(Address::ram(0x1080)),
        row: FuncProgress {
            visited: true,
            ..FuncProgress::default()
        },
    });
    // A full disk: the meta line goes in part, and the append fails.
    fs.tear_next_append();
    assert!(project.append(&visited, &p).is_err());
    let mut h = History::new();
    rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    let text = fs.get(&path).unwrap();
    let journal = crate::journal::parse(&text, &crate::migrate::ExtMap::default()).unwrap();
    assert_eq!(journal.lines.len(), 1, "only the good commit");
    assert!(!journal.torn);
    drop(project);
    let opened = reopen(&fs, &dir, &write(100)).unwrap();
    assert_eq!(opened.program.rev(), Rev(1));
    assert_eq!(hash(&opened.program), hash(&p));
    assert!(!opened.tail_discarded);
}

#[test]
fn failed_cut_stops_the_project_until_a_reload() {
    let fs = sim(&[100]);
    let (mut project, p, dir) = create(&fs, 100);
    let path = dir.join(JOURNAL_FILE);
    let brief = Line::Meta(MetaLine::Brief {
        session: session("mcp-1"),
        rev: Rev(0),
    });
    project.append(&brief, &p).unwrap();
    let good = fs.get(&path).unwrap();
    // The short write works, and the cut after it fails.
    fs.tear_next_append();
    fs.stop_after(1);
    let first = project.append(&brief, &p).unwrap_err();
    fs.resume();
    let torn = fs.get(&path).unwrap();
    assert!(torn.len() > good.len(), "the cut failed");
    let ops = fs.ops();
    assert_eq!(project.append(&brief, &p), Err(first.clone()));
    assert_eq!(project.snapshot(&p), Err(first));
    assert_eq!(fs.ops(), ops, "a stopped project writes nothing");
    assert_eq!(fs.get(&path).unwrap(), torn);
    // A reload repairs the torn tail, and the project works again.
    let loaded = project.load(&Limits::DEFAULT).unwrap();
    assert!(loaded.tail_discarded);
    assert_eq!(fs.get(&path).unwrap(), good);
    project.append(&brief, &p).unwrap();
    let journal =
        crate::journal::parse(&fs.get(&path).unwrap(), &crate::migrate::ExtMap::default()).unwrap();
    assert_eq!(journal.lines.len(), 2);
    assert!(!journal.torn);
    // A failed sync and a failed cut also stop the project.
    fs.stop_after(1);
    assert!(project.append(&brief, &p).is_err());
    fs.resume();
    assert!(project.append(&brief, &p).is_err(), "the cut also failed");
}

#[test]
fn ac_128b_forward_undo() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut h = History::new();
    let first = rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    let path = dir.join(JOURNAL_FILE);
    let before = fs.get(&path).unwrap();
    let req = UndoRequest {
        scope: Scope::Session(session("mcp-1")),
        tx: None,
        count: 1,
        redo: false,
        force: false,
        dry_run: false,
        source: Source::Agent,
        session: session("mcp-1"),
    };
    let out = run(&mut p, &h, &req).unwrap();
    let line = out.line.unwrap();
    project
        .append(&Line::Tx(Box::new(line.clone())), &p)
        .unwrap();
    h.record(&line);
    let after = fs.get(&path).unwrap();
    assert!(after.len() > before.len());
    assert_eq!(
        &after[..before.len()],
        &before[..],
        "the journal never gets shorter"
    );
    assert_eq!(line.undo_of, vec![first.tx]);
    assert_eq!(line.tx, TxId(2));
    assert_eq!(p.rev(), Rev(2), "rev only increases");
    assert_eq!(h.lines().len(), 2);
}

#[test]
fn snapshot_every_256_lines() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let mut snapshots = Vec::new();
    for i in 0..300u64 {
        let name = if i % 2 == 0 { "even" } else { "odd" };
        let mut tx = p
            .begin("symbol_rename", Source::Agent, session("mcp-1"))
            .unwrap();
        let fact = tx.fact(name.to_string());
        tx.apply(Edit::SetName {
            addr: Address::ram(0x1084),
            key: None,
            kind: SymKind::Label,
            primary: true,
            name: Some(fact),
            evidence: Vec::new(),
        })
        .unwrap();
        let commit = tx.commit().unwrap();
        let line = Line::Tx(Box::new(TxLine::of_commit(&commit)));
        if project.append(&line, &p).unwrap() {
            snapshots.push(i + 1);
        }
    }
    assert_eq!(snapshots, vec![SNAPSHOT_EVERY]);
    let text = fs.get(&dir.join(SNAPSHOT_FILE)).unwrap();
    let snap = crate::snapshot::decode(&text, &crate::migrate::ExtMap::default()).unwrap();
    assert_eq!(snap.rev, Rev(SNAPSHOT_EVERY));
    assert_eq!(snap.journal_lines, SNAPSHOT_EVERY);
    drop(project);
    let opened = reopen(&fs, &dir, &write(100)).unwrap();
    assert_eq!(hash(&opened.program), hash(&p));
}

#[test]
fn meta_lines_and_runs_after_the_snapshot() {
    let fs = sim(&[100]);
    let (mut project, mut p, dir) = create(&fs, 100);
    let func = ghidorah_base::FuncId(Address::ram(0x1080));
    let row = FuncProgress {
        visited: true,
        ..FuncProgress::default()
    };
    let line = MetaLine::Progress { func, row };
    crate::meta::apply(&mut p, &line);
    project.append(&Line::Meta(line), &p).unwrap();
    project.snapshot(&p).unwrap();
    let marker = crate::journal::RunLine {
        rev: Rev(1),
        tx: TxId(1),
        state: crate::journal::RunState::Complete,
        inputs_hash: [7; 32],
        fuel_used: 12,
        result_hash: [9; 32],
    };
    crate::replay::skip_to(&mut p, Rev(1), TxId(1));
    project.append(&Line::Run(marker), &p).unwrap();
    drop(project);
    let opened = reopen(&fs, &dir, &write(100)).unwrap();
    assert!(opened.program.progress().get(func).visited);
    assert_eq!(opened.program.rev(), Rev(1));
    assert!(
        opened.analysis.behind,
        "the run after the snapshot is not in the snapshot"
    );
    assert!(!opened.analysis.current);
    assert_eq!(opened.analysis.last_run, Some(marker));
}

#[test]
fn crash_records_and_project_list() {
    let fs = sim(&[100]);
    let (mut project, mut p, _dir) = create(&fs, 100);
    let mut h = History::new();
    rename(&mut p, &mut project, &mut h, 0x1084, "alpha");
    let record = Value::object([("tool", Value::from("test_boom"))]);
    let path = project.write_crash("00ff00ff00ff00ff", &record).unwrap();
    assert_eq!(path, "crash/00ff00ff00ff00ff.json");
    let found = list(fs.boxed().as_mut(), Path::new(ROOT));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rev, Rev(1));
    assert_eq!(found[0].file_name, "hello.gcc-O2");
    assert_eq!(found[0].last_session.as_deref(), Some("mcp-1"));
}

#[test]
fn project_meta_roundtrip_and_errors() {
    let (_, program) = input("hello.gcc-O2");
    let meta = ProjectMeta::new(
        &program,
        "hello.gcc-O2",
        LoadSpec::Raw {
            base: 0x40_0000,
            entry: Some(0x40_1000),
        },
    );
    assert_eq!(ProjectMeta::from_json(&meta.to_json()), Ok(meta.clone()));
    let mut wrong = meta.to_json();
    if let Some(o) = wrong.as_object_mut() {
        o.insert("format_version", Value::from(9u64));
    }
    assert!(ProjectMeta::from_json(&wrong).is_err());
    let fs = sim(&[100]);
    let missing = reopen(
        &fs,
        Path::new("/data/projects/0011223344556677"),
        &write(100),
    );
    assert!(missing.is_err());
}

/// Makes the project of `hello.gcc-O2` for the process `pid` with `--break-lock`.
fn create_breaking(fs: &SimFs, pid: u32) -> Result<(Project, Program), ProjectError> {
    let (bytes, program) = input("hello.gcc-O2");
    let meta = ProjectMeta::new(&program, "hello.gcc-O2", LoadSpec::Auto);
    let options = opts(Access::Write { break_lock: true }, pid);
    let project = Project::create(
        fs.boxed(),
        Path::new(ROOT),
        meta,
        &bytes,
        &program,
        &options,
    )?;
    Ok((project, program))
}

/// Gives the names of the temporary files of the process `pid` in `dir`.
fn temps_of(fs: &SimFs, dir: &Path, pid: u32) -> Vec<String> {
    let mark = format!(".tmp.{pid}.");
    let names = fs.boxed().list(dir).unwrap_or_default();
    names.into_iter().filter(|n| n.contains(&mark)).collect()
}

#[test]
fn regress_stale_temp_removed_on_open() {
    // A writer that dies, a live process and the process of the next open. No ID is the ID
    // of the test process.
    let me = std::process::id();
    let pids: Vec<u32> = (7..).filter(|p| *p != me).take(3).collect();
    let (dead, live, next) = (pids[0], pids[1], pids[2]);
    let fs = sim(&[live, next]);
    let (_, program) = input("hello.gcc-O2");
    let sha = ghidorah_base::hex::encode(&program.meta().sha256);
    let dir = Project::dir_of(Path::new(ROOT), program.meta().binary_id);
    let bin = dir.join(super::BIN_DIR);
    // Crashes between create_temp and rename: the input copy, then the project file.
    fs.crash_after(&format!("create_new {sha}.tmp."));
    assert!(create_breaking(&fs, dead).is_err());
    fs.resume();
    fs.crash_after("create_new project.json.tmp.");
    assert!(create_breaking(&fs, dead).is_err());
    fs.resume();
    // A complete project, then a crash between create_temp and rename of the snapshot.
    let (mut project, program) = create_breaking(&fs, dead).unwrap();
    fs.crash_after("create_new snapshot.json.tmp.");
    assert!(project.snapshot(&program).is_err());
    drop(project);
    fs.resume();
    // The test process stays alive, so its temporary files get the ID of the dead writer.
    let mut raw = fs.boxed();
    let mut moved = Vec::new();
    for d in [&dir, &bin] {
        for name in temps_of(&fs, d, me) {
            let to = name.replacen(&format!(".tmp.{me}."), &format!(".tmp.{dead}."), 1);
            raw.rename(&d.join(&name), &d.join(&to)).unwrap();
            moved.push(to);
        }
    }
    assert_eq!(moved.len(), 3, "one temporary file per crash: {moved:?}");
    let stale = [
        format!("project.lock.tmp.{dead}.40"),
        format!("journal.jsonl.tmp.{dead}.41"),
        format!(".gitignore.tmp.{dead}.42"),
    ];
    // The files of live processes and the names of another shape stay.
    let keep = [
        format!("snapshot.json.tmp.{live}.0"),
        format!("project.json.tmp.{me}.99"),
        "snapshot.json.tmp.99999999999999999999.1".to_owned(),
        "snapshot.json.tmp.5.99999999999999999999".to_owned(),
        "snapshot.json.tmp.+5.0".to_owned(),
        "snapshot.json.tmp.05.0".to_owned(),
        "snapshot.json.tmp.5".to_owned(),
        "snapshot.json.tmp.5.".to_owned(),
        "snapshot.json.tmp..0".to_owned(),
        "snapshot.json.tmp.5.0.1".to_owned(),
        "snapshot.json.tmp.5.0x".to_owned(),
        "notes.json.tmp.5.0".to_owned(),
    ];
    for name in stale.iter().chain(&keep) {
        fs.seed(&dir.join(name), b"x");
    }
    let live_bin = format!("{sha}.tmp.{live}.1");
    fs.seed(&bin.join(&live_bin), b"x");
    // The files of the dead writer are older than the grace time.
    fs.advance(crate::fs::TEMP_GRACE);
    let opened = reopen(&fs, &dir, &opts(Access::Write { break_lock: true }, next)).unwrap();
    let mut left = temps_of(&fs, &dir, dead);
    left.extend(temps_of(&fs, &bin, dead));
    assert_eq!(
        left,
        Vec::<String>::new(),
        "no file of the dead writer stays"
    );
    let names = fs.boxed().list(&dir).unwrap();
    for name in &keep {
        assert!(names.contains(name), "{name} stays: {names:?}");
    }
    assert!(
        fs.get(&bin.join(&live_bin)).is_some(),
        "the input copy of a live process stays"
    );
    drop(opened);
}

/// A file system over a [`SimFs`] that shows each path of `links` as a symbolic link.
#[derive(Clone)]
struct LinkFs {
    sim: SimFs,
    links: Vec<PathBuf>,
}

impl Fs for LinkFs {
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.create_dir_all(path)
    }
    fn create_new(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.create_new(path)
    }
    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.sim.append(path, bytes)
    }
    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.sim.write_all(path, bytes)
    }
    fn truncate(&mut self, path: &Path, len: u64) -> Result<(), FsError> {
        self.sim.truncate(path, len)
    }
    fn sync_file(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.sync_file(path)
    }
    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.sim.rename(from, to)
    }
    fn link_new(&mut self, src: &Path, dst: &Path) -> Result<(), FsError> {
        self.sim.link_new(src, dst)
    }
    fn sync_dir(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.sync_dir(path)
    }
    fn remove(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.remove(path)
    }
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.sim.read(path)
    }
    fn set_read_only(&mut self, path: &Path) -> Result<(), FsError> {
        self.sim.set_read_only(path)
    }
    fn list(&mut self, dir: &Path) -> Result<Vec<String>, FsError> {
        self.sim.list(dir)
    }
    fn exists(&mut self, path: &Path) -> bool {
        self.sim.exists(path)
    }
    fn kind(&mut self, path: &Path) -> Option<EntryKind> {
        if self.links.iter().any(|l| l == path) {
            return Some(EntryKind::Other);
        }
        self.sim.kind(path)
    }
    fn modified(&mut self, path: &Path) -> Option<std::time::SystemTime> {
        self.sim.modified(path)
    }
    fn boxed(&self) -> Box<dyn Fs> {
        Box::new(self.clone())
    }
}

#[test]
fn regress_sweep_removes_dead_crash_temps() {
    // A writer that dies, a live process and the process of the next open. No ID is the ID
    // of the test process.
    let me = std::process::id();
    let pids: Vec<u32> = (7..).filter(|p| *p != me).take(3).collect();
    let (dead, live, next) = (pids[0], pids[1], pids[2]);
    let fs = sim(&[live, next]);
    let (mut project, program) = create_breaking(&fs, dead).unwrap();
    let dir = Project::dir_of(Path::new(ROOT), program.meta().binary_id);
    let crash = dir.join(super::CRASH_DIR);
    // A crash record of a handler panic, then a crash between create_temp and rename.
    let record = Value::object([("code", Value::from("E_INTERNAL"))]);
    assert_eq!(
        project.write_crash("a1", &record).unwrap(),
        format!("{}/a1.json", super::CRASH_DIR)
    );
    fs.crash_after("create_new b2.tmp.");
    assert!(project.write_crash("b2", &record).is_err());
    drop(project);
    fs.resume();
    // The test process stays alive, so its temporary file gets the ID of the dead writer.
    let mut raw = fs.boxed();
    let mut moved = Vec::new();
    for name in temps_of(&fs, &crash, me) {
        let to = name.replacen(&format!(".tmp.{me}."), &format!(".tmp.{dead}."), 1);
        raw.rename(&crash.join(&name), &crash.join(&to)).unwrap();
        moved.push(to);
    }
    assert_eq!(moved.len(), 1, "one temporary file of the crash: {moved:?}");
    let id64 = "0123456789abcdef".repeat(4);
    let stale = [
        format!("{id64}.tmp.{dead}.0"),
        format!("ABCDEF.tmp.{dead}.7"),
    ];
    // The files of live processes and the names of another shape stay.
    let keep = [
        format!("{id64}.tmp.{live}.0"),
        format!("{id64}0.tmp.{dead}.0"),
        format!("xyz.tmp.{dead}.0"),
        format!(".tmp.{dead}.0"),
        format!("a1.json.tmp.{dead}.0"),
        format!("a1.tmp.{dead}.0.1"),
        format!("a1.tmp.{dead}"),
        format!("a1.tmp.+{dead}.0"),
        "a1.json".to_owned(),
    ];
    for name in stale.iter().chain(&keep) {
        fs.seed(&crash.join(name), b"x");
    }
    let folder = crash.join(format!("c3.tmp.{dead}.0"));
    raw.create_dir_all(&folder).unwrap();
    let link = crash.join(format!("d4.tmp.{dead}.0"));
    fs.seed(&link, b"x");
    let linked = LinkFs {
        sim: fs.clone(),
        links: vec![link.clone()],
    };
    fs.advance(crate::fs::TEMP_GRACE);
    let options = opts(Access::Write { break_lock: true }, next);
    let opened = Project::open(linked.boxed(), &dir, &options).unwrap();
    let names = fs.boxed().list(&crash).unwrap();
    for name in moved.iter().chain(&stale) {
        assert!(!names.contains(name), "{name} goes: {names:?}");
    }
    for name in &keep {
        assert!(names.contains(name), "{name} stays: {names:?}");
    }
    assert!(raw.kind(&folder).is_some(), "a directory stays");
    assert!(fs.get(&link).is_some(), "a symbolic link stays");
    drop(opened);
}
