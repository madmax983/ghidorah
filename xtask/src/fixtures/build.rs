//! `xtask fixtures build`: the fixture binaries, the goldens, the truth files and the manifest.
//!
//! The build works in `target/fixtures-work`. For each program and build it copies the
//! sources into one directory, compiles each source with `-c` and links with
//! `-Wl,-Map`. Then it makes the variants, runs the fact runs, writes the goldens, runs the
//! leaf driver and assembles the truth file. With `--check`, it writes into
//! `target/fixtures-check` and compares each file with the checked-in file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ghidorah_testkit::golden::{self, Header};

use super::assemble::{self, Inputs};
use super::elfinfo::{self, ElfInfo};
use super::facts;
use super::jumptab::{self, Object};
use super::leaf::{self, LeafFn};
use super::manifest::{self, Entry, Manifest};
use super::objdump;
use super::spec::{self, Build, Fixture, Program, Variant};
use super::toolchain::{self, Tools};
use super::{BIN_DIR, GENERATOR, GOLDEN_AREAS, SRC_DIR, TRUTH_DIR, VERSION, pretty, truth};
use crate::Error;
use crate::json::Value;
use crate::verify::tree::{hex, sha256};
use crate::workspace::rel;

/// The work directory, relative to the workspace root.
pub const WORK_DIR: &str = "target/fixtures-work";

/// The output root of `--check`, relative to the workspace root.
pub const CHECK_DIR: &str = "target/fixtures-check";

/// The state of one build run.
struct Run<'a> {
    root: &'a Path,
    out: PathBuf,
    tools: Tools,
    written: BTreeSet<String>,
    entries: Vec<Entry>,
    vectors: BTreeMap<String, Vec<(String, String)>>,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn fresh_dir(path: &Path) -> Result<(), Error> {
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(|e| Error::io(path, e))?;
    }
    std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(path, bytes).map_err(|e| Error::io(path, e))
}

fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| Error::io(path, e))
}

impl Run<'_> {
    fn put(&mut self, rel_path: &str, bytes: &[u8]) -> Result<(), Error> {
        write_file(&self.out.join(rel_path), bytes)?;
        self.written.insert(rel_path.to_owned());
        Ok(())
    }

    fn golden(&mut self, rel_path: &str, header: &Header, body: &str) -> Result<(), Error> {
        golden::compare(&self.out.join(rel_path), header, body, true)
            .map_err(|e| Error::data(rel_path, e.to_string()))?;
        self.written.insert(rel_path.to_owned());
        Ok(())
    }

    fn header(&self, fixture: &str, sha: &str) -> Header {
        Header::new(GENERATOR, VERSION)
            .with("fixture", fixture)
            .with("fixture_sha256", sha)
            .with("binutils", &self.tools.binutils)
    }
}

/// Compiles and links one build. Gives the object file names and the link map text.
fn compile(
    dir: &Path,
    program: &Program,
    build: &Build,
    name: &str,
    gcc_dir: &str,
) -> Result<(Vec<String>, String), Error> {
    let cc = build.compiler.program();
    let mut cflags = toolchain::driver_flags(build.compiler, gcc_dir);
    cflags.extend(strings(build.cflags));
    cflags.extend(strings(program.cflags));
    let mut objects = Vec::new();
    for src in program.sources {
        let obj = format!("{}.o", src.trim_end_matches(".c"));
        let mut args = cflags.clone();
        args.extend([
            "-c".to_owned(),
            (*src).to_owned(),
            "-o".to_owned(),
            obj.clone(),
        ]);
        toolchain::run_in(dir, cc, &args)?;
        objects.push(obj);
    }
    let mut args = cflags;
    args.extend(objects.iter().cloned());
    args.extend(strings(build.ldflags));
    args.extend(strings(program.ldflags));
    args.extend([
        "-o".to_owned(),
        name.to_owned(),
        format!("-Wl,-Map={name}.map"),
    ]);
    toolchain::run_in(dir, cc, &args)?;
    let map =
        std::fs::read_to_string(dir.join(format!("{name}.map"))).map_err(|e| Error::io(dir, e))?;
    Ok((objects, map))
}

/// Runs the fact runs of the program on a built binary.
fn check_runs(path: &Path, facts_in: &Value) -> Result<(), Error> {
    for run in facts::list(facts_in, "runs") {
        let args: Vec<String> = facts::list(run, "args")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let (stdout, code) = toolchain::run_fixture(path, &args)?;
        let want_out = run.get("stdout").and_then(Value::as_str).unwrap_or("");
        let want_code = run.get("exit").and_then(Value::as_u64);
        let code = code.and_then(|c| u64::try_from(c).ok());
        if stdout != want_out || code != want_code {
            return Err(Error::data(
                path.display().to_string(),
                format!("run {args:?} gave {stdout:?} with exit {code:?}"),
            ));
        }
    }
    Ok(())
}

/// Finds the jump tables of all objects of a build.
fn jump_tables(
    dir: &Path,
    objects: &[String],
    map_text: &str,
) -> Result<Vec<jumptab::JumpTable>, Error> {
    let map = jumptab::parse_map(map_text, objects);
    let mut out = Vec::new();
    for obj in objects {
        let args = strings(&["-W", "-S", "-r", obj]);
        let info = elfinfo::parse(&toolchain::run_in(dir, "readelf", &args)?);
        let object = Object {
            file: obj,
            sections: &info.sections,
            relocs: &info.relocs,
        };
        out.extend(jumptab::tables(&object, &map));
    }
    out.sort_by_key(|t| t.table);
    Ok(out)
}

/// Builds and runs the leaf driver. Gives the vector lines.
fn leaf_vectors(
    dir: &Path,
    program: &Program,
    build: &Build,
    objects: &[String],
    fns: &[LeafFn],
    gcc_dir: &str,
) -> Result<String, Error> {
    let cc = build.compiler.program();
    let mut leaf_objects = Vec::new();
    for obj in objects {
        let renamed = format!("leaf_{obj}");
        let args = strings(&["--redefine-sym", "main=fixture_main", obj, &renamed]);
        toolchain::run_in(dir, "objcopy", &args)?;
        leaf_objects.push(renamed);
    }
    write_file(&dir.join("leaf_list.h"), leaf::list_header(fns).as_bytes())?;
    let mut args = toolchain::driver_flags(build.compiler, gcc_dir);
    args.extend(strings(build.cflags));
    args.extend(strings(program.cflags));
    args.push("-DLEAF_LIST=\"leaf_list.h\"".to_owned());
    args.extend(strings(&[spec::LEAF_DRIVER, "-o", "leaf_driver"]));
    args.extend(leaf_objects);
    args.extend(strings(build.ldflags));
    toolchain::run_in(dir, cc, &args)?;
    let (stdout, code) = toolchain::run_fixture(&dir.join("leaf_driver"), &[])?;
    if code != Some(0) || stdout.lines().count() != fns.len() * leaf::CASES {
        return Err(Error::data(
            "leaf_driver",
            format!("bad driver run in {}", dir.display()),
        ));
    }
    Ok(stdout)
}

/// Gives the bytes of a variant made from the build output in `dir`.
fn variant_bytes(dir: &Path, name: &str, variant: Variant) -> Result<Vec<u8>, Error> {
    let stripped = format!("{name}.stripped");
    toolchain::run_in(dir, "strip", &strings(&["-o", &stripped, name]))?;
    let path = match variant {
        Variant::Stripped => dir.join(&stripped),
        Variant::NoEh => {
            let noeh = format!("{name}.noeh");
            let args = strings(&[
                "--remove-section=.eh_frame",
                "--remove-section=.eh_frame_hdr",
                &stripped,
                &noeh,
            ]);
            toolchain::run_in(dir, "objcopy", &args)?;
            dir.join(noeh)
        }
        Variant::NoShdr => {
            let bytes = read_file(&dir.join(&stripped))?;
            return toolchain::drop_section_headers(&bytes).map_err(|m| Error::data(name, m));
        }
    };
    read_file(&path)
}

impl Run<'_> {
    /// Writes one fixture binary, its loader goldens and its manifest entry.
    fn emit(&mut self, fixture: &Fixture, bytes: &[u8]) -> Result<String, Error> {
        let name = fixture.name();
        let rel_bin = format!("{BIN_DIR}/{name}");
        self.put(&rel_bin, bytes)?;
        let sha = hex(&sha256(bytes));
        let bin_dir = self.out.join(BIN_DIR);
        let header = self.header(&name, &sha);
        let readelf = toolchain::run_in(
            &bin_dir,
            "readelf",
            &strings(&["-W", "-h", "-l", "-S", "-s", "-d", "-r", "-n", &name]),
        )?;
        self.golden(
            &format!("tests/golden/loader/{name}.readelf.txt"),
            &header,
            &readelf,
        )?;
        if fixture.variant == Some(Variant::NoShdr) {
            let dynrel =
                toolchain::run_in(&bin_dir, "readelf", &strings(&["-W", "-D", "-r", &name]))?;
            self.golden(
                &format!("tests/golden/loader/{name}.dynrel.txt"),
                &header,
                &dynrel,
            )?;
        }
        let mut cflags = strings(fixture.build.cflags);
        cflags.extend(strings(fixture.program.cflags));
        let mut ldflags = strings(fixture.build.ldflags);
        ldflags.extend(strings(fixture.program.ldflags));
        let compiler = fixture.build.compiler;
        self.entries.push(Entry {
            name,
            path: rel_bin,
            sha256: sha.clone(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            tier: fixture.program.tier.name().to_owned(),
            program: fixture.program.name.to_owned(),
            build: fixture.build.id.to_owned(),
            variant: fixture.variant.map_or("none", Variant::suffix).to_owned(),
            compiler: format!("{} {}", compiler.program(), self.tools.compiler(compiler)),
            cflags,
            ldflags,
            truth: truth::path(&fixture.truth_name()),
        });
        Ok(sha)
    }

    /// Writes the objdump and frames goldens of a build output. Gives the objdump text.
    fn code_goldens(&mut self, name: &str, sha: &str) -> Result<String, Error> {
        let bin_dir = self.out.join(BIN_DIR);
        let header = self.header(name, sha);
        let listing = toolchain::run_in(
            &bin_dir,
            "objdump",
            &strings(&["-d", "-w", "-z", "-M", "intel", name]),
        )?;
        self.golden(
            &format!("tests/golden/objdump/{name}.txt"),
            &header,
            &listing,
        )?;
        let frames = toolchain::run_in(
            &bin_dir,
            "readelf",
            &strings(&["--debug-dump=frames", name]),
        )?;
        self.golden(
            &format!("tests/golden/ehframe/{name}.txt"),
            &header,
            &frames,
        )?;
        Ok(listing)
    }

    /// Writes the build output and its variants. Gives the `binaries` rows and the build sha256.
    fn emit_all(
        &mut self,
        program: &Program,
        build: &Build,
        dir: &Path,
        bytes: &[u8],
    ) -> Result<(Vec<Value>, String), Error> {
        let name = spec::build_name(program, build);
        let mut binaries = Vec::new();
        let mut sha = String::new();
        let fixtures = spec::fixtures()
            .into_iter()
            .filter(|f| f.program.name == program.name && f.build.id == build.id);
        for fixture in fixtures {
            let out = match fixture.variant {
                None => bytes.to_vec(),
                Some(v) => variant_bytes(dir, &name, v)?,
            };
            let fixture_sha = self.emit(&fixture, &out)?;
            if fixture.variant.is_none() {
                sha.clone_from(&fixture_sha);
            }
            let variant = fixture.variant.map_or("none", Variant::suffix);
            binaries.push(Value::object([
                ("name", Value::from(fixture.name())),
                ("sha256", Value::from(fixture_sha)),
                ("variant", Value::from(variant)),
            ]));
        }
        Ok((binaries, sha))
    }

    /// Runs the leaf driver of a build and writes its vector golden.
    fn vectors_of(
        &mut self,
        program: &Program,
        build: &Build,
        dir: &Path,
        objects: &[String],
        fns: &[LeafFn],
        sha: &str,
    ) -> Result<(), Error> {
        let name = spec::build_name(program, build);
        let lines = leaf_vectors(dir, program, build, objects, fns, &self.tools.gcc_dir)?;
        let cc = format!(
            "{}-{}",
            build.compiler.program(),
            self.tools.compiler(build.compiler)
        );
        let header = self
            .header(&name, sha)
            .with("cc", &cc)
            .with("cases", &leaf::CASES.to_string());
        self.golden(&leaf::vector_path(&name), &header, &lines)?;
        self.vectors
            .entry(program.name.to_owned())
            .or_default()
            .push((name, lines));
        Ok(())
    }

    /// Gives the fixed head fields of a truth file.
    fn truth_head(
        &self,
        program: &Program,
        build: &Build,
        binaries: Vec<Value>,
    ) -> Vec<(&'static str, Value)> {
        let compiler = format!(
            "{} {}",
            build.compiler.program(),
            self.tools.compiler(build.compiler)
        );
        let flags = |a: &[&str], b: &[&str]| {
            Value::from(
                a.iter()
                    .chain(b)
                    .map(|s| Value::from(*s))
                    .collect::<Vec<_>>(),
            )
        };
        vec![
            ("program", Value::from(program.name)),
            ("tier", Value::from(program.tier.name())),
            (
                "generator",
                Value::object([
                    ("name", Value::from(GENERATOR)),
                    ("version", Value::from(VERSION)),
                ]),
            ),
            (
                "build",
                Value::object([
                    ("id", Value::from(build.id)),
                    ("compiler", Value::from(compiler)),
                    ("cflags", flags(build.cflags, program.cflags)),
                    ("ldflags", flags(build.ldflags, program.ldflags)),
                ]),
            ),
            ("binaries", Value::from(binaries)),
        ]
    }

    /// Builds one build of a program with its variants, goldens, vectors and truth.
    fn build_one(
        &mut self,
        program: &'static Program,
        build: &'static Build,
        facts_in: &Value,
        fns: &[LeafFn],
    ) -> Result<(), Error> {
        let name = spec::build_name(program, build);
        let dir = self.root.join(WORK_DIR).join(&name);
        fresh_dir(&dir)?;
        let src_root = self.root.join(SRC_DIR);
        for file in program
            .sources
            .iter()
            .chain([&spec::HEADER, &spec::LEAF_DRIVER])
        {
            let bytes = read_file(&src_root.join(file))?;
            write_file(&dir.join(file), &bytes)?;
        }
        let (objects, map) = compile(&dir, program, build, &name, &self.tools.gcc_dir)?;
        check_runs(&dir.join(&name), facts_in)?;
        let bytes = read_file(&dir.join(&name))?;
        let (binaries, sha) = self.emit_all(program, build, &dir, &bytes)?;
        let listing_text = self.code_goldens(&name, &sha)?;
        let leafs: &[LeafFn] = if build.leaf_vectors { fns } else { &[] };
        if !leafs.is_empty() {
            self.vectors_of(program, build, &dir, &objects, leafs, &sha)?;
        }
        let args = strings(&["-W", "-h", "-l", "-S", "-s", "-d", "-r", "-n", &name]);
        let info: ElfInfo = elfinfo::parse(&toolchain::run_in(&dir, "readelf", &args)?);
        let listing = objdump::parse(&listing_text);
        let tables = jump_tables(&dir, &objects, &map)?;
        let inputs = Inputs {
            name: &name,
            head: self.truth_head(program, build, binaries),
            info: &info,
            listing: &listing,
            bytes: &bytes,
            tables: &tables,
            facts: facts_in,
            leafs,
        };
        let value =
            assemble::assemble(&inputs).map_err(|errs| Error::data(&name, errs.join("; ")))?;
        self.put(&truth::path(&name), pretty::write(&value).as_bytes())
    }

    /// Checks that the leaf vectors of a program agree across its builds.
    fn check_vectors_agree(&self) -> Result<(), Error> {
        for (program, runs) in &self.vectors {
            if let Some((first, body)) = runs.first() {
                for (other, other_body) in runs.iter().skip(1) {
                    if other_body != body {
                        return Err(Error::data(
                            program,
                            format!("leaf vectors of {first} and {other} differ"),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), Error> {
    if !dir.is_dir() {
        return Ok(());
    }
    for item in std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let path = item.map_err(|e| Error::io(dir, e))?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "pe") {
                collect(root, &path, out)?;
            }
        } else {
            out.push(rel(root, &path));
        }
    }
    Ok(())
}

/// Gives the files of the output directories that the build owns, relative to `root`.
fn owned_files(root: &Path) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    collect(root, &root.join(BIN_DIR), &mut out)?;
    collect(root, &root.join(TRUTH_DIR), &mut out)?;
    for area in GOLDEN_AREAS {
        collect(root, &root.join("tests/golden").join(area), &mut out)?;
    }
    out.sort();
    Ok(out)
}

/// Runs the build. With `check`, it compares the outputs with the checked-in files.
///
/// # Errors
///
/// Returns an error when a tool is missing, a build step fails or a fact does not hold.
pub fn run(root: &Path, check: bool) -> Result<Value, Error> {
    let out = if check {
        root.join(CHECK_DIR)
    } else {
        root.to_path_buf()
    };
    if check {
        fresh_dir(&out)?;
    }
    let mut state = Run {
        root,
        out: out.clone(),
        tools: toolchain::detect()?,
        written: BTreeSet::new(),
        entries: Vec::new(),
        vectors: BTreeMap::new(),
    };
    for program in spec::PROGRAMS {
        let facts_in = facts::read(root, program.name)?;
        let mut fns = Vec::new();
        for src in program.sources {
            let text = std::fs::read_to_string(root.join(SRC_DIR).join(src))
                .map_err(|e| Error::io(*src, e))?;
            fns.extend(leaf::parse_source(&text).map_err(|e| Error::data(*src, e.to_string()))?);
        }
        for build in program.builds {
            state.build_one(program, build, &facts_in, &fns)?;
        }
    }
    state.check_vectors_agree()?;
    state.entries.sort_by(|a, b| a.name.cmp(&b.name));
    let manifest = Manifest {
        tools: state.tools.map(),
        entries: state.entries.clone(),
    };
    state.put(
        manifest::PATH,
        pretty::write(&manifest.to_value()).as_bytes(),
    )?;
    let mut differences = Vec::new();
    if check {
        let mut produced = owned_files(&out)?;
        produced.push(manifest::PATH.to_owned());
        let mut repo = owned_files(root)?;
        repo.push(manifest::PATH.to_owned());
        let mut all = produced;
        all.extend(repo);
        all.sort();
        all.dedup();
        for file in &all {
            if std::fs::read(out.join(file)).ok() != std::fs::read(root.join(file)).ok() {
                differences.push(Value::from(file.as_str()));
            }
        }
    } else {
        for file in owned_files(root)? {
            if !state.written.contains(&file) {
                std::fs::remove_file(root.join(&file)).map_err(|e| Error::io(&file, e))?;
            }
        }
    }
    Ok(Value::object([
        ("ok", Value::from(differences.is_empty())),
        ("fixtures", Value::from(manifest.entries.len())),
        ("total_bytes", Value::from(manifest.total_bytes())),
        ("differences", Value::from(differences)),
    ]))
}
