//! The PE32+ fixtures of WP-30: their build, their truth and their goldens (design Section 4.15).
//!
//! `xtask fixtures build` calls [`run`] after the ELF build. The build works in
//! `target/fixtures-pe-work`. The steps are:
//!
//! 1. `clang --target=x86_64-pc-windows-msvc -O2 -c` compiles each source.
//! 2. `rust-lld -flavor link /lib` makes the import libraries.
//! 3. `rust-lld -flavor link /nodefaultlib` links each image with `/map`.
//! 4. `llvm-readobj` and `llvm-objdump` of the `llvm-tools` component write the goldens.
//!
//! Outputs, relative to the workspace root:
//!
//! | Output | Content |
//! |---|---|
//! | `fixtures/bin/pe/<image>` | the four images of [`IMAGES`] |
//! | `fixtures/truth/pe/<program>.json` | the truth of [`truth`] |
//! | `tests/golden/loader/pe/<image>.readobj.txt` | `llvm-readobj` with the options of [`READOBJ_ARGS`] |
//! | `tests/golden/loader/pe/<image>.objdump.txt` | `llvm-objdump -d -M intel` |
//! | `fixtures/manifest.json` | one entry for each image, tier `PE` |
//!
//! `/Brepro` makes the time stamps and the `CodeView` GUIDs a hash of the image, so two builds
//! give the same bytes. With `--check`, the build writes into `target/fixtures-pe-check` and
//! compares each file with the checked-in file.

pub mod parse;
pub mod truth;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_testkit::golden::{self, Header};

use crate::fixtures::manifest::{self, Entry, Manifest};
use crate::fixtures::{GENERATOR, VERSION, pretty};
use crate::json::Value;
use crate::verify::tree::{hex, sha256};
use crate::workspace::rel;
use crate::{Error, Finding, proc};

/// The source directory, relative to the workspace root.
pub const SRC_DIR: &str = "fixtures/src/pe";

/// The image directory, relative to the workspace root.
pub const BIN_DIR: &str = "fixtures/bin/pe";

/// The truth directory, relative to the workspace root.
pub const TRUTH_DIR: &str = "fixtures/truth/pe";

/// The golden directory, relative to the workspace root.
pub const GOLDEN_DIR: &str = "tests/golden/loader/pe";

/// The work directory, relative to the workspace root.
pub const WORK_DIR: &str = "target/fixtures-pe-work";

/// The output root of `--check`, relative to the workspace root.
pub const CHECK_DIR: &str = "target/fixtures-pe-check";

/// The manifest tier of the PE fixtures.
pub const TIER: &str = "PE";

/// The compiler flags of every object.
pub const CFLAGS: &[&str] = &["--target=x86_64-pc-windows-msvc", "-O2"];

/// The `llvm-readobj` options of the readobj golden.
pub const READOBJ_ARGS: &[&str] = &[
    "-h",
    "--sections",
    "--coff-imports",
    "--coff-exports",
    "--coff-basereloc",
    "--coff-tls-directory",
    "--coff-debug-directory",
    "--unwind",
];

/// The import libraries that the images link. Each one has `<name>.def`.
pub const IMPORT_LIBS: &[&str] = &["kernel32", "alpha", "beta"];

/// One fixture image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image {
    /// The file name, for example `pe_main.exe`.
    pub name: &'static str,
    /// The program name. The truth file and the PDB take it.
    pub program: &'static str,
    /// The C sources.
    pub sources: &'static [&'static str],
    /// The import libraries.
    pub libs: &'static [&'static str],
    /// The entry symbol.
    pub entry: &'static str,
    /// The DLLs of `/delayload`.
    pub delay: &'static [&'static str],
    /// The other link flags.
    pub flags: &'static [&'static str],
}

/// The four images of design Section 4.15.
pub const IMAGES: &[Image] = &[
    Image {
        name: "pe_cc.exe",
        program: "pe_cc",
        sources: &["pe_cc.c"],
        libs: &[],
        entry: "cc_start",
        delay: &[],
        flags: &[],
    },
    Image {
        name: "pe_dll.dll",
        program: "pe_dll",
        sources: &["pe_dll.c"],
        libs: &[],
        entry: "dll_entry",
        delay: &[],
        flags: &["/dll", "/def:pe_dll.def"],
    },
    Image {
        name: "pe_flags.exe",
        program: "pe_flags",
        sources: &["pe_main.c", "pe_tls.c"],
        libs: &["kernel32", "alpha", "beta"],
        entry: "pe_start",
        delay: &["beta.dll"],
        flags: &["/guard:cf", "/integritycheck", "/highentropyva:no"],
    },
    Image {
        name: "pe_main.exe",
        program: "pe_main",
        sources: &["pe_main.c", "pe_tls.c"],
        libs: &["kernel32", "alpha", "beta"],
        entry: "pe_start",
        delay: &["beta.dll"],
        flags: &[],
    },
];

impl Image {
    /// Gives the link flags of the image, in command order.
    #[must_use]
    pub fn ldflags(&self) -> Vec<String> {
        let mut out: Vec<String> = [
            "/subsystem:console",
            "/nodefaultlib",
            "/Brepro",
            "/debug",
            "/machine:x64",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        out.push(format!("/entry:{}", self.entry));
        out.push(format!("/pdbaltpath:{}.pdb", self.program));
        // A fixed source root keeps the PDB, and so the GUID, free of the work directory.
        out.push("/pdbsourcepath:/src".to_owned());
        out.extend(self.delay.iter().map(|d| format!("/delayload:{d}")));
        out.extend(self.flags.iter().map(|f| (*f).to_owned()));
        out
    }
}

/// The tools of the PE build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    /// The clang version, for example `18.1.3`.
    pub clang: String,
    /// The LLVM version of `llvm-readobj`, for example `22.1.6`.
    pub llvm: String,
    /// The directory of `rust-lld`, `llvm-readobj` and `llvm-objdump`.
    pub bin: PathBuf,
}

/// Gives the first word of the lines of `text` that follows `marker`.
fn word_after(text: &str, marker: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.split_once(marker))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_owned)
}

/// Gives the version after `marker` without a `-` suffix, for example `22.1.6`.
fn version_after(text: &str, marker: &str) -> Option<String> {
    word_after(text, marker).map(|w| w.split('-').next().unwrap_or(&w).to_owned())
}

/// Finds the tools: clang on `PATH`, and the `llvm-tools` binaries of the Rust toolchain.
///
/// # Errors
///
/// Returns [`Error::Command`] when a tool is missing, or [`Error::Data`] for an unknown output.
pub fn detect() -> Result<Tools, Error> {
    let clang = proc::run_ok(Command::new("clang").arg("--version"))?.stdout;
    let clang = version_after(&clang, "clang version ")
        .ok_or_else(|| Error::data("clang", "no version in the output"))?;
    let sysroot = proc::run_ok(Command::new("rustc").args(["--print", "sysroot"]))?;
    let host = proc::run_ok(Command::new("rustc").arg("-vV"))?.stdout;
    let host = word_after(&host, "host: ").ok_or_else(|| Error::data("rustc", "no host"))?;
    let bin = Path::new(sysroot.stdout.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin");
    let readobj = proc::run_ok(Command::new(bin.join("llvm-readobj")).arg("--version"))?;
    let llvm = version_after(&readobj.stdout, "LLVM version ")
        .ok_or_else(|| Error::data("llvm-readobj", "no version in the output"))?;
    Ok(Tools { clang, llvm, bin })
}

/// The state of one PE build.
struct Run<'a> {
    root: &'a Path,
    out: PathBuf,
    work: PathBuf,
    tools: Tools,
    written: BTreeSet<String>,
    entries: Vec<Entry>,
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(path, bytes).map_err(|e| Error::io(path, e))
}

fn fresh_dir(path: &Path) -> Result<(), Error> {
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(|e| Error::io(path, e))?;
    }
    std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))
}

impl Run<'_> {
    /// Runs a program in the work directory and gives its standard output.
    fn tool(&self, program: &Path, args: &[String]) -> Result<String, Error> {
        let mut cmd = Command::new(program);
        cmd.args(args).current_dir(&self.work);
        Ok(proc::run_ok(&mut cmd)?.stdout)
    }

    /// Runs `rust-lld -flavor link` with `args`.
    fn link(&self, args: &[String]) -> Result<String, Error> {
        let mut all = vec!["-flavor".to_owned(), "link".to_owned()];
        all.extend_from_slice(args);
        self.tool(&self.tools.bin.join("rust-lld"), &all)
    }

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

    /// Copies the sources and makes the import libraries.
    fn prepare(&self) -> Result<(), Error> {
        let src = self.root.join(SRC_DIR);
        for item in std::fs::read_dir(&src).map_err(|e| Error::io(&src, e))? {
            let path = item.map_err(|e| Error::io(&src, e))?.path();
            if let Some(name) = path.file_name() {
                std::fs::copy(&path, self.work.join(name)).map_err(|e| Error::io(&path, e))?;
            }
        }
        for lib in IMPORT_LIBS {
            self.link(&[
                "/lib".to_owned(),
                format!("/def:{lib}.def"),
                "/machine:x64".to_owned(),
                format!("/out:{lib}.lib"),
            ])?;
        }
        Ok(())
    }

    /// Builds one image with its goldens, its truth and its manifest entry.
    fn build(&mut self, image: &Image) -> Result<(), Error> {
        let mut objects = Vec::new();
        for src in image.sources {
            let obj = src.replace(".c", ".obj");
            let mut args: Vec<String> = CFLAGS.iter().map(|s| (*s).to_owned()).collect();
            args.extend([
                "-c".to_owned(),
                (*src).to_owned(),
                "-o".to_owned(),
                obj.clone(),
            ]);
            self.tool(Path::new("clang"), &args)?;
            objects.push(obj);
        }
        let mut args = image.ldflags();
        args.extend(objects);
        args.extend(image.libs.iter().map(|l| format!("{l}.lib")));
        args.push(format!("/out:{}", image.name));
        args.push(format!("/pdb:{}.pdb", image.program));
        args.push(format!("/map:{}.map", image.program));
        self.link(&args)?;
        let bytes = std::fs::read(self.work.join(image.name))
            .map_err(|e| Error::io(self.work.join(image.name), e))?;
        let sha = hex(&sha256(&bytes));
        self.put(&format!("{BIN_DIR}/{}", image.name), &bytes)?;
        let header = Header::new(GENERATOR, VERSION)
            .with("llvm", &self.tools.llvm)
            .with("fixture", image.name)
            .with("fixture_sha256", &sha);
        let mut readobj_args: Vec<String> = READOBJ_ARGS.iter().map(|s| (*s).to_owned()).collect();
        readobj_args.push(image.name.to_owned());
        let readobj = self.tool(&self.tools.bin.join("llvm-readobj"), &readobj_args)?;
        self.golden(
            &format!("{GOLDEN_DIR}/{}.readobj.txt", image.name),
            &header,
            &readobj,
        )?;
        let objdump_args = ["-d", "-M", "intel", image.name].map(str::to_owned);
        let objdump = self.tool(&self.tools.bin.join("llvm-objdump"), &objdump_args)?;
        self.golden(
            &format!("{GOLDEN_DIR}/{}.objdump.txt", image.name),
            &header,
            &objdump,
        )?;
        let map = std::fs::read_to_string(self.work.join(format!("{}.map", image.program)))
            .map_err(|e| Error::io(self.work.join(image.program), e))?;
        let inputs = truth::Inputs {
            image,
            sha256: &sha,
            map: &map,
            readobj: &readobj,
            objdump: &objdump,
            sources: &self.sources(image)?,
            compiler: &self.compiler(),
        };
        let value = truth::assemble(&inputs).map_err(|e| Error::data(image.name, e))?;
        self.put(
            &truth::path(image.program),
            pretty::write(&value).as_bytes(),
        )?;
        self.entries.push(Entry {
            name: image.name.to_owned(),
            path: format!("{BIN_DIR}/{}", image.name),
            sha256: sha,
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            tier: TIER.to_owned(),
            program: image.program.to_owned(),
            build: "clang-O2".to_owned(),
            variant: "none".to_owned(),
            compiler: self.compiler(),
            cflags: CFLAGS.iter().map(|s| (*s).to_owned()).collect(),
            ldflags: image.ldflags(),
            truth: truth::path(image.program),
        });
        Ok(())
    }

    fn compiler(&self) -> String {
        format!("clang {}", self.tools.clang)
    }

    /// Gives the texts of the sources and the `.def` files of an image, by file name.
    fn sources(&self, image: &Image) -> Result<Vec<(String, String)>, Error> {
        let own = image
            .flags
            .contains(&"/dll")
            .then(|| format!("{}.def", image.program));
        image
            .sources
            .iter()
            .map(|s| (*s).to_owned())
            .chain(image.libs.iter().map(|l| format!("{l}.def")))
            .chain(own)
            .map(|n| {
                let path = self.work.join(&n);
                std::fs::read_to_string(&path)
                    .map(|t| (n, t))
                    .map_err(|e| Error::io(path, e))
            })
            .collect()
    }
}

/// Gives the files of the PE outputs under `root`, relative to `root`.
fn owned_files(root: &Path) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for dir in [BIN_DIR, TRUTH_DIR, GOLDEN_DIR] {
        let path = root.join(dir);
        if !path.is_dir() {
            continue;
        }
        for item in std::fs::read_dir(&path).map_err(|e| Error::io(&path, e))? {
            let file = item.map_err(|e| Error::io(&path, e))?.path();
            if file.is_file() {
                out.push(rel(root, &file));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Gives `manifest` with the PE entries of `entries` in place of its old PE entries.
#[must_use]
pub fn merge(manifest: &Manifest, entries: &[Entry]) -> Manifest {
    let mut out = manifest.clone();
    out.entries
        .retain(|e| !e.path.starts_with(&format!("{BIN_DIR}/")));
    out.entries.extend(entries.iter().cloned());
    out.entries.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Runs the PE build. With `check`, it compares the outputs with the checked-in files.
///
/// # Errors
///
/// Returns an error when a tool is missing, a build step fails or the truth does not assemble.
pub fn run(root: &Path, check: bool) -> Result<Value, Error> {
    let out = if check {
        root.join(CHECK_DIR)
    } else {
        root.to_path_buf()
    };
    let work = root.join(WORK_DIR);
    fresh_dir(&work)?;
    if check {
        fresh_dir(&out)?;
    }
    let mut state = Run {
        root,
        out: out.clone(),
        work,
        tools: detect()?,
        written: BTreeSet::new(),
        entries: Vec::new(),
    };
    state.prepare()?;
    for image in IMAGES {
        state.build(image)?;
    }
    let merged = merge(&manifest::read(root)?, &state.entries);
    write_file(
        &out.join(manifest::PATH),
        pretty::write(&merged.to_value()).as_bytes(),
    )?;
    let mut differences = Vec::new();
    let produced = owned_files(&out)?;
    if check {
        let mut all = produced;
        all.extend(owned_files(root)?);
        all.push(manifest::PATH.to_owned());
        all.sort();
        all.dedup();
        for file in &all {
            if std::fs::read(out.join(file)).ok() != std::fs::read(root.join(file)).ok() {
                differences.push(Value::from(file.as_str()));
            }
        }
    } else {
        for file in produced {
            if !state.written.contains(&file) {
                std::fs::remove_file(root.join(&file)).map_err(|e| Error::io(&file, e))?;
            }
        }
    }
    Ok(Value::object([
        ("ok", Value::from(differences.is_empty())),
        ("images", Value::from(state.entries.len())),
        ("llvm", Value::from(state.tools.llvm.as_str())),
        ("differences", Value::from(differences)),
    ]))
}

/// Checks the PE part of the corpus: each image of [`IMAGES`] has a manifest entry of tier
/// `PE`, and each truth file has the schema of [`truth`] and the sha256 of its image.
///
/// # Errors
///
/// Returns [`Error::Io`] or [`Error::Data`] when a truth file does not read or parse.
pub fn check(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    for image in IMAGES {
        let Some(entry) = manifest.entry(image.name) else {
            found.push(Finding::new(
                "AC-022",
                manifest::PATH,
                0,
                format!("no entry for the PE fixture `{}`", image.name),
            ));
            continue;
        };
        if entry.tier != TIER || entry.truth != truth::path(image.program) {
            found.push(Finding::new(
                "AC-022",
                manifest::PATH,
                0,
                format!("the entry of `{}` has a bad tier or truth", image.name),
            ));
        }
        let value = truth::read(root, image.program)?;
        for message in truth::check_value(&value, &entry.sha256) {
            found.push(Finding::new(
                "WP-30",
                truth::path(image.program),
                0,
                message,
            ));
        }
    }
    Ok(found)
}
