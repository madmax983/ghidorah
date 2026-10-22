//! The static workspace gates and the `xtask gates` command.
//!
//! Each gate maps one AC to a check over the repository.
//! The tests in `xtask/tests/gates.rs` and `xtask/tests/docs.rs` run the same gates.
//! The modules [`docs`] and [`ledger`] hold the doc gates of WP-28.

pub mod docs;
pub mod ledger;

use std::path::{Path, PathBuf};

use crate::json::Value;
use crate::workspace::{self, Metadata, PURE_CORE};
use crate::{Error, Finding, ac, dag, manifest, proc, scan, workflow};

/// The repository that the gates check.
#[derive(Debug, Clone)]
pub struct Repo {
    /// The workspace root.
    pub root: PathBuf,
    /// The workspace model.
    pub meta: Metadata,
}

impl Repo {
    /// Loads the workspace model of `root`.
    ///
    /// # Errors
    ///
    /// Returns an error when `cargo metadata` fails.
    pub fn load(root: &Path) -> Result<Self, Error> {
        Ok(Self {
            root: root.to_path_buf(),
            meta: workspace::load_metadata(root)?,
        })
    }

    /// Gives the relative path of each package manifest, plus the root manifest.
    #[must_use]
    pub fn manifests(&self) -> Vec<String> {
        let mut list: Vec<String> = self
            .meta
            .packages
            .iter()
            .map(|p| format!("{}/Cargo.toml", p.dir(&self.root)))
            .collect();
        list.push("Cargo.toml".to_owned());
        list.sort();
        list.dedup();
        list
    }

    /// Reads every Rust file that `keep` selects and runs `check` on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when a read fails.
    pub fn each_rust_file(
        &self,
        keep: impl Fn(&str) -> bool,
        check: impl Fn(&str, &str) -> Vec<Finding>,
    ) -> Result<Vec<Finding>, Error> {
        let mut found = Vec::new();
        for rel in scan::rust_files(&self.root)? {
            if keep(&rel) {
                found.extend(check(&rel, &self.read(&rel)?));
            }
        }
        Ok(found)
    }

    /// Reads a file relative to the root.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the read fails.
    pub fn read(&self, rel: &str) -> Result<String, Error> {
        let path = self.root.join(rel);
        std::fs::read_to_string(&path).map_err(|e| Error::io(path, e))
    }
}

/// One gate.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    /// The AC that the gate checks, for example `AC-012`.
    pub ac: &'static str,
    /// A short statement of the rule.
    pub summary: &'static str,
    /// The check.
    pub check: fn(&Repo) -> Result<Vec<Finding>, Error>,
}

const fn gate(
    ac: &'static str,
    summary: &'static str,
    check: fn(&Repo) -> Result<Vec<Finding>, Error>,
) -> Gate {
    Gate { ac, summary, check }
}

/// Every static gate, in AC order.
pub const GATES: &[Gate] = &[
    gate(
        "AC-001a",
        "Every package is a package of Section 2.1 at its path.",
        |r| Ok(workspace::check_packages(&r.meta)),
    ),
    gate(
        "AC-001b",
        "`Cargo.lock` has no package with a `source` key.",
        |r| Ok(manifest::no_lock_sources(&r.read("Cargo.lock")?)),
    ),
    gate("AC-001c", "Every dependency is a workspace package.", |r| {
        Ok(workspace::check_workspace_deps(&r.meta))
    }),
    gate(
        "AC-001d",
        "No `[patch]`, `[replace]` or `[source]` table exists.",
        patch_tables,
    ),
    gate(
        "AC-001e",
        "Production packages can go to crates.io with LICENSE and NOTICE. Dev packages cannot.",
        |r| {
            let mut found = workspace::check_publish_license(&r.meta);
            found.extend(workspace::check_legal_copies(&r.meta, |rel| {
                r.read(rel).ok()
            }));
            Ok(found)
        },
    ),
    gate(
        "AC-002",
        "`.cargo/config.toml` sets `net.offline = true`.",
        |r| Ok(manifest::offline(&r.read(".cargo/config.toml")?)),
    ),
    gate("AC-003", "Every edge is in the allowed-edge table.", |r| {
        let mut found = dag::check_edges(&dag::edges(&r.meta));
        found.extend(dag::check_mmd(&r.root));
        Ok(found)
    }),
    gate(
        "AC-004",
        "The binary closure holds no unsafe code.",
        no_unsafe,
    ),
    gate(
        "AC-005",
        "No manifest names `vstd` or a Verus crate.",
        |r| each_manifest(r, manifest::no_vstd),
    ),
    gate("AC-007a", "`rust-toolchain.toml` pins 1.97.0.", |r| {
        Ok(manifest::toolchain_pin(&r.read("rust-toolchain.toml")?))
    }),
    gate("AC-007b", "Every crate uses edition 2024.", |r| {
        Ok(workspace::check_edition(&r.meta))
    }),
    gate("AC-007c", "The workspace uses resolver 3.", |r| {
        Ok(manifest::resolver_3(&r.read("Cargo.toml")?))
    }),
    gate(
        "AC-008",
        "No build script uses the network or child processes.",
        build_scripts,
    ),
    gate("AC-009", "`cargo fmt --all -- --check` passes.", fmt_check),
    gate(
        "AC-010",
        "The clippy policy of ADR-0019 applies to every package and source file.",
        clippy_policy,
    ),
    gate(
        "AC-011",
        "The workspace denies `missing_docs` and `unsafe_code`, with no source exception.",
        |r| {
            let mut found = policy(r, manifest::docs_policy)?;
            found.extend(r.each_rust_file(scan::is_source_file, scan::docs_exceptions)?);
            Ok(found)
        },
    ),
    gate(
        "AC-012",
        "Non-test code has no stubs and no panicking calls.",
        |r| r.each_rust_file(|f| !scan::is_test_file(f), scan::no_stubs),
    ),
    gate(
        "AC-014",
        "Each non-table, non-test file has at most 600 lines.",
        |r| {
            r.each_rust_file(
                |f| !scan::is_test_file(f) && !scan::is_table_file(f),
                scan::file_size,
            )
        },
    ),
    gate("AC-016", "`clippy.toml` disallows the hash types.", |r| {
        let mut found = manifest::clippy_config(&r.read("clippy.toml")?);
        found.extend(r.each_rust_file(|_| true, scan::disallowed_exceptions)?);
        Ok(found)
    }),
    gate(
        "AC-017",
        "Pure core crates use no I/O, process or clock APIs.",
        |r| {
            let pure = |f: &str| {
                !scan::is_test_file(f)
                    && f.starts_with("crates/")
                    && scan::crate_dir(f).is_some_and(|d| PURE_CORE.contains(&d))
            };
            r.each_rust_file(pure, scan::layering)
        },
    ),
    gate(
        "AC-018c",
        "Each AC closes after the WPs of its Needs column.",
        |r| {
            let (rows, mut found) = ac::parse_rows(&r.read(ac::DESIGN_PATH)?);
            found.extend(ac::needs_order(&rows));
            Ok(found)
        },
    ),
    gate(
        "AC-019",
        "The CI workflow has its tiers and only allowed actions.",
        |r| Ok(workflow::check(&r.read(workflow::PATH)?)),
    ),
    gate(
        "AC-023a",
        "The required docs exist, README links resolve and the ADR index matches.",
        |r| docs::check_present(&r.root),
    ),
    gate(
        "AC-023b",
        "Each ADR has Alternatives and a Verified-by line with MVP ACs.",
        |r| docs::check_adrs(&r.root),
    ),
    gate(
        "AC-027",
        "NOTICE and the ledger list each vendored data file.",
        |r| ledger::check_ledger(&r.root),
    ),
    gate("AC-223", "No crate changes the process environment.", |r| {
        r.each_rust_file(|_| true, scan::no_set_var)
    }),
];

fn each_manifest(
    repo: &Repo,
    check: fn(&str, &str) -> Vec<Finding>,
) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    for rel in repo.manifests() {
        found.extend(check(&rel, &repo.read(&rel)?));
    }
    Ok(found)
}

fn each_package_manifest(
    repo: &Repo,
    check: fn(&str, &str) -> Vec<Finding>,
) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    for rel in repo.manifests().into_iter().filter(|m| m != "Cargo.toml") {
        found.extend(check(&rel, &repo.read(&rel)?));
    }
    Ok(found)
}

/// Checks the root lint policy, then the `[lints] workspace = true` line of each package.
fn policy(repo: &Repo, root_check: fn(&str) -> Vec<Finding>) -> Result<Vec<Finding>, Error> {
    let mut found = root_check(&repo.read("Cargo.toml")?);
    found.extend(each_package_manifest(repo, manifest::lints_inherited)?);
    Ok(found)
}

/// AC-010: checks the root clippy policy, the inherited lints, the ADR-0019 lists and each
/// clippy exception of the non-test sources.
fn clippy_policy(repo: &Repo) -> Result<Vec<Finding>, Error> {
    let root_toml = repo.read("Cargo.toml")?;
    let mut found = policy(repo, manifest::lint_policy)?;
    found.extend(manifest::adr_names_exceptions(
        &repo.read(manifest::LINT_ADR)?,
    ));
    let mut sources = Vec::new();
    for rel in scan::rust_files(&repo.root)? {
        if scan::is_source_file(&rel) {
            let text = repo.read(&rel)?;
            sources.push((rel, text));
        }
    }
    let mut restriction = manifest::restriction_lints(&root_toml);
    for (_, text) in &sources {
        restriction.extend(scan::denied_clippy_lints(text));
    }
    for (rel, text) in &sources {
        found.extend(scan::clippy_exceptions(rel, text, &restriction));
    }
    Ok(found)
}

fn patch_tables(repo: &Repo) -> Result<Vec<Finding>, Error> {
    let mut found = each_manifest(repo, manifest::no_patch_tables)?;
    let config = ".cargo/config.toml";
    found.extend(manifest::no_source_tables(config, &repo.read(config)?));
    Ok(found)
}

fn no_unsafe(repo: &Repo) -> Result<Vec<Finding>, Error> {
    let closure = workspace::closure(&repo.meta, workspace::BINARY);
    let dirs: Vec<String> = closure
        .iter()
        .filter_map(|name| repo.meta.package(name))
        .map(|p| format!("{}/", p.dir(&repo.root)))
        .collect();
    repo.each_rust_file(
        |f| dirs.iter().any(|d| f.starts_with(d.as_str())),
        scan::no_unsafe,
    )
}

fn build_scripts(repo: &Repo) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    for package in &repo.meta.packages {
        for target in &package.targets {
            if target.kinds.iter().any(|k| k == "custom-build") {
                let rel = workspace::rel(&repo.root, &target.src_path);
                found.extend(scan::build_script(&rel, &repo.read(&rel)?));
            }
        }
    }
    Ok(found)
}

fn fmt_check(repo: &Repo) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    let config = repo.read("rustfmt.toml")?;
    if manifest::value(&config, "", "edition").as_deref() != Some("\"2024\"") {
        found.push(Finding::new(
            "AC-009",
            "rustfmt.toml",
            0,
            "set `edition = \"2024\"`",
        ));
    }
    let mut cmd = proc::cargo_cmd(&["fmt", "--all", "--", "--check"]);
    cmd.current_dir(&repo.root);
    let out = proc::run(&mut cmd)?;
    if !out.ok() {
        let detail = format!(
            "`cargo fmt --all -- --check` fails:\n{}",
            proc::tail(&out.stdout, 20)
        );
        found.push(Finding::new("AC-009", "", 0, detail));
    }
    Ok(found)
}

/// Gives the gate of an AC.
#[must_use]
pub fn find(ac: &str) -> Option<&'static Gate> {
    GATES.iter().find(|g| g.ac == ac)
}

/// Runs the gate of one AC.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown AC, or the error of the check.
pub fn check(repo: &Repo, ac: &str) -> Result<Vec<Finding>, Error> {
    find(ac).map_or_else(
        || Err(Error::Usage(format!("no gate for {ac}"))),
        |g| (g.check)(repo),
    )
}

/// Runs `xtask gates [AC...]`. Without arguments, it runs every gate.
///
/// # Errors
///
/// Returns an error when the repository does not load or a check fails to run.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let repo = Repo::load(root)?;
    let selected: Vec<&Gate> = if args.is_empty() {
        GATES.iter().collect()
    } else {
        args.iter()
            .map(|ac| find(ac).ok_or_else(|| Error::Usage(format!("no gate for {ac}"))))
            .collect::<Result<_, _>>()?
    };
    let mut ok = true;
    let mut results = Vec::new();
    for gate in selected {
        let findings = (gate.check)(&repo)?;
        ok &= findings.is_empty();
        results.push(Value::object([
            ("ac", Value::from(gate.ac)),
            ("summary", Value::from(gate.summary)),
            ("ok", Value::from(findings.is_empty())),
            (
                "findings",
                Value::from(findings.iter().map(Finding::to_json).collect::<Vec<_>>()),
            ),
        ]));
    }
    Ok(Value::object([
        ("ok", Value::from(ok)),
        ("gates", Value::from(results)),
    ]))
}
