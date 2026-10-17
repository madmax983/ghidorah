//! AC-025: the STE checker reports no finding on docs and comments.
//!
//! The scan reads every Markdown file and every Rust comment of the repository.
//! It skips `docs/research.md` and `docs/planning/`. The reviewed allowlist
//! `docs/ste-allowlist.txt` allows the remaining findings.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;

use ghidorah_testkit::ste::{self, AllowEntry, Checker, Mode};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn ac_025_ste_docs() {
    let root = repo_root();
    let lexicon = ste::repo_lexicon(&root);
    let allowlist = ste::repo_allowlist(&root);
    let Ok(allowlist) = allowlist else {
        panic!("{} does not parse: {allowlist:?}", ste::ALLOWLIST_PATH);
    };
    let report = ste::scan_repo(&root, &Checker::new(lexicon), Mode::Warn, &allowlist);
    let Ok(report) = report else {
        panic!("the scan fails: {report:?}");
    };
    assert!(
        report.files >= 10,
        "the scan reads the docs and sources: {}",
        report.files
    );
    if !report.ok() {
        let lines: Vec<String> = report
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{f}\n    allow: {}",
                    AllowEntry::for_finding(&f.path, &f.finding)
                )
            })
            .collect();
        panic!(
            "{} STE findings. Fix the text or add a reviewed entry to {}:\n{}",
            report.findings.len(),
            ste::ALLOWLIST_PATH,
            lines.join("\n")
        );
    }
}
