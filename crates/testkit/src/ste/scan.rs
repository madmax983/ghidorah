//! The scan of a repository tree.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::Path;

use super::{
    ALLOWLIST_PATH, AllowEntry, Allowlist, AllowlistError, BANLIST_PATH, Checker, Finding,
    GLOSSARY_PATH, Lexicon, Mode, TextKind, is_exempt,
};

/// A finding in one repository file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileFinding {
    /// The repository path with `/` separators.
    pub path: String,
    /// The finding.
    pub finding: Finding,
}

impl fmt::Display for FileFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.finding)
    }
}

/// The result of a repository scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanReport {
    /// The number of files that the scan read.
    pub files: usize,
    /// The findings that no allowlist entry allows, in path and line order.
    pub findings: Vec<FileFinding>,
    /// The number of findings that the allowlist allows.
    pub allowed: usize,
    /// The allowlist entries that allow no finding.
    pub unused: Vec<AllowEntry>,
}

impl ScanReport {
    /// Returns `true` when the scan has no finding.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }
}

fn collect(dir: &Path, prefix: &str, out: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type()?;
        if kind.is_dir() {
            let skip = name.starts_with('.') || name == "target" || is_exempt(&format!("{path}/"));
            if !skip {
                collect(&entry.path(), &path, out)?;
            }
        } else if kind.is_file() && TextKind::of_path(&path).is_some() && !is_exempt(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Returns the sorted repository paths of the Markdown and Rust files under `root`.
///
/// The walk skips directories whose name starts with `.`, `target` directories and exempt paths.
///
/// # Errors
///
/// Returns the I/O error of a directory that the function cannot read.
pub fn repo_files(root: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    collect(root, "", &mut out)?;
    out.sort();
    Ok(out)
}

/// Returns the built-in lexicon plus the ban list and the glossary of `root`, when they exist.
#[must_use]
pub fn repo_lexicon(root: &Path) -> Lexicon {
    let mut lexicon = Lexicon::builtin();
    if let Ok(text) = std::fs::read_to_string(root.join(BANLIST_PATH)) {
        lexicon.add_banlist(&text);
    }
    if let Ok(text) = std::fs::read_to_string(root.join(GLOSSARY_PATH)) {
        lexicon.add_glossary(&text);
    }
    lexicon
}

/// Reads the allowlist of `root`. A missing file gives an empty allowlist.
///
/// # Errors
///
/// Returns [`AllowlistError`] when a line does not parse. A read error has line 0.
pub fn repo_allowlist(root: &Path) -> Result<Allowlist, AllowlistError> {
    match std::fs::read_to_string(root.join(ALLOWLIST_PATH)) {
        Ok(text) => Allowlist::parse(&text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Allowlist::default()),
        Err(e) => Err(AllowlistError {
            line: 0,
            message: e.to_string(),
        }),
    }
}

/// Checks every docs and comments file under `root`.
///
/// In [`Mode::Warn`] the allowlist applies. In [`Mode::Deny`] it does not.
///
/// # Errors
///
/// Returns the I/O error of a file or directory that the function cannot read.
pub fn scan_repo(
    root: &Path,
    checker: &Checker,
    mode: Mode,
    allowlist: &Allowlist,
) -> io::Result<ScanReport> {
    let files = repo_files(root)?;
    let mut report = ScanReport {
        files: files.len(),
        ..ScanReport::default()
    };
    let mut used: BTreeSet<usize> = BTreeSet::new();
    for path in &files {
        let bytes = std::fs::read(root.join(path))?;
        let text = String::from_utf8_lossy(&bytes);
        let Some(kind) = TextKind::of_path(path) else {
            continue;
        };
        for finding in checker.check(&text, kind) {
            let entry = (mode == Mode::Warn)
                .then(|| allowlist.matching(path, &finding))
                .flatten();
            if let Some(index) = entry {
                used.insert(index);
                report.allowed += 1;
            } else {
                report.findings.push(FileFinding {
                    path: path.clone(),
                    finding,
                });
            }
        }
    }
    if mode == Mode::Warn {
        report.unused = allowlist
            .entries()
            .iter()
            .enumerate()
            .filter(|(i, _)| !used.contains(i))
            .map(|(_, e)| e.clone())
            .collect();
    }
    Ok(report)
}
