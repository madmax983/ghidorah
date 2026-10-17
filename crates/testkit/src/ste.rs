//! The ASD-STE100 checker of ADR-0019.
//!
//! The checker reads plain text, Markdown or the comments of Rust source.
//! It gives one [`Finding`] per broken rule:
//!
//! | Rule | Check |
//! |---|---|
//! | STE-1 | A procedural sentence has at most 20 words. |
//! | STE-2 | A descriptive sentence has at most 25 words. |
//! | STE-3 | A paragraph has at most 6 sentences. |
//! | STE-4 | No passive voice (a form of "be" plus a participle). |
//! | STE-5 | No present perfect (a form of "have" plus a participle). |
//! | STE-6 | No word of the ban list. |
//! | STE-7 | No run of more than 3 nouns. |
//! | STE-8 | No two imperatives joined by "and". |
//!
//! A sentence is procedural when its first word is an imperative of the [`Lexicon`].
//!
//! Counting rules: a code span counts as one word. A parenthetical counts as
//! one word. A comma enumeration of code spans counts as one word. A list after
//! a label and a colon counts as one word. Markdown table cells count as text.
//! The checker skips headings, fenced blocks and Mermaid blocks.
//!
//! Modes: [`Mode::Deny`] is for agent-facing text and ignores the allowlist.
//! [`Mode::Warn`] is for docs and comments and applies the allowlist.
//!
//! Allowlist format (`docs/ste-allowlist.txt`): one entry per line,
//! `<path> <rule> <fragment>`. The entry allows a finding of `<rule>` in the file
//! `<path>` when the sentence contains `<fragment>`. Lines that start with `#` are comments.
//!
//! Ban list format (`docs/ste-banlist.txt`): one word per line. Lines that start with `#` are comments.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::Path;

/// The paths that the checker never reads. A path that ends with `/` is a directory.
pub const EXEMPT_PATHS: [&str; 2] = ["docs/research.md", "docs/planning/"];

/// The repository path of the allowlist.
pub const ALLOWLIST_PATH: &str = "docs/ste-allowlist.txt";

/// The repository path of the ban list.
pub const BANLIST_PATH: &str = "docs/ste-banlist.txt";

/// The repository path of the glossary with the approved verbs.
pub const GLOSSARY_PATH: &str = "docs/GLOSSARY.md";

/// The largest number of words in a procedural sentence (STE-1).
pub const MAX_PROCEDURAL_WORDS: usize = 20;

/// The largest number of words in a descriptive sentence (STE-2).
pub const MAX_DESCRIPTIVE_WORDS: usize = 25;

/// The largest number of sentences in a paragraph (STE-3).
pub const MAX_PARAGRAPH_SENTENCES: usize = 6;

/// The largest number of nouns in a row (STE-7).
pub const MAX_NOUN_RUN: usize = 3;

/// One rule of the checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// STE-1: a procedural sentence has at most 20 words.
    Ste1,
    /// STE-2: a descriptive sentence has at most 25 words.
    Ste2,
    /// STE-3: a paragraph has at most 6 sentences.
    Ste3,
    /// STE-4: no passive voice.
    Ste4,
    /// STE-5: no present perfect.
    Ste5,
    /// STE-6: no word of the ban list.
    Ste6,
    /// STE-7: no run of more than 3 nouns.
    Ste7,
    /// STE-8: no two imperatives joined by "and".
    Ste8,
}

impl Rule {
    /// All rules in ID order.
    pub const ALL: [Self; 8] = [
        Self::Ste1,
        Self::Ste2,
        Self::Ste3,
        Self::Ste4,
        Self::Ste5,
        Self::Ste6,
        Self::Ste7,
        Self::Ste8,
    ];

    /// Returns the rule ID, for example `STE-4`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ste1 => "STE-1",
            Self::Ste2 => "STE-2",
            Self::Ste3 => "STE-3",
            Self::Ste4 => "STE-4",
            Self::Ste5 => "STE-5",
            Self::Ste6 => "STE-6",
            Self::Ste7 => "STE-7",
            Self::Ste8 => "STE-8",
        }
    }

    /// Parses a rule ID such as `STE-4`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.id() == id)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The checker mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Agent-facing text. Each finding is an error, and the allowlist does not apply.
    Deny,
    /// Docs and comments. The allowlist applies.
    Warn,
}

/// The kind of a text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    /// Plain text. A blank line ends a paragraph.
    Plain,
    /// Markdown.
    Markdown,
    /// Rust source. The checker reads only the comments.
    RustComments,
}

impl TextKind {
    /// Returns the kind for a file path: `.md` gives Markdown and `.rs` gives Rust comments.
    #[must_use]
    pub fn of_path(path: &str) -> Option<Self> {
        let _ = path;
        None
    }
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The 1-based line where the sentence starts.
    pub line: usize,
    /// The broken rule.
    pub rule: Rule,
    /// The sentence, with spaces in place of line ends.
    pub sentence: String,
    /// What broke the rule, for example `is used` or `27 words`.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} line {} ({}): {}",
            self.rule, self.line, self.detail, self.sentence
        )
    }
}

/// The word lists of the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lexicon {
    imperatives: BTreeSet<String>,
    banned: BTreeSet<String>,
}

impl Lexicon {
    /// Returns the built-in lexicon: the imperative verbs and the ban list of ADR-0019.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            imperatives: BTreeSet::new(),
            banned: BTreeSet::new(),
        }
    }

    /// Adds the words of a ban list file.
    pub fn add_banlist(&mut self, text: &str) {
        let _ = text;
    }

    /// Adds the verbs of a glossary file.
    ///
    /// A verb is a table row whose second cell is `verb`, or a list item
    /// `- word (verb)`. The first cell or the item word is the verb.
    pub fn add_glossary(&mut self, text: &str) {
        let _ = text;
    }

    /// Returns `true` when `word` is an imperative verb, in any letter case.
    #[must_use]
    pub fn is_imperative(&self, word: &str) -> bool {
        self.imperatives.contains(word)
    }

    /// Returns `true` when `word` or its base form is on the ban list, in any letter case.
    #[must_use]
    pub fn is_banned(&self, word: &str) -> bool {
        self.banned.contains(word)
    }
}

/// The checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checker {
    lexicon: Lexicon,
}

impl Checker {
    /// Makes a checker with `lexicon`.
    #[must_use]
    pub const fn new(lexicon: Lexicon) -> Self {
        Self { lexicon }
    }

    /// Returns the lexicon of the checker.
    #[must_use]
    pub const fn lexicon(&self) -> &Lexicon {
        &self.lexicon
    }

    /// Checks `text` of `kind` and returns the findings in line order.
    #[must_use]
    pub fn check(&self, text: &str, kind: TextKind) -> Vec<Finding> {
        let _ = (text, kind);
        Vec::new()
    }
}

/// Checks agent-facing text in deny mode with the built-in lexicon.
///
/// Tool descriptions, messages and hints use this function.
#[must_use]
pub fn check_agent_text(text: &str) -> Vec<Finding> {
    Checker::new(Lexicon::builtin()).check(text, TextKind::Plain)
}

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowEntry {
    /// The repository path with `/` separators.
    pub path: String,
    /// The allowed rule.
    pub rule: Rule,
    /// A text that the sentence contains.
    pub fragment: String,
}

impl AllowEntry {
    /// Makes the entry that allows `finding` in `path`.
    ///
    /// The fragment is the first 8 words of the sentence.
    #[must_use]
    pub fn for_finding(path: &str, finding: &Finding) -> Self {
        Self {
            path: path.to_string(),
            rule: finding.rule,
            fragment: String::new(),
        }
    }

    /// Returns `true` when the entry allows `finding` in `path`.
    #[must_use]
    pub fn allows(&self, path: &str, finding: &Finding) -> bool {
        let _ = (path, finding);
        false
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.path, self.rule, self.fragment)
    }
}

/// An allowlist line that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistError {
    /// The 1-based line.
    pub line: usize,
    /// What is wrong with the line.
    pub message: String,
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "allowlist line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for AllowlistError {}

/// The reviewed allowlist of warn mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

impl Allowlist {
    /// Parses the allowlist format of this module.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError`] for a line with no path, an unknown rule or no fragment.
    pub fn parse(text: &str) -> Result<Self, AllowlistError> {
        let _ = text;
        Ok(Self::default())
    }

    /// Returns the entries in file order.
    #[must_use]
    pub fn entries(&self) -> &[AllowEntry] {
        &self.entries
    }

    /// Returns `true` when an entry allows `finding` in `path`.
    #[must_use]
    pub fn allows(&self, path: &str, finding: &Finding) -> bool {
        self.entries.iter().any(|e| e.allows(path, finding))
    }
}

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

/// Returns `true` when the checker never reads `path`.
#[must_use]
pub fn is_exempt(path: &str) -> bool {
    let _ = path;
    false
}

/// Returns the sorted repository paths of the Markdown and Rust files under `root`.
///
/// The walk skips directories whose name starts with `.`, `target` directories and exempt paths.
///
/// # Errors
///
/// Returns the I/O error of a directory that cannot be read.
pub fn repo_files(root: &Path) -> io::Result<Vec<String>> {
    let _ = root;
    Ok(Vec::new())
}

/// Returns the built-in lexicon plus the ban list and the glossary of `root`, when they exist.
#[must_use]
pub fn repo_lexicon(root: &Path) -> Lexicon {
    let _ = root;
    Lexicon::builtin()
}

/// Reads the allowlist of `root`. A missing file gives an empty allowlist.
///
/// # Errors
///
/// Returns [`AllowlistError`] when a line does not parse. A read error has line 0.
pub fn repo_allowlist(root: &Path) -> Result<Allowlist, AllowlistError> {
    let _ = root;
    Ok(Allowlist::default())
}

/// Checks every docs and comments file under `root`.
///
/// In [`Mode::Warn`] the allowlist applies. In [`Mode::Deny`] it does not.
///
/// # Errors
///
/// Returns the I/O error of a file or directory that cannot be read.
pub fn scan_repo(
    root: &Path,
    checker: &Checker,
    mode: Mode,
    allowlist: &Allowlist,
) -> io::Result<ScanReport> {
    let _ = (root, checker, mode, allowlist);
    Ok(ScanReport::default())
}
