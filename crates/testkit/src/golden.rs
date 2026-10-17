//! Golden files with a header line.
//!
//! Each golden file starts with one header line. The header names the
//! generator, its version and other facts, for example a fixture sha256.
//! A text golden has the header `# golden: generator=G version=V key=value`.
//! A `.json` or `.jsonl` golden has the header `{"golden":"generator=G version=V"}`.
//! The body follows the header line.
//!
//! A golden matches when the header and the body are equal. When
//! `GHIDORAH_BLESS=1` is set, a mismatch rewrites the file.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// The environment variable that turns on bless mode.
pub const BLESS_ENV: &str = "GHIDORAH_BLESS";

/// The largest number of diff lines that a mismatch message shows.
pub const MAX_DIFF_LINES: usize = 8;

/// The prefix of a text header line.
const TEXT_PREFIX: &str = "# golden: ";

/// The prefix of a JSON header line.
const JSON_PREFIX: &str = "{\"golden\":\"";

/// The suffix of a JSON header line.
const JSON_SUFFIX: &str = "\"}";

/// Changes whitespace to `_`, so a value stays one header word.
fn word(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
}

/// The header of a golden file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    generator: String,
    version: String,
    fields: BTreeMap<String, String>,
}

impl Header {
    /// Makes a header with a generator name and a generator version.
    #[must_use]
    pub fn new(generator: &str, version: &str) -> Self {
        Self {
            generator: word(generator),
            version: word(version),
            fields: BTreeMap::new(),
        }
    }

    /// Adds a field, for example `fixture_sha256` or an oracle version.
    ///
    /// Whitespace in a key or a value changes to `_`. A `=` in a key also changes to `_`.
    #[must_use]
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(word(key).replace('=', "_"), word(value));
        self
    }

    /// Returns the generator name.
    #[must_use]
    pub fn generator(&self) -> &str {
        &self.generator
    }

    /// Returns the generator version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the value of a field.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// Returns the header words without a prefix.
    fn words(&self) -> String {
        let mut out = format!("generator={} version={}", self.generator, self.version);
        for (k, v) in &self.fields {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    }

    /// Returns the header line for `format`, without a line end.
    #[must_use]
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Text => format!("{TEXT_PREFIX}{}", self.words()),
            Format::Json => {
                let escaped = self.words().replace('\\', "\\\\").replace('"', "\\\"");
                format!("{JSON_PREFIX}{escaped}{JSON_SUFFIX}")
            }
        }
    }

    /// Parses a header line of `format`.
    ///
    /// # Errors
    ///
    /// Returns [`GoldenError::BadHeader`] when the line is not a header line.
    pub fn parse(line: &str, format: Format) -> Result<Self, GoldenError> {
        let bad = || GoldenError::BadHeader {
            path: String::new(),
            line: line.to_string(),
        };
        let words = match format {
            Format::Text => line.strip_prefix(TEXT_PREFIX).map(ToString::to_string),
            Format::Json => line
                .strip_prefix(JSON_PREFIX)
                .and_then(|rest| rest.strip_suffix(JSON_SUFFIX))
                .map(|w| w.replace("\\\"", "\"").replace("\\\\", "\\")),
        }
        .ok_or_else(bad)?;
        let mut pairs = words.split_whitespace().map(|w| w.split_once('='));
        let Some(Some(("generator", generator))) = pairs.next() else {
            return Err(bad());
        };
        let Some(Some(("version", version))) = pairs.next() else {
            return Err(bad());
        };
        let mut header = Self::new(generator, version);
        for pair in pairs {
            let Some((k, v)) = pair else {
                return Err(bad());
            };
            header.fields.insert(k.to_string(), v.to_string());
        }
        Ok(header)
    }
}

/// The header format of a golden file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A text golden with a `# golden:` header.
    Text,
    /// A JSON or JSON Lines golden with a `{"golden":..}` header.
    Json,
}

impl Format {
    /// Returns the format for a path: `.json` and `.jsonl` give `Json`, other paths give `Text`.
    #[must_use]
    pub fn of_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json" | "jsonl") => Self::Json,
            _ => Self::Text,
        }
    }
}

/// The result of a successful compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The file matched.
    Match,
    /// Bless mode wrote the file.
    Blessed,
}

/// A golden mismatch or a golden file error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoldenError {
    /// The golden file does not exist.
    Missing {
        /// The golden path.
        path: String,
    },
    /// The first line is not a header line.
    BadHeader {
        /// The golden path.
        path: String,
        /// The first line.
        line: String,
    },
    /// The header differs from the expected header.
    HeaderMismatch {
        /// The golden path.
        path: String,
        /// The expected header line.
        expected: String,
        /// The header line in the file.
        found: String,
    },
    /// The body differs from the actual text.
    BodyMismatch {
        /// The golden path.
        path: String,
        /// The 1-based body line of the first difference.
        line: usize,
        /// A short diff with at most [`MAX_DIFF_LINES`] lines.
        diff: String,
    },
    /// A file operation failed.
    Io {
        /// The golden path.
        path: String,
        /// The operating system message.
        message: String,
    },
}

impl fmt::Display for GoldenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { path } => {
                write!(
                    f,
                    "golden file {path} is missing. Run with {BLESS_ENV}=1 to write it."
                )
            }
            Self::BadHeader { path, line } => {
                write!(
                    f,
                    "golden file {path} has no header line. Line 1 is: {line}"
                )
            }
            Self::HeaderMismatch {
                path,
                expected,
                found,
            } => write!(
                f,
                "golden header of {path} differs. Expected: {expected}. Found: {found}. Run with {BLESS_ENV}=1 to rewrite it."
            ),
            Self::BodyMismatch { path, line, diff } => write!(
                f,
                "golden body of {path} differs at line {line}. Run with {BLESS_ENV}=1 to rewrite it.\n{diff}"
            ),
            Self::Io { path, message } => write!(f, "golden file error at {path}: {message}"),
        }
    }
}

impl std::error::Error for GoldenError {}

/// Returns `true` when `GHIDORAH_BLESS` is `1`.
#[must_use]
pub fn bless_from_env() -> bool {
    std::env::var(BLESS_ENV).is_ok_and(|v| v == "1")
}

fn io_error(path: &Path, e: &std::io::Error) -> GoldenError {
    GoldenError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    }
}

/// Reads a golden file and returns its header and its body.
///
/// # Errors
///
/// Returns [`GoldenError`] when the file is missing, cannot be read or has no header.
pub fn read(path: &Path) -> Result<(Header, String), GoldenError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GoldenError::Missing {
                path: path.display().to_string(),
            });
        }
        Err(e) => return Err(io_error(path, &e)),
    };
    let (first, body) = text.split_once('\n').unwrap_or((text.as_str(), ""));
    let header =
        Header::parse(first, Format::of_path(path)).map_err(|_| GoldenError::BadHeader {
            path: path.display().to_string(),
            line: first.to_string(),
        })?;
    Ok((header, body.to_string()))
}

/// Returns `text` with one line end at the end. Empty text stays empty.
fn with_line_end(text: &str) -> String {
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Returns the 1-based line of the first difference and a short diff.
fn first_difference(want: &str, got: &str) -> (usize, String) {
    let want_lines: Vec<&str> = want.lines().collect();
    let got_lines: Vec<&str> = got.lines().collect();
    let first = want_lines
        .iter()
        .zip(&got_lines)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want_lines.len().min(got_lines.len()));
    let mut diff = Vec::new();
    for i in first..first + MAX_DIFF_LINES / 2 {
        if let Some(line) = want_lines.get(i) {
            diff.push(format!("- {line}"));
        }
        if let Some(line) = got_lines.get(i) {
            diff.push(format!("+ {line}"));
        }
    }
    (first + 1, diff.join("\n"))
}

fn write_golden(path: &Path, header_line: &str, body: &str) -> Result<Outcome, GoldenError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_error(path, &e))?;
    }
    std::fs::write(path, format!("{header_line}\n{body}")).map_err(|e| io_error(path, &e))?;
    Ok(Outcome::Blessed)
}

/// Compares `actual` with the golden file at `path`.
///
/// With `bless`, a mismatch or a missing file writes the file and gives [`Outcome::Blessed`].
///
/// # Errors
///
/// Returns [`GoldenError`] on a mismatch without `bless`, or on a file error.
pub fn compare(
    path: &Path,
    header: &Header,
    actual: &str,
    bless: bool,
) -> Result<Outcome, GoldenError> {
    let format = Format::of_path(path);
    let header_line = header.render(format);
    let body = with_line_end(actual);
    let result = match read(path) {
        Ok((found, _)) if found != *header => Err(GoldenError::HeaderMismatch {
            path: path.display().to_string(),
            expected: header_line.clone(),
            found: found.render(format),
        }),
        Ok((_, found_body)) if found_body != body => {
            let (line, diff) = first_difference(&found_body, &body);
            Err(GoldenError::BodyMismatch {
                path: path.display().to_string(),
                line,
                diff,
            })
        }
        Ok(_) => Ok(Outcome::Match),
        Err(e) => Err(e),
    };
    match result {
        Err(GoldenError::Io { .. }) | Ok(_) => result,
        Err(_) if bless => write_golden(path, &header_line, &body),
        Err(_) => result,
    }
}

/// Asserts that a text golden matches. It reads `GHIDORAH_BLESS`.
///
/// # Panics
///
/// Panics with the mismatch message. This fails the calling test.
#[allow(clippy::panic, reason = "a golden mismatch must fail the calling test")]
pub fn assert_text(path: &Path, header: &Header, actual: &str) {
    if let Err(e) = compare(path, header, actual, bless_from_env()) {
        panic!("{e}");
    }
}

/// Asserts that a JSON golden matches. It reads `GHIDORAH_BLESS`.
///
/// The path must end with `.json` or `.jsonl`.
///
/// # Panics
///
/// Panics with the mismatch message or when the path is not a JSON path.
#[allow(clippy::panic, reason = "a golden mismatch must fail the calling test")]
pub fn assert_json(path: &Path, header: &Header, json: &str) {
    assert!(
        Format::of_path(path) == Format::Json,
        "assert_json needs a .json or .jsonl path, not {}",
        path.display()
    );
    assert_text(path, header, json);
}
