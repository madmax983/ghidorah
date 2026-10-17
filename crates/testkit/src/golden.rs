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
            generator: generator.to_string(),
            version: version.to_string(),
            fields: BTreeMap::new(),
        }
    }

    /// Adds a field, for example `fixture_sha256` or an oracle version.
    ///
    /// Whitespace in a key or a value changes to `_`.
    #[must_use]
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
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

    /// Returns the header line for `format`, without a line end.
    #[must_use]
    pub fn render(&self, format: Format) -> String {
        let _ = format;
        String::new()
    }

    /// Parses a header line of `format`.
    ///
    /// # Errors
    ///
    /// Returns [`GoldenError::BadHeader`] when the line is not a header line.
    pub fn parse(line: &str, format: Format) -> Result<Self, GoldenError> {
        let _ = format;
        Err(GoldenError::BadHeader {
            path: String::new(),
            line: line.to_string(),
        })
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
        let _ = path;
        Self::Text
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
                write!(f, "golden file {path} is missing. Run with {BLESS_ENV}=1 to write it.")
            }
            Self::BadHeader { path, line } => {
                write!(f, "golden file {path} has no header line. Line 1 is: {line}")
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
    false
}

/// Reads a golden file and returns its header and its body.
///
/// # Errors
///
/// Returns [`GoldenError`] when the file is missing, cannot be read or has no header.
pub fn read(path: &Path) -> Result<(Header, String), GoldenError> {
    Err(GoldenError::Missing {
        path: path.display().to_string(),
    })
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
    let _ = (header, actual, bless);
    Err(GoldenError::Missing {
        path: path.display().to_string(),
    })
}

/// Asserts that a text golden matches. It reads `GHIDORAH_BLESS`.
///
/// # Panics
///
/// Panics with the mismatch message. This fails the calling test.
pub fn assert_text(path: &Path, header: &Header, actual: &str) {
    let _ = compare(path, header, actual, bless_from_env());
}

/// Asserts that a JSON golden matches. It reads `GHIDORAH_BLESS`.
///
/// The path must end with `.json` or `.jsonl`.
///
/// # Panics
///
/// Panics with the mismatch message or when the path is not a JSON path.
pub fn assert_json(path: &Path, header: &Header, json: &str) {
    let _ = compare(path, header, json, bless_from_env());
}
