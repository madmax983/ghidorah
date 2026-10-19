//! The error type of the harness.

use std::fmt;
use std::path::Path;

/// An error of the harness: an input file that does not read or that has bad data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// A file does not read or does not write.
    Io {
        /// The path, relative to the workspace root when possible.
        path: String,
        /// The message of the operating system.
        message: String,
    },
    /// A file is not valid JSON.
    Json {
        /// The path.
        path: String,
        /// The message of the parser.
        message: String,
    },
    /// A file has a value that the harness does not accept.
    Data {
        /// The path.
        path: String,
        /// What is wrong.
        message: String,
    },
    /// A bless run refuses a change (design Section 12.6).
    Bless {
        /// What the bless refuses.
        message: String,
    },
}

impl EvalError {
    /// Makes an [`EvalError::Io`] for `path`.
    #[must_use]
    pub fn io(path: &Path, error: &std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        }
    }

    /// Makes an [`EvalError::Data`] for `path`.
    #[must_use]
    pub fn data(path: &str, message: &str) -> Self {
        Self::Data {
            path: path.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "{path} does not read: {message}"),
            Self::Json { path, message } => write!(f, "{path} is not valid JSON: {message}"),
            Self::Data { path, message } => write!(f, "{path} has bad data: {message}"),
            Self::Bless { message } => write!(f, "the bless stops: {message}"),
        }
    }
}

impl std::error::Error for EvalError {}

/// Reads the text of `rel` under `root`.
///
/// # Errors
///
/// Returns [`EvalError::Io`] when the file does not read.
pub fn read_text(root: &Path, rel: &str) -> Result<String, EvalError> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| EvalError::Io {
        path: rel.to_owned(),
        message: e.to_string(),
    })
}

/// Parses the JSON text of the file `rel`.
///
/// # Errors
///
/// Returns [`EvalError::Json`] when the text is not valid JSON.
pub fn parse_json(rel: &str, text: &str) -> Result<ghidorah_json::Value, EvalError> {
    ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).map_err(|e| EvalError::Json {
        path: rel.to_owned(),
        message: e.to_string(),
    })
}

/// Reads and parses the JSON file `rel` under `root`.
///
/// # Errors
///
/// Returns [`EvalError::Io`] or [`EvalError::Json`].
pub fn read_json(root: &Path, rel: &str) -> Result<ghidorah_json::Value, EvalError> {
    parse_json(rel, &read_text(root, rel)?)
}

/// Reads and parses each non-blank line of the JSON Lines file `rel` under `root`.
///
/// # Errors
///
/// Returns [`EvalError::Io`] or [`EvalError::Json`] with the line number.
pub fn read_jsonl(root: &Path, rel: &str) -> Result<Vec<ghidorah_json::Value>, EvalError> {
    let text = read_text(root, rel)?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(parse_json(&format!("{rel}:{}", n.saturating_add(1)), line)?);
    }
    Ok(out)
}
