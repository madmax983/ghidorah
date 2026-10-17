//! Loader diagnostics and the load error (design Section 4.8, ADR-0002).
//!
//! A [`Diagnostic`] is data. It names a frozen [`DiagCode`], the place in the file and the sizes.
//! A malformed table gives a diagnostic, and the load continues. Only a bad magic or a
//! truncated main header stops the load with [`LoadError::Malformed`].

use std::fmt;

use ghidorah_base::{DiagCode, ErrorCode};

/// The largest number of diagnostics that one load keeps. The load counts the others.
pub const MAX_DIAGNOSTICS: usize = 1024;

/// One loader diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The frozen code.
    pub code: DiagCode,
    /// The place in the file, for example `elf.dynamic[7]` or `elf.shdr[12].sh_entsize`.
    pub path: String,
    /// The file offset or the address of the place, if known.
    pub offset: Option<u64>,
    /// The size or the value that the parser needs.
    pub need: Option<u64>,
    /// The size or the value that the file has.
    pub have: Option<u64>,
    /// A short fact for the reader of the diagnostic.
    pub hint: Option<&'static str>,
}

impl Diagnostic {
    /// Makes a diagnostic with a code and a path and no other fields.
    #[must_use]
    pub fn new(code: DiagCode, path: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            offset: None,
            need: None,
            have: None,
            hint: None,
        }
    }

    /// Sets the offset.
    #[must_use]
    pub const fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets the needed size or value.
    #[must_use]
    pub const fn need(mut self, need: u64) -> Self {
        self.need = Some(need);
        self
    }

    /// Sets the size or value that the file has.
    #[must_use]
    pub const fn have(mut self, have: u64) -> Self {
        self.have = Some(have);
        self
    }

    /// Sets the hint.
    #[must_use]
    pub const fn hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.code.name(), self.path)?;
        if let Some(offset) = self.offset {
            write!(f, ", offset {offset:#x}")?;
        }
        if let Some(need) = self.need {
            write!(f, ", need {need:#x}")?;
        }
        if let Some(have) = self.have {
            write!(f, ", have {have:#x}")?;
        }
        if let Some(hint) = self.hint {
            write!(f, ": {hint}")?;
        }
        Ok(())
    }
}

/// The diagnostics of one load, with a cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Diags {
    list: Vec<Diagnostic>,
    dropped: u64,
}

impl Diags {
    /// Adds a diagnostic. Above [`MAX_DIAGNOSTICS`], the collector only counts it.
    pub(crate) fn push(&mut self, diag: Diagnostic) {
        if self.list.len() < MAX_DIAGNOSTICS {
            self.list.push(diag);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Gives the kept diagnostics and the count of dropped ones.
    pub(crate) fn into_parts(self) -> (Vec<Diagnostic>, u64) {
        (self.list, self.dropped)
    }
}

/// The error of a load. The load gives no [`Binary`](crate::Binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The file is larger than the file size limit.
    TooLarge {
        /// The file size in bytes.
        size: u64,
        /// The limit in bytes.
        limit: u64,
    },
    /// The probe found a format that does not load fully.
    UnsupportedFormat {
        /// The format name of the probe, for example `elf32-le` or `macho64`.
        detected: String,
        /// The formats that load fully: [`SUPPORTED_FORMATS`](crate::SUPPORTED_FORMATS).
        supported: &'static [&'static str],
    },
    /// The magic is bad, or the main header is cut.
    Malformed(Diagnostic),
}

impl LoadError {
    /// Gives the tool error code of the error.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } => ErrorCode::LimitExceeded,
            Self::UnsupportedFormat { .. } => ErrorCode::UnsupportedFormat,
            Self::Malformed(_) => ErrorCode::FormatMalformed,
        }
    }

    /// Gives the diagnostic of a malformed file.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Self::Malformed(diag) => Some(diag),
            _ => None,
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, limit } => write!(
                f,
                "The file has {size} bytes. The limit is {limit} bytes. Use a smaller file."
            ),
            Self::UnsupportedFormat {
                detected,
                supported,
            } => write!(
                f,
                "The file format {detected} does not load. The supported formats are {}.",
                supported.join(", ")
            ),
            Self::Malformed(diag) => write!(f, "The file is malformed: {diag}."),
        }
    }
}

impl std::error::Error for LoadError {}
