//! A small Rust lexer that removes comments and literal text.
//!
//! Gates search the stripped text, so a word in a comment or a string does not count.

/// Gives `text` with comments and the contents of string and char literals replaced by spaces.
///
/// Newlines stay in place, so line numbers do not change.
/// Quote characters of literals stay, so `"x"` becomes `" "`.
#[must_use]
pub fn strip(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut lexer = Lexer {
        chars: &chars,
        pos: 0,
        out: String::with_capacity(text.len()),
    };
    lexer.run();
    lexer.out
}

struct Lexer<'a> {
    chars: &'a [char],
    pos: usize,
    out: String,
}

const fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

impl Lexer<'_> {
    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn keep(&mut self) {
        if let Some(c) = self.at(0) {
            self.out.push(c);
        }
        self.pos += 1;
    }

    fn blank(&mut self) {
        if let Some(c) = self.at(0) {
            self.out.push(if c == '\n' { '\n' } else { ' ' });
        }
        self.pos += 1;
    }

    fn run(&mut self) {
        while let Some(c) = self.at(0) {
            let prev_ident = self
                .pos
                .checked_sub(1)
                .and_then(|p| self.chars.get(p))
                .is_some_and(|&p| is_ident(p));
            match c {
                '/' if self.at(1) == Some('/') => self.line_comment(),
                '/' if self.at(1) == Some('*') => self.block_comment(),
                '"' => self.string(),
                '\'' => self.char_or_lifetime(),
                'r' | 'b' | 'c' if !prev_ident => self.prefixed(),
                _ => self.keep(),
            }
        }
    }

    fn line_comment(&mut self) {
        while let Some(c) = self.at(0) {
            if c == '\n' {
                return;
            }
            self.blank();
        }
    }

    fn block_comment(&mut self) {
        let mut depth = 0usize;
        while let Some(c) = self.at(0) {
            if c == '/' && self.at(1) == Some('*') {
                depth += 1;
                self.blank();
                self.blank();
            } else if c == '*' && self.at(1) == Some('/') {
                self.blank();
                self.blank();
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return;
                }
            } else {
                self.blank();
            }
        }
    }

    fn string(&mut self) {
        self.keep();
        while let Some(c) = self.at(0) {
            match c {
                '"' => {
                    self.keep();
                    return;
                }
                '\\' => {
                    self.blank();
                    self.blank();
                }
                _ => self.blank(),
            }
        }
    }

    fn raw_string(&mut self, hashes: usize) {
        for _ in 0..=hashes {
            self.keep();
        }
        while let Some(c) = self.at(0) {
            if c == '"' && (1..=hashes).all(|i| self.at(i) == Some('#')) {
                for _ in 0..=hashes {
                    self.keep();
                }
                return;
            }
            self.blank();
        }
    }

    fn prefixed(&mut self) {
        let offset = usize::from(matches!(self.at(0), Some('b' | 'c')) && self.at(1) == Some('r'));
        let raw = self.at(offset) == Some('r');
        let mut hashes = 0;
        if raw {
            while self.at(offset + 1 + hashes) == Some('#') {
                hashes += 1;
            }
        }
        let quote_at = if raw { offset + 1 + hashes } else { 1 };
        let next = self.at(quote_at);
        if raw && next == Some('"') {
            for _ in 0..=offset {
                self.keep();
            }
            self.raw_string(hashes);
        } else if !raw && next == Some('"') {
            self.keep();
            self.string();
        } else if self.at(0) == Some('b') && self.at(1) == Some('\'') {
            self.keep();
            self.char_or_lifetime();
        } else {
            self.ident();
        }
    }

    fn ident(&mut self) {
        while self.at(0).is_some_and(is_ident) {
            self.keep();
        }
    }

    fn char_or_lifetime(&mut self) {
        if self.at(1) == Some('\\') {
            self.keep();
            while let Some(c) = self.at(0) {
                if c == '\'' {
                    self.keep();
                    return;
                }
                if c == '\\' {
                    self.blank();
                }
                self.blank();
            }
        } else if self.at(2) == Some('\'') {
            self.keep();
            self.blank();
            self.keep();
        } else {
            self.keep();
        }
    }
}

/// Gives the byte offsets where `word` occurs as a full identifier.
///
/// A match must not touch another identifier character on either side.
#[must_use]
pub fn find_word(text: &str, word: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let touches = |i: Option<usize>| {
        i.and_then(|i| bytes.get(i))
            .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_')
    };
    text.match_indices(word)
        .map(|(i, _)| i)
        .filter(|&i| !touches(i.checked_sub(1)) && !touches(i.checked_add(word.len())))
        .collect()
}

/// Gives the 1-based line number of a byte offset.
#[must_use]
pub fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()
        .get(..end)
        .map_or(1, |b| b.split(|&c| c == b'\n').count())
}
