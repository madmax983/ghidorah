//! Comment text of Rust source.
//!
//! The reader skips string literals, raw strings, character literals and
//! lifetimes, so a `//` inside a string does not start a comment.

use super::blocks::{Paragraph, markdown_lines};

/// Consecutive comment lines.
struct Block {
    first_line: usize,
    last_line: usize,
    lines: Vec<String>,
    /// `true` when each line has no code before the comment.
    standalone: bool,
}

/// Reads the source and keeps the comment blocks.
struct Scanner {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    code_on_line: bool,
    blocks: Vec<Block>,
}

impl Scanner {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn add_line_comment(&mut self, text: String, standalone: bool) {
        let line = self.line;
        if let Some(last) = self.blocks.last_mut()
            && standalone
            && last.standalone
            && last.last_line + 1 == line
        {
            last.lines.push(text);
            last.last_line = line;
            return;
        }
        self.blocks.push(Block {
            first_line: line,
            last_line: line,
            lines: vec![text],
            standalone,
        });
    }

    /// Reads a `//` comment. The reader stops before the line end.
    fn line_comment(&mut self) {
        let start = self.pos + 2;
        let mut end = start;
        while self.chars.get(end).is_some_and(|c| *c != '\n') {
            end += 1;
        }
        let mut body: &[char] = &self.chars[start..end];
        if matches!(body.first(), Some('!'))
            || (body.first() == Some(&'/') && body.get(1) != Some(&'/'))
        {
            body = &body[1..];
        }
        let text: String = body.iter().collect();
        let standalone = !self.code_on_line;
        self.add_line_comment(
            text.strip_prefix(' ').unwrap_or(&text).to_string(),
            standalone,
        );
        self.pos = end;
    }

    /// Reads a `/* */` comment with nesting.
    fn block_comment(&mut self) {
        let first_line = self.line;
        let mut depth = 0usize;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '/' && self.peek(1) == Some('*') {
                depth += 1;
                self.pos += 2;
                text.push(' ');
                if depth == 1
                    && matches!(self.peek(0), Some('*' | '!'))
                    && self.peek(1) != Some('/')
                {
                    self.pos += 1;
                }
            } else if c == '*' && self.peek(1) == Some('/') {
                depth = depth.saturating_sub(1);
                self.pos += 2;
                text.push(' ');
                if depth == 0 {
                    break;
                }
            } else {
                if c == '\n' {
                    self.line += 1;
                }
                text.push(c);
                self.pos += 1;
            }
        }
        let lines = text
            .split('\n')
            .map(|l| {
                let t = l.trim();
                t.strip_prefix('*').map_or(t, str::trim_start).to_string()
            })
            .collect();
        self.blocks.push(Block {
            first_line,
            last_line: self.line,
            lines,
            standalone: false,
        });
    }

    /// Skips a string literal that starts with `"` at the current position.
    fn string(&mut self) {
        self.pos += 1;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '\\' => {
                    if self.peek(0) == Some('\n') {
                        self.line += 1;
                    }
                    self.pos += 1;
                }
                '"' => break,
                '\n' => self.line += 1,
                _ => {}
            }
        }
    }

    /// Skips a raw string whose `#` marks start at the current position.
    fn raw_string(&mut self) {
        let hashes = self.chars[self.pos..]
            .iter()
            .take_while(|c| **c == '#')
            .count();
        self.pos += hashes + 1;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            if c == '\n' {
                self.line += 1;
            } else if c == '"' {
                let closing = self.chars[self.pos..]
                    .iter()
                    .take(hashes)
                    .filter(|h| **h == '#')
                    .count();
                if closing == hashes {
                    self.pos += hashes;
                    break;
                }
            }
        }
    }

    /// Skips a character literal, or the quote of a lifetime.
    fn quote(&mut self) {
        if self.peek(1) == Some('\\') {
            let mut j = self.pos + 3;
            while j < self.pos + 14 && self.chars.get(j).is_some_and(|c| *c != '\'') {
                j += 1;
            }
            self.pos = (j + 1).min(self.chars.len());
        } else if self.peek(2) == Some('\'') {
            self.pos += 3;
        } else {
            self.pos += 1;
        }
    }

    /// Skips an identifier. A raw string prefix such as `r#` starts a raw string.
    fn identifier(&mut self) {
        let start = self.pos;
        while self
            .peek(0)
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            self.pos += 1;
        }
        let word: String = self.chars[start..self.pos].iter().collect();
        let raw_prefix = matches!(word.as_str(), "r" | "br" | "cr");
        if raw_prefix && matches!(self.peek(0), Some('#' | '"')) {
            let hashes = self.chars[self.pos..]
                .iter()
                .take_while(|c| **c == '#')
                .count();
            if self.chars.get(self.pos + hashes) == Some(&'"') {
                self.raw_string();
            }
        }
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                '\n' => {
                    self.line += 1;
                    self.code_on_line = false;
                    self.pos += 1;
                }
                _ if c.is_whitespace() => self.pos += 1,
                '/' if self.peek(1) == Some('/') => self.line_comment(),
                '/' if self.peek(1) == Some('*') => self.block_comment(),
                '"' => {
                    self.code_on_line = true;
                    self.string();
                }
                '\'' => {
                    self.code_on_line = true;
                    self.quote();
                }
                _ if c.is_alphabetic() || c == '_' => {
                    self.code_on_line = true;
                    self.identifier();
                }
                _ => {
                    self.code_on_line = true;
                    self.pos += 1;
                }
            }
        }
    }
}

/// Returns the paragraphs of the comments of Rust source `text`.
pub(crate) fn paragraphs(text: &str) -> Vec<Paragraph> {
    let mut scanner = Scanner {
        chars: text.chars().collect(),
        pos: 0,
        line: 1,
        code_on_line: false,
        blocks: Vec::new(),
    };
    scanner.run();
    let mut out = Vec::new();
    for block in &scanner.blocks {
        let lines: Vec<&str> = block.lines.iter().map(String::as_str).collect();
        out.extend(markdown_lines(&lines, block.first_line));
    }
    out
}
