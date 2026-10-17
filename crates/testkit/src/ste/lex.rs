//! Tokens and sentences of the STE checker.
//!
//! The lexer reads one paragraph. It gives sentences of tokens. A code span,
//! a parenthetical and a collapsed list are single tokens.

/// The kind of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A word.
    Word,
    /// A number.
    Num,
    /// A code span, or a comma enumeration of code spans.
    Code,
    /// A parenthetical.
    Paren,
    /// A list after a label and a colon.
    List,
    /// A comma.
    Comma,
    /// A colon.
    Colon,
    /// Any other mark. It ends a noun cluster.
    Break,
}

/// One token.
#[derive(Debug, Clone)]
pub(crate) struct Tok {
    pub(crate) kind: Kind,
    /// The text as written.
    pub(crate) text: String,
    /// The lower case text without edge marks.
    pub(crate) norm: String,
    /// The 1-based line.
    pub(crate) line: usize,
    /// The words inside a parenthetical, lower case.
    pub(crate) inner: Vec<String>,
    /// `true` for a word that looks like code: `snake_case`, `CamelCase`, `ACRONYM`, `x86`.
    pub(crate) code_like: bool,
}

impl Tok {
    fn new(kind: Kind, text: &str, line: usize) -> Self {
        Self {
            kind,
            text: text.to_string(),
            norm: norm(text),
            line,
            inner: Vec::new(),
            code_like: false,
        }
    }

    /// Returns `true` for a word that is not code.
    pub(crate) fn is_plain_word(&self) -> bool {
        self.kind == Kind::Word && !self.code_like
    }

    /// Returns `true` when the token counts as one word.
    pub(crate) const fn counts(&self) -> bool {
        matches!(
            self.kind,
            Kind::Word | Kind::Num | Kind::Code | Kind::Paren | Kind::List
        )
    }
}

/// One sentence.
#[derive(Debug, Clone)]
pub(crate) struct Sentence {
    /// The 1-based line of the first token.
    pub(crate) line: usize,
    /// The text with single spaces.
    pub(crate) text: String,
    pub(crate) toks: Vec<Tok>,
}

/// Returns the lower case text without non-alphanumeric marks at both ends.
pub(crate) fn norm(text: &str) -> String {
    text.trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

/// Returns `true` when `text` looks like code and not like a plain word.
fn looks_like_code(text: &str) -> bool {
    let lower = norm(text);
    if lower == "e.g" || lower == "i.e" {
        return false;
    }
    if text.chars().count() == 1 && !matches!(lower.as_str(), "a" | "i") {
        return true;
    }
    let letters = text.chars().filter(|c| c.is_alphabetic()).count();
    let upper = text.chars().filter(|c| c.is_uppercase()).count();
    let lower_count = text.chars().filter(|c| c.is_lowercase()).count();
    let inner_upper = text.chars().skip(1).any(char::is_uppercase);
    text.contains(['_', '/', '.'])
        || text.contains("::")
        || text.chars().any(|c| c.is_ascii_digit()) && letters > 0
        || inner_upper && lower_count > 0
        || upper >= 2 && lower_count == 0
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Finds the end of a code span that starts at `start` with a run of backticks.
///
/// Returns the run length and the index after the closing run.
fn code_span_end(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let run = chars[start..].iter().take_while(|c| **c == '`').count();
    let mut i = start + run;
    while i < chars.len() {
        if chars[i] == '`' {
            let len = chars[i..].iter().take_while(|c| **c == '`').count();
            if len == run {
                return Some((run, i + len));
            }
            i += len;
        } else {
            i += 1;
        }
    }
    None
}

/// Finds the index of the `)` that matches the `(` at `start`.
fn paren_end(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '`' => match code_span_end(chars, i) {
                Some((_, next)) => {
                    i = next;
                    continue;
                }
                None => i += chars[i..].iter().take_while(|c| **c == '`').count() - 1,
            },
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Returns the length of the word that starts at `start`.
fn word_len(chars: &[char], start: usize) -> usize {
    let mut j = start;
    while let Some(&c) = chars.get(j) {
        let next = chars.get(j + 1).copied();
        let joins = |n: Option<char>| n.is_some_and(is_word_char);
        let joined = matches!(c, '\'' | '’' | '-' | '.' | '/') && joins(next) && j > start;
        if is_word_char(c) || joined {
            j += 1;
        } else if c == ':'
            && next == Some(':')
            && chars.get(j + 2).is_some_and(|n| is_word_char(*n))
        {
            j += 2;
        } else {
            break;
        }
    }
    j - start
}

/// Collects the words of the parenthetical text `inner`.
fn inner_words(inner: &str, line: usize) -> Vec<String> {
    let mut out = Vec::new();
    for sentence in lex(inner, line) {
        for tok in sentence.toks {
            if tok.kind == Kind::Word {
                out.push(tok.norm);
            }
            out.extend(tok.inner);
        }
    }
    out
}

/// Returns `true` when a `.` at `i` ends a sentence.
fn ends_sentence(chars: &[char], i: usize) -> bool {
    match chars.get(i + 1) {
        None => true,
        Some(next) if next.is_whitespace() => {
            let after = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            !after.is_some_and(char::is_ascii_lowercase)
        }
        Some(_) => false,
    }
}

fn collapse_text(chars: &[char], from: usize, to: usize) -> String {
    chars[from..to]
        .iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Splits `text` into sentences. `first_line` is the line number of the first line.
pub(crate) fn lex(text: &str, first_line: usize) -> Vec<Sentence> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<Sentence> = Vec::new();
    let mut toks: Vec<Tok> = Vec::new();
    let mut start = 0;
    let mut line = first_line;
    let mut i = 0;
    let finish = |toks: &mut Vec<Tok>, out: &mut Vec<Sentence>, start: usize, end: usize| {
        let mut taken = std::mem::take(toks);
        if taken.iter().any(Tok::counts) {
            normalize(&mut taken);
            out.push(Sentence {
                line: taken.first().map_or(first_line, |t| t.line),
                text: collapse_text(&chars, start, end),
                toks: taken,
            });
        }
    };
    while let Some(&c) = chars.get(i) {
        if toks.is_empty() && !c.is_whitespace() {
            start = i;
        }
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '`' {
            let (len, next) = code_span_end(&chars, i).unwrap_or((0, i + 1));
            if len > 0 {
                let body: String = chars[i + len..next - len].iter().collect();
                toks.push(Tok::new(Kind::Code, &body, line));
                line += body.matches('\n').count();
            }
            i = next;
        } else if c == '(' {
            if let Some(end) = paren_end(&chars, i) {
                let body: String = chars[i + 1..end].iter().collect();
                let mut tok = Tok::new(Kind::Paren, &body, line);
                tok.inner = inner_words(&body, line);
                toks.push(tok);
                line += body.matches('\n').count();
                i = end + 1;
            } else {
                toks.push(Tok::new(Kind::Break, "(", line));
                i += 1;
            }
        } else if c.is_alphanumeric() {
            let len = word_len(&chars, i);
            let word: String = chars[i..i + len].iter().collect();
            let kind = if c.is_ascii_digit() && !word.chars().any(char::is_alphabetic) {
                Kind::Num
            } else {
                Kind::Word
            };
            let mut tok = Tok::new(kind, &word, line);
            tok.code_like = kind == Kind::Word && looks_like_code(&word);
            toks.push(tok);
            i += len.max(1);
        } else if c == ',' {
            toks.push(Tok::new(Kind::Comma, ",", line));
            i += 1;
        } else if c == ':' {
            toks.push(Tok::new(Kind::Colon, ":", line));
            i += 1;
        } else if matches!(c, '.' | '!' | '?') {
            if c != '.' || ends_sentence(&chars, i) {
                if chars.get(i + 1).is_none_or(|n| n.is_whitespace()) {
                    finish(&mut toks, &mut out, start, i + 1);
                } else {
                    toks.push(Tok::new(Kind::Break, &c.to_string(), line));
                }
            } else {
                toks.push(Tok::new(Kind::Break, ".", line));
            }
            i += 1;
        } else {
            toks.push(Tok::new(Kind::Break, &c.to_string(), line));
            i += 1;
        }
    }
    finish(&mut toks, &mut out, start, chars.len());
    out
}

/// Collapses enumerations of code spans and lists after a label.
fn normalize(toks: &mut Vec<Tok>) {
    collapse_code_enums(toks);
    collapse_label_list(toks);
}

fn is_and_or(tok: &Tok) -> bool {
    tok.kind == Kind::Word && matches!(tok.norm.as_str(), "and" | "or")
}

/// Replaces `` `a`, `b`, `c` `` and `` `a`, `b` and `c` `` with one code token.
fn collapse_code_enums(toks: &mut Vec<Tok>) {
    let mut out: Vec<Tok> = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        if toks[i].kind != Kind::Code {
            out.push(toks[i].clone());
            i += 1;
            continue;
        }
        let mut j = i;
        let mut commas = false;
        loop {
            let at = |k: usize| toks.get(k);
            let comma = at(j + 1).is_some_and(|t| t.kind == Kind::Comma);
            if comma && at(j + 2).is_some_and(|t| t.kind == Kind::Code) {
                j += 2;
                commas = true;
            } else if comma
                && at(j + 2).is_some_and(is_and_or)
                && at(j + 3).is_some_and(|t| t.kind == Kind::Code)
            {
                j += 3;
                commas = true;
            } else if commas
                && at(j + 1).is_some_and(is_and_or)
                && at(j + 2).is_some_and(|t| t.kind == Kind::Code)
            {
                j += 2;
                break;
            } else {
                break;
            }
        }
        if commas {
            let mut merged = toks[i].clone();
            merged.text = format!("{}, ...", toks[i].text);
            out.push(merged);
        } else {
            out.push(toks[i].clone());
        }
        i = j + 1;
    }
    *toks = out;
}

/// The longest label before a colon, in tokens.
const MAX_LABEL: usize = 8;

/// Replaces the tokens after `label:` with one list token when they hold a comma.
fn collapse_label_list(toks: &mut Vec<Tok>) {
    let colon = toks.iter().position(|t| t.kind == Kind::Colon);
    let Some(colon) = colon.filter(|c| *c >= 1 && *c <= MAX_LABEL) else {
        return;
    };
    let rest = &toks[colon + 1..];
    if rest.len() < 3 || !rest.iter().any(|t| t.kind == Kind::Comma) {
        return;
    }
    let line = rest.first().map_or(1, |t| t.line);
    toks.truncate(colon + 1);
    toks.push(Tok::new(Kind::List, "list", line));
}
