//! Paragraphs of plain text and Markdown.

/// One paragraph: the text and the 1-based line where it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Paragraph {
    pub(crate) line: usize,
    pub(crate) text: String,
}

/// Collects lines into paragraphs.
struct Builder {
    out: Vec<Paragraph>,
    current: Option<Paragraph>,
    clean: bool,
}

impl Builder {
    const fn new(clean: bool) -> Self {
        Self {
            out: Vec::new(),
            current: None,
            clean,
        }
    }

    /// Adds a line to the current paragraph, or starts a paragraph.
    fn push(&mut self, line: usize, text: &str) {
        match &mut self.current {
            Some(p) => {
                p.text.push('\n');
                p.text.push_str(text);
            }
            None => {
                self.current = Some(Paragraph {
                    line,
                    text: text.to_string(),
                });
            }
        }
    }

    /// Ends the current paragraph.
    fn flush(&mut self) {
        if let Some(mut p) = self.current.take() {
            if self.clean {
                p.text = clean_inline(&p.text);
            }
            if !p.text.trim().is_empty() {
                self.out.push(p);
            }
        }
    }

    /// Makes a paragraph from one text, for example a table cell.
    fn single(&mut self, line: usize, text: &str) {
        self.flush();
        self.push(line, text);
        self.flush();
    }

    fn finish(mut self) -> Vec<Paragraph> {
        self.flush();
        self.out
    }
}

/// Splits plain text at blank lines.
pub(crate) fn plain(text: &str) -> Vec<Paragraph> {
    let mut b = Builder::new(false);
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            b.flush();
        } else {
            b.push(i + 1, line);
        }
    }
    b.finish()
}

/// Splits Markdown text into paragraphs.
pub(crate) fn markdown(text: &str) -> Vec<Paragraph> {
    let lines: Vec<&str> = text.lines().collect();
    markdown_lines(&lines, 1)
}

/// Returns the fence marker and its length when `line` opens a code fence.
fn opens_fence(line: &str) -> Option<(char, usize)> {
    let marker = line.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let len = line.chars().take_while(|c| *c == marker).count();
    (len >= 3).then_some((marker, len))
}

fn closes_fence(line: &str, marker: char, len: usize) -> bool {
    let run = line.chars().take_while(|c| *c == marker).count();
    run >= len && line.chars().skip(run).all(char::is_whitespace)
}

/// Removes block quote marks from the start of `line`.
fn strip_quote(line: &str) -> &str {
    let mut rest = line;
    while let Some(after) = rest.strip_prefix('>') {
        rest = after.trim_start();
    }
    rest
}

fn is_heading(line: &str) -> bool {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    (1..=6).contains(&hashes) && line.chars().nth(hashes).is_none_or(char::is_whitespace)
}

fn is_rule(line: &str) -> bool {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    let first = compact.chars().next();
    compact.len() >= 3
        && compact.chars().all(|c| matches!(c, '-' | '*' | '_' | '='))
        && compact.chars().all(|c| Some(c) == first)
}

/// Returns `true` for a link definition line such as `[name]: target`.
fn is_link_definition(line: &str) -> bool {
    line.strip_prefix('[')
        .and_then(|rest| rest.split_once("]:"))
        .is_some_and(|(name, _)| !name.contains(']'))
}

/// Returns the text after a list marker, or `None` when `line` is not a list item.
fn list_item(line: &str) -> Option<&str> {
    if let Some(rest) = ["- ", "* ", "+ "]
        .iter()
        .find_map(|marker| line.strip_prefix(marker))
    {
        return Some(rest.trim_start());
    }
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = line.get(digits..)?;
    let rest = rest.strip_prefix('.').or_else(|| rest.strip_prefix(')'))?;
    rest.strip_prefix(' ').map(str::trim_start)
}

/// Splits a table row into cells. A `|` inside a code span does not split.
fn table_cells(row: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut in_code = false;
    let mut chars = row.trim().chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '`' => {
                in_code = !in_code;
                cell.push(c);
            }
            '\\' if chars.peek() == Some(&'|') => {
                cell.push('|');
                chars.next();
            }
            '|' if !in_code => cells.push(std::mem::take(&mut cell)),
            _ => cell.push(c),
        }
    }
    cells.push(cell);
    if cells.first().is_some_and(|c| c.trim().is_empty()) {
        cells.remove(0);
    }
    if cells.last().is_some_and(|c| c.trim().is_empty()) {
        cells.pop();
    }
    cells
}

fn is_separator_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|c| {
            let c = c.trim().trim_matches(':');
            !c.is_empty() && c.chars().all(|ch| ch == '-')
        })
}

/// Splits Markdown lines into paragraphs. `first_line` is the number of `lines[0]`.
///
/// The function skips headings, fenced blocks, HTML comments, rules and
/// link definitions. A table row gives one paragraph for each cell. The
/// function skips the header row of a table. A list item starts a new paragraph.
pub(crate) fn markdown_lines(lines: &[&str], first_line: usize) -> Vec<Paragraph> {
    let mut b = Builder::new(true);
    let mut fence: Option<(char, usize)> = None;
    let mut html_comment = false;
    for (i, raw) in lines.iter().enumerate() {
        let number = first_line + i;
        let trimmed = raw.trim();
        if let Some((marker, len)) = fence {
            if closes_fence(trimmed, marker, len) {
                fence = None;
            }
            continue;
        }
        if html_comment {
            html_comment = !trimmed.contains("-->");
            continue;
        }
        if let Some(open) = opens_fence(trimmed) {
            b.flush();
            fence = Some(open);
            continue;
        }
        if trimmed.starts_with("<!--") {
            b.flush();
            html_comment = !trimmed.contains("-->");
            continue;
        }
        let body = strip_quote(trimmed);
        if body.is_empty() || is_heading(body) || is_rule(body) || is_link_definition(body) {
            b.flush();
        } else if body.starts_with('|') {
            let cells = table_cells(body);
            let next_is_separator = lines.get(i + 1).is_some_and(|next| {
                let next = strip_quote(next.trim());
                next.starts_with('|') && is_separator_row(&table_cells(next))
            });
            b.flush();
            if !is_separator_row(&cells) && !next_is_separator {
                for cell in cells.iter().filter(|c| !c.trim().is_empty()) {
                    b.single(number, cell.trim());
                }
            }
        } else if let Some(item) = list_item(body) {
            b.flush();
            b.push(number, item);
        } else {
            b.push(number, body);
        }
    }
    b.finish()
}

/// Returns the index of the closing mark of a span that starts at `start`.
///
/// The search skips code spans. `open` and `close` count for nesting.
fn find_close(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while let Some(&c) = chars.get(i) {
        if c == '`' {
            let run = chars[i..].iter().take_while(|x| **x == '`').count();
            i = find_code_end(chars, i, run);
            continue;
        }
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Removes link targets, image marks, inline HTML and bold marks. Code spans stay as they are.
pub(crate) fn clean_inline(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        match c {
            '`' => {
                let run = chars[i..].iter().take_while(|x| **x == '`').count();
                let end = find_code_end(&chars, i, run);
                out.extend(&chars[i..end]);
                i = end;
            }
            '!' if chars.get(i + 1) == Some(&'[') => i += 1,
            '[' => {
                let Some(close) = find_close(&chars, i, '[', ']') else {
                    i += 1;
                    continue;
                };
                let inner: String = chars[i + 1..close].iter().collect();
                out.push_str(&clean_inline(&inner));
                i = close + 1;
                let target = match chars.get(i) {
                    Some('(') => find_close(&chars, i, '(', ')'),
                    Some('[') => find_close(&chars, i, '[', ']'),
                    _ => None,
                };
                if let Some(end) = target {
                    i = end + 1;
                }
            }
            '<' if chars
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || *n == '/' || *n == '!') =>
            {
                if let Some(len) = chars[i..].iter().take(120).position(|x| *x == '>') {
                    i += len + 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            '*' if chars.get(i + 1) == Some(&'*') => i += 2,
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Returns the index after the code span that starts at `start`, or after the run when it has no end.
fn find_code_end(chars: &[char], start: usize, run: usize) -> usize {
    let mut j = start + run;
    while j < chars.len() {
        let len = chars[j..].iter().take_while(|x| **x == '`').count();
        if len == run {
            return j + len;
        }
        j += len.max(1);
    }
    start + run
}
