//! Message templates with placeholders such as `{field}`.

/// One piece of a template.
enum Piece<'a> {
    /// Literal text.
    Text(&'a str),
    /// The name of a placeholder, without the braces.
    Key(&'a str),
}

/// Gives the placeholder names of a template in text order, for example `["field"]`.
///
/// A placeholder is `{` and a name of `a-z` and `_`, then `}`.
#[must_use]
pub fn placeholders(template: &str) -> Vec<&str> {
    pieces(template)
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Key(key) => Some(key),
            Piece::Text(_) => None,
        })
        .collect()
}

/// Fills the placeholders of a template.
///
/// Each `{key}` with a pair in `args` changes to its value. Other text stays the same.
/// Values must hold no binary text (ADR-0022).
#[must_use]
pub fn render(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    for piece in pieces(template) {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Key(key) => {
                if let Some((_, value)) = args.iter().find(|(k, _)| *k == key) {
                    out.push_str(value);
                } else {
                    out.push('{');
                    out.push_str(key);
                    out.push('}');
                }
            }
        }
    }
    out
}

/// Splits a template into literal text and placeholders.
fn pieces(template: &str) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let (before, from_brace) = rest.split_at(open);
        let after = from_brace.get(1..).unwrap_or_default();
        let len = after
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || *b == b'_')
            .count();
        let key = after.get(..len).unwrap_or_default();
        let closed = after.as_bytes().get(len) == Some(&b'}');
        if len > 0 && closed {
            out.push(Piece::Text(before));
            out.push(Piece::Key(key));
            rest = after.get(len + 1..).unwrap_or_default();
        } else {
            out.push(Piece::Text(rest.get(..=open).unwrap_or_default()));
            rest = after;
        }
    }
    out.push(Piece::Text(rest));
    out
}
