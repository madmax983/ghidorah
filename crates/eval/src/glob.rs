//! Glob match for answer checks and derive steps: `*` matches any text, `?` one character.
//!
//! The match keeps the last `*` only, so it runs in `O(pattern x text)` time at most.

/// Tells if `text` matches `pattern` in full. With `icase`, letters match in any case.
#[must_use]
pub fn matches(pattern: &str, text: &str, icase: bool) -> bool {
    let fold = |c: char| {
        if icase { c.to_ascii_lowercase() } else { c }
    };
    let p: Vec<char> = pattern.chars().map(fold).collect();
    let t: Vec<char> = text.chars().map(fold).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(&c) if c == '?' || Some(&c) == t.get(ti) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .is_some_and(|rest| rest.iter().all(|&c| c == '*'))
}

#[cfg(test)]
mod tests;
