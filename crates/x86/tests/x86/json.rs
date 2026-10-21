//! A small JSON reader for the checked-in test data: truth files and vector files.
//!
//! The reader trusts its input. A bad file fails the test with a message.

use std::collections::BTreeMap;

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Self>),
    Obj(BTreeMap<String, Self>),
}

impl Json {
    /// Gives the member `key`, or fails the test.
    pub fn get(&self, key: &str) -> &Self {
        match self {
            Self::Obj(m) => m
                .get(key)
                .unwrap_or_else(|| panic!("no member `{key}` in {self:?}")),
            _ => panic!("not an object: {self:?}"),
        }
    }

    /// Gives the member `key`, or `None`.
    pub fn opt(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(m) => m.get(key),
            _ => None,
        }
    }

    pub fn str(&self) -> &str {
        match self {
            Self::Str(s) => s,
            _ => panic!("not a string: {self:?}"),
        }
    }

    pub fn arr(&self) -> &[Self] {
        match self {
            Self::Arr(a) => a,
            _ => panic!("not an array: {self:?}"),
        }
    }

    pub fn u64(&self) -> u64 {
        match self {
            Self::Num(n) => n.parse().unwrap_or_else(|_| panic!("not a count: {n}")),
            _ => panic!("not a count: {self:?}"),
        }
    }

    /// Reads a `0x..` hex string as a number.
    pub fn hex(&self) -> u128 {
        let s = self.str();
        let digits = s.strip_prefix("0x").unwrap_or(s);
        u128::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("not hex: {s}"))
    }
}

/// Parses one JSON text.
pub fn parse(text: &str) -> Json {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.value();
    p.ws();
    assert_eq!(p.i, p.b.len(), "text after the JSON value");
    v
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.b.get(self.i), Some(&c), "expected `{}`", char::from(c));
        self.i += 1;
    }

    fn peek(&mut self) -> u8 {
        self.ws();
        *self.b.get(self.i).expect("more JSON")
    }

    fn value(&mut self) -> Json {
        match self.peek() {
            b'{' => {
                self.eat(b'{');
                let mut m = BTreeMap::new();
                if self.peek() == b'}' {
                    self.i += 1;
                    return Json::Obj(m);
                }
                loop {
                    let Json::Str(k) = self.value() else {
                        panic!("a key")
                    };
                    self.eat(b':');
                    m.insert(k, self.value());
                    match self.peek() {
                        b',' => self.i += 1,
                        _ => break,
                    }
                }
                self.eat(b'}');
                Json::Obj(m)
            }
            b'[' => {
                self.eat(b'[');
                let mut a = Vec::new();
                if self.peek() == b']' {
                    self.i += 1;
                    return Json::Arr(a);
                }
                loop {
                    a.push(self.value());
                    match self.peek() {
                        b',' => self.i += 1,
                        _ => break,
                    }
                }
                self.eat(b']');
                Json::Arr(a)
            }
            b'"' => Json::Str(self.string()),
            b't' => self.word("true", Json::Bool(true)),
            b'f' => self.word("false", Json::Bool(false)),
            b'n' => self.word("null", Json::Null),
            _ => {
                let start = self.i;
                while self.i < self.b.len() && b"+-.eE0123456789".contains(&self.b[self.i]) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.b[start..self.i]).expect("utf-8");
                assert!(!text.is_empty(), "a JSON value at byte {start}");
                Json::Num(text.to_owned())
            }
        }
    }

    fn word(&mut self, w: &str, v: Json) -> Json {
        assert!(self.b[self.i..].starts_with(w.as_bytes()), "expected {w}");
        self.i += w.len();
        v
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return out,
                b'\\' => {
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(&self.b[self.i..self.i + 4]).expect("hex");
                            let code = u32::from_str_radix(hex, 16).expect("hex");
                            out.push(char::from_u32(code).unwrap_or('?'));
                            self.i += 4;
                        }
                        other => out.push(char::from(other)),
                    }
                }
                _ => {
                    // Copy one UTF-8 sequence.
                    let start = self.i - 1;
                    let mut end = self.i;
                    while end < self.b.len() && (self.b[end] & 0xc0) == 0x80 {
                        end += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.b[start..end]).expect("utf-8"));
                    self.i = end;
                }
            }
        }
    }
}
