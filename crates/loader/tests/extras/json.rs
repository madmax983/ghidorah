//! A small JSON reader for the truth files. The loader has no JSON dependency.

use std::collections::BTreeMap;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number as its text.
    Num(String),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Self>),
    /// An object.
    Obj(BTreeMap<String, Self>),
}

impl Json {
    /// Gives the member `key` of an object.
    pub fn get(&self, key: &str) -> &Self {
        match self {
            Self::Obj(map) => map.get(key).unwrap_or_else(|| panic!("no member {key}")),
            other => panic!("not an object: {other:?}"),
        }
    }

    /// Gives the items of an array.
    pub fn items(&self) -> &[Self] {
        match self {
            Self::Arr(items) => items,
            other => panic!("not an array: {other:?}"),
        }
    }

    /// Gives the text of a string.
    pub fn text(&self) -> &str {
        match self {
            Self::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    /// Gives the value of a boolean.
    pub fn bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            other => panic!("not a boolean: {other:?}"),
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.bytes.get(self.pos), Some(&c), "at {}", self.pos);
        self.pos += 1;
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = Vec::new();
        loop {
            let c = self.bytes[self.pos];
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.bytes[self.pos];
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .expect("hex");
                            let cp = u32::from_str_radix(hex, 16).expect("code point");
                            self.pos += 4;
                            let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                            out.extend_from_slice(ch.to_string().as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn value(&mut self) -> Json {
        self.ws();
        match self.bytes[self.pos] {
            b'{' => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.bytes[self.pos] == b'}' {
                    self.pos += 1;
                    return Json::Obj(map);
                }
                loop {
                    let key = self.string();
                    self.eat(b':');
                    map.insert(key, self.value());
                    self.ws();
                    let c = self.bytes[self.pos];
                    self.pos += 1;
                    if c == b'}' {
                        return Json::Obj(map);
                    }
                    assert_eq!(c, b',');
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.bytes[self.pos] == b']' {
                    self.pos += 1;
                    return Json::Arr(items);
                }
                loop {
                    items.push(self.value());
                    self.ws();
                    let c = self.bytes[self.pos];
                    self.pos += 1;
                    if c == b']' {
                        return Json::Arr(items);
                    }
                    assert_eq!(c, b',');
                }
            }
            b'"' => Json::Str(self.string()),
            b't' => {
                self.pos += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.pos += 5;
                Json::Bool(false)
            }
            b'n' => {
                self.pos += 4;
                Json::Null
            }
            _ => {
                let start = self.pos;
                while self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|c| c.is_ascii_digit() || b"+-.eE".contains(c))
                {
                    self.pos += 1;
                }
                Json::Num(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
            }
        }
    }
}

/// Parses one JSON text.
pub fn parse(text: &str) -> Json {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.value()
}
