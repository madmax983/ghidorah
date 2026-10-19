//! A small reader of the nested `llvm-readobj` text: `Name {` and `Name [` open a node, `}`
//! and `]` close it, and `Key: Value` is a field. A flag list such as `Characteristics [ (0x22)`
//! is a field with the value `(0x22)` and a node with the flag lines.

/// One node of the text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    /// The node name, for example `Section`.
    pub name: String,
    /// The fields in text order.
    pub fields: Vec<(String, String)>,
    /// The child nodes in text order.
    pub children: Vec<Self>,
}

impl Node {
    /// Gives the value of the first field `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Gives the first child with the name `name`.
    pub fn child(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Gives the children with the name `name`.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Gives the number of the field `key`: `0x` hex, decimal or the hex in parentheses.
    pub fn num(&self, key: &str) -> u64 {
        let text = self
            .get(key)
            .unwrap_or_else(|| panic!("no field {key} in {}", self.name));
        number(text).unwrap_or_else(|| panic!("{key}: {text} is not a number"))
    }
}

/// Gives the number of a field value: `(0x22)`, `IMAGE_FILE_MACHINE_AMD64 (0x8664)`, `0x1000`
/// or `512`.
pub fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some((_, rest)) = text.rsplit_once('(') {
        return number(rest.trim_end_matches(')'));
    }
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    text.parse().ok()
}

/// Parses the text into one root node.
pub fn parse(text: &str) -> Node {
    let mut stack = vec![Node::default()];
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line == "}" || line == "]" {
            if stack.len() > 1 {
                let done = stack.pop().expect("an open node");
                stack.last_mut().expect("a parent").children.push(done);
            }
            continue;
        }
        if let Some((key, rest)) = line.split_once(" [ (") {
            let top = stack.last_mut().expect("a node");
            top.fields.push((key.to_owned(), format!("({rest}")));
            stack.push(Node {
                name: key.to_owned(),
                ..Node::default()
            });
            continue;
        }
        if let Some(name) = line.strip_suffix(" {").or_else(|| line.strip_suffix(" [")) {
            stack.push(Node {
                name: name.to_owned(),
                ..Node::default()
            });
            continue;
        }
        let top = stack.last_mut().expect("a node");
        match line.split_once(':') {
            Some((k, v)) => top.fields.push((k.trim().to_owned(), v.trim().to_owned())),
            None => top.fields.push((line.to_owned(), String::new())),
        }
    }
    while stack.len() > 1 {
        let done = stack.pop().expect("an open node");
        stack.last_mut().expect("a parent").children.push(done);
    }
    stack.pop().unwrap_or_default()
}
