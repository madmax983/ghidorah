//! Text parsers of the PE fixture build: the link map, the C sources, the `.def` files and
//! the `llvm-readobj` and `llvm-objdump` listings.

use std::collections::{BTreeMap, BTreeSet};

/// One public symbol of the link map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSym {
    /// The section number, for example `0001`.
    pub section: String,
    /// The name.
    pub name: String,
    /// The address.
    pub addr: u64,
    /// The `Lib:Object` column, for example `pe_main.obj` or `kernel32:kernel32.dll`.
    pub object: String,
}

/// The parts of a link map that the truth reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkMap {
    /// The preferred load address.
    pub image_base: u64,
    /// The public symbols in map order.
    pub symbols: Vec<MapSym>,
}

/// Parses hex text with or without the `0x` prefix.
pub(crate) fn hex_u64(text: &str) -> Option<u64> {
    let digits = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(digits, 16).ok()
}

/// Parses an `lld-link /map` file.
#[must_use]
pub fn parse_map(text: &str) -> LinkMap {
    let mut out = LinkMap::default();
    let mut publics = false;
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Preferred load address is ") {
            out.image_base = hex_u64(rest).unwrap_or(0);
        }
        if line.contains("Publics by Value") {
            publics = true;
            continue;
        }
        if line.trim().starts_with("entry point at") || line.trim() == "Static symbols" {
            publics = false;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if !publics || words.len() < 4 {
            continue;
        }
        let (Some(at), Some(name), Some(va), Some(object)) =
            (words.first(), words.get(1), words.get(2), words.last())
        else {
            continue;
        };
        let (Some((section, _)), Some(va)) = (at.split_once(':'), hex_u64(va)) else {
            continue;
        };
        out.symbols.push(MapSym {
            section: section.to_owned(),
            name: (*name).to_owned(),
            addr: va,
            object: (*object).to_owned(),
        });
    }
    out
}

/// One function definition of a C source: its name and its parameter count.
#[must_use]
pub fn source_functions(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let starts = line.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        let Some((head_text, _)) = line.split_once('{') else {
            continue;
        };
        let head_text = head_text.trim_end();
        if !starts || !head_text.ends_with(')') || head_text.contains('=') {
            continue;
        }
        let body = head_text
            .trim_start_matches("NOINLINE ")
            .trim_start_matches("__declspec(noreturn) ");
        let Some(open) = body.find('(') else {
            continue;
        };
        let Some(close) = body.rfind(')') else {
            continue;
        };
        let head = body.get(..open).unwrap_or("");
        let name = head
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        let params = body.get(open + 1..close).unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let count = if params.is_empty() || params == "void" {
            0
        } else {
            u64::try_from(params.matches(',').count()).unwrap_or(0) + 1
        };
        out.insert(name.to_owned(), count);
    }
    out
}

/// Gives the switch function of the sources and its case count.
#[must_use]
pub fn switch_of(sources: &[(String, String)]) -> Option<(String, u64)> {
    for (_, text) in sources {
        let mut func: Option<String> = None;
        let mut cases = 0u64;
        let mut inside = false;
        for line in text.lines() {
            if let Some((name, _)) = source_functions(&format!("{line}\n")).into_iter().next() {
                func = Some(name);
            }
            let t = line.trim();
            if t.starts_with("switch (") {
                inside = true;
            } else if inside && t.starts_with("case ") {
                cases += 1;
            } else if inside && t.starts_with("default:") {
                return func.map(|f| (f, cases));
            }
        }
    }
    None
}

/// Gives the TLS callback names: the initializers of the `.CRT$XLB` lines.
#[must_use]
pub fn tls_callbacks(sources: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, text) in sources {
        for line in text
            .lines()
            .filter(|l| l.contains("allocate(\".CRT$XLB\")"))
        {
            if let Some((_, init)) = line.split_once('=') {
                out.push(init.trim().trim_end_matches(';').trim().to_owned());
            }
        }
    }
    out
}

/// One line of the `EXPORTS` block of a `.def` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefExport {
    /// The export name, or the alias of a forwarder.
    pub name: String,
    /// The ordinal of `@N`.
    pub ordinal: Option<u32>,
    /// `NONAME`: the export has no name.
    pub noname: bool,
    /// The forwarder text of `alias = dll.target`.
    pub forwarder: Option<String>,
}

/// Parses the library name and the exports of a `.def` file.
#[must_use]
pub fn parse_def(text: &str) -> (String, Vec<DefExport>) {
    let mut library = String::new();
    let mut out = Vec::new();
    let mut exports = false;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(name) = line.strip_prefix("LIBRARY ") {
            name.trim().clone_into(&mut library);
            continue;
        }
        if line == "EXPORTS" {
            exports = true;
            continue;
        }
        if !exports {
            continue;
        }
        let (head, forwarder) = match line.split_once('=') {
            Some((alias, rest)) => {
                let target = rest.split_whitespace().next().unwrap_or("").to_owned();
                (format!("{} {}", alias.trim(), rest.trim()), Some(target))
            }
            None => (line.to_owned(), None),
        };
        let words: Vec<&str> = head.split_whitespace().collect();
        let ordinal = words
            .iter()
            .find_map(|w| w.strip_prefix('@'))
            .and_then(|n| n.parse().ok());
        out.push(DefExport {
            name: words.first().copied().unwrap_or("").to_owned(),
            ordinal,
            noname: words.contains(&"NONAME"),
            forwarder,
        });
    }
    (library, out)
}

/// Gives the start addresses of the `RuntimeFunction` entries of the `--unwind` text.
#[must_use]
pub fn pdata_starts(readobj: &str) -> BTreeSet<u64> {
    readobj
        .lines()
        .filter_map(|l| l.trim().strip_prefix("StartAddress:"))
        .filter_map(|rest| {
            let inner = rest.rsplit_once('(')?.1.trim_end_matches(')');
            hex_u64(inner)
        })
        .collect()
}

/// Gives the targets of the direct `call` instructions of an `llvm-objdump -d` listing.
#[must_use]
pub fn call_targets(objdump: &str) -> BTreeSet<u64> {
    objdump
        .lines()
        .filter_map(|l| l.split_once("\tcall\t0x").map(|(_, r)| r))
        .filter_map(|r| hex_u64(r.split_whitespace().next().unwrap_or("")))
        .collect()
}
