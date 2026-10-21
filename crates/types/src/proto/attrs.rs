//! The attribute comment of a Tier-0 line.
//!
//! The comment holds a category and then attribute words. The header of `data/tier0.h`
//! gives the grammar. Each parameter number names a parameter of the prototype.

use super::{Attrs, Category, Effect, Fmt, FmtKind, Tier0Error};
use crate::store::{TypeStore, is_identifier};
use crate::ty::{Prim, Sig, Type, TypeId};

/// The largest number of words in one attribute comment.
const MAX_WORDS: usize = 64;

/// The parsed comment of one line.
pub(super) struct Comment {
    pub(super) category: Category,
    pub(super) attrs: Attrs,
    pub(super) aliases: Vec<String>,
}

/// The checks of one line.
struct Checks<'a> {
    line: u32,
    sig: &'a Sig,
    store: &'a TypeStore,
}

impl Checks<'_> {
    fn bad(&self, word: &str) -> Tier0Error {
        Tier0Error::Attr {
            line: self.line,
            word: word.to_string(),
        }
    }

    /// Gives the type of parameter `n`, from 1.
    fn param(&self, n: u16, word: &str) -> Result<TypeId, Tier0Error> {
        let index = usize::from(n)
            .checked_sub(1)
            .ok_or_else(|| self.bad(word))?;
        self.sig
            .params
            .get(index)
            .map(|p| p.ty)
            .ok_or_else(|| self.bad(word))
    }

    /// Gives the resolved type of parameter `n`.
    fn resolved(&self, n: u16, word: &str) -> Result<Option<&Type>, Tier0Error> {
        let ty = self.param(n, word)?;
        let id = self.store.resolve(ty).map_err(|_| self.bad(word))?;
        Ok(self.store.get(id))
    }

    /// Checks that parameter `n` is a pointer.
    fn pointer(&self, n: u16, word: &str) -> Result<u16, Tier0Error> {
        match self.resolved(n, word)? {
            Some(Type::Ptr(_)) => Ok(n),
            _ => Err(self.bad(word)),
        }
    }

    /// Checks that parameter `n` is an integer.
    fn integer(&self, n: u16, word: &str) -> Result<u16, Tier0Error> {
        match self.resolved(n, word)? {
            Some(Type::Prim(p)) if p.is_integer() && *p != Prim::Bool => Ok(n),
            _ => Err(self.bad(word)),
        }
    }

    /// Splits `name(a,b)` into the name and the arguments.
    fn call<'w>(&self, word: &'w str) -> Result<(&'w str, Vec<&'w str>), Tier0Error> {
        let Some((name, rest)) = word.split_once('(') else {
            return Ok((word, Vec::new()));
        };
        let args = rest.strip_suffix(')').ok_or_else(|| self.bad(word))?;
        let args: Vec<&str> = args.split(',').collect();
        if args.iter().any(|a| a.is_empty()) {
            return Err(self.bad(word));
        }
        Ok((name, args))
    }

    /// Parses a parameter number.
    fn number(&self, text: &str, word: &str) -> Result<u16, Tier0Error> {
        text.parse::<u16>().map_err(|_| self.bad(word))
    }

    /// Parses one attribute word into `out`.
    fn word(&self, word: &str, out: &mut Comment) -> Result<(), Tier0Error> {
        let (name, args) = self.call(word)?;
        let one = |out: &Self| -> Result<u16, Tier0Error> {
            match args.as_slice() {
                [n] => out.number(n, word),
                _ => Err(out.bad(word)),
            }
        };
        match (name, args.len()) {
            ("noreturn", 0) => out.attrs.noreturn = true,
            ("allocates", 0) => out.attrs.effects.push(Effect::Allocates),
            ("fmt", 2) => {
                let kind = match args.first().copied() {
                    Some("printf") => FmtKind::Printf,
                    Some("scanf") => FmtKind::Scanf,
                    _ => return Err(self.bad(word)),
                };
                let n = self.number(args.get(1).copied().unwrap_or(""), word)?;
                let index = self.pointer(n, word)?;
                out.attrs.fmt = Some(Fmt { kind, index });
            }
            ("nonnull", 1..) => {
                for a in &args {
                    let n = self.number(a, word)?;
                    out.attrs.nonnull.push(self.pointer(n, word)?);
                }
            }
            ("reads_str", 1) => {
                let n = self.pointer(one(self)?, word)?;
                out.attrs.effects.push(Effect::ReadsStr(n));
            }
            ("returns_arg", 1) => {
                let n = one(self)?;
                self.param(n, word)?;
                out.attrs.effects.push(Effect::ReturnsArg(n));
            }
            ("writes", 1 | 2) => {
                let arg = self.number(args.first().copied().unwrap_or(""), word)?;
                let arg = self.pointer(arg, word)?;
                let len_arg = match args.get(1) {
                    Some(l) => Some(self.integer(self.number(l, word)?, word)?),
                    None => None,
                };
                out.attrs.effects.push(Effect::Writes { arg, len_arg });
            }
            ("alias", 1..) => {
                for a in &args {
                    if !is_identifier(a) {
                        return Err(self.bad(word));
                    }
                    out.aliases.push((*a).to_string());
                }
            }
            _ => return Err(self.bad(word)),
        }
        Ok(())
    }
}

/// Parses the attribute comment `text` of line `line` for the signature `sig`.
pub(super) fn parse(
    text: &str,
    sig: &Sig,
    store: &TypeStore,
    line: u32,
) -> Result<Comment, Tier0Error> {
    let checks = Checks { line, sig, store };
    let mut words = text.split_whitespace();
    let first = words.next().unwrap_or("");
    let category = Category::from_name(first).ok_or_else(|| checks.bad(first))?;
    let mut out = Comment {
        category,
        attrs: Attrs::default(),
        aliases: Vec::new(),
    };
    for (i, word) in words.enumerate() {
        if i >= MAX_WORDS {
            return Err(checks.bad(word));
        }
        checks.word(word, &mut out)?;
    }
    if out.attrs.noreturn != sig.noreturn {
        return Err(checks.bad("noreturn"));
    }
    Ok(out)
}
