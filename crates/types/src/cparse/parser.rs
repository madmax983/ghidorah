//! The parser state, the specifier lists and the two parse modes.

use std::collections::BTreeMap;

use ghidorah_base::dym::MAX_SUGGESTIONS;
use ghidorah_base::{DiagCode, Fuel, did_you_mean};

use super::ParsedSig;
use super::decl::NameMode;
use super::diag::Fail;
use super::lex::{Tok, Token};
use super::words::{
    C23_ATTRIBUTE, PRAGMA, TYPE_WORDS, is_keyword, is_storage, qual_word, unsupported,
};
use super::{MAX_DEPTH, MAX_PARAMS};
use crate::store::{StoreError, TypeStore};
use crate::ty::{Prim, Quals, RecordKind, Sig, TagKind, Type, TypeId};

/// A parse step result.
pub(crate) type PResult<T> = Result<T, Fail>;

/// The fuel of one candidate search.
const CANDIDATE_FUEL: u64 = 1 << 22;

/// Gives the names nearest to `word`: the did-you-mean names, then the names that start
/// with `word`, at most [`MAX_SUGGESTIONS`] names.
pub(crate) fn candidates(word: &str, names: &[&str]) -> Vec<String> {
    let mut fuel = Fuel::new(CANDIDATE_FUEL);
    let mut out: Vec<String> = did_you_mean(word, names.iter().copied(), &mut fuel)
        .into_iter()
        .map(|s| s.name)
        .collect();
    let mut longer: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| !word.is_empty() && n.len() > word.len() && n.starts_with(word))
        .collect();
    longer.sort_unstable();
    for name in longer {
        if out.len() >= MAX_SUGGESTIONS {
            break;
        }
        if !out.iter().any(|o| o == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// The place of a specifier list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ctx {
    /// The start of a prototype.
    Sig,
    /// The start of an abstract type.
    Type,
    /// A parameter.
    Param,
    /// A record field.
    Field,
}

/// The bits of the type keywords of one specifier list.
mod kw {
    pub(super) const VOID: u16 = 1;
    pub(super) const CHAR: u16 = 1 << 1;
    pub(super) const SHORT: u16 = 1 << 2;
    pub(super) const INT: u16 = 1 << 3;
    pub(super) const FLOAT: u16 = 1 << 4;
    pub(super) const DOUBLE: u16 = 1 << 5;
    pub(super) const SIGNED: u16 = 1 << 6;
    pub(super) const UNSIGNED: u16 = 1 << 7;
    pub(super) const BOOL: u16 = 1 << 8;
    pub(super) const INT128: u16 = 1 << 9;
    pub(super) const WCHAR: u16 = 1 << 10;
    pub(super) const SIGN: u16 = SIGNED | UNSIGNED;
    /// The largest valid keyword sets and their largest `long` counts.
    pub(super) const SHAPES: [(u16, u8); 9] = [
        (VOID, 0),
        (SIGN | CHAR, 0),
        (SIGN | SHORT | INT, 0),
        (SIGN | INT, 2),
        (FLOAT, 0),
        (DOUBLE, 1),
        (BOOL, 0),
        (SIGN | INT128, 0),
        (WCHAR, 0),
    ];
}

/// The type keywords of one specifier list.
#[derive(Debug, Clone, Copy, Default)]
struct Kw {
    bits: u16,
    longs: u8,
}

impl Kw {
    /// Adds a keyword. `None` when the keywords do not combine.
    fn add(self, word: &str) -> Option<Self> {
        let next = if word == "long" {
            Self {
                bits: self.bits,
                longs: self.longs.checked_add(1)?,
            }
        } else {
            let bit = match word {
                "void" => kw::VOID,
                "char" => kw::CHAR,
                "short" => kw::SHORT,
                "int" => kw::INT,
                "float" => kw::FLOAT,
                "double" => kw::DOUBLE,
                "signed" => kw::SIGNED,
                "unsigned" => kw::UNSIGNED,
                "_Bool" | "bool" => kw::BOOL,
                "__int128" => kw::INT128,
                "wchar_t" => kw::WCHAR,
                _ => return None,
            };
            if self.bits & bit != 0 {
                return None;
            }
            Self {
                bits: self.bits | bit,
                longs: self.longs,
            }
        };
        next.fits().then_some(next)
    }

    fn fits(self) -> bool {
        self.bits & kw::SIGN != kw::SIGN
            && kw::SHAPES
                .iter()
                .any(|(mask, longs)| self.bits & !mask == 0 && self.longs <= *longs)
    }

    const fn is_empty(self) -> bool {
        self.bits == 0 && self.longs == 0
    }

    fn has(self, bit: u16) -> bool {
        self.bits & bit != 0
    }

    /// Gives the primitive type of the keywords.
    fn prim(self) -> Option<Prim> {
        if self.is_empty() {
            return None;
        }
        let unsigned = self.has(kw::UNSIGNED);
        let pick = |s: Prim, u: Prim| if unsigned { u } else { s };
        Some(if self.has(kw::VOID) {
            Prim::Void
        } else if self.has(kw::BOOL) {
            Prim::Bool
        } else if self.has(kw::WCHAR) {
            Prim::WChar
        } else if self.has(kw::FLOAT) {
            Prim::Float
        } else if self.has(kw::DOUBLE) {
            if self.longs > 0 {
                Prim::LongDouble
            } else {
                Prim::Double
            }
        } else if self.has(kw::CHAR) {
            if self.has(kw::SIGNED) {
                Prim::SChar
            } else {
                pick(Prim::Char, Prim::UChar)
            }
        } else if self.has(kw::INT128) {
            pick(Prim::Int128, Prim::UInt128)
        } else if self.has(kw::SHORT) {
            pick(Prim::Short, Prim::UShort)
        } else if self.longs >= 2 {
            pick(Prim::LongLong, Prim::ULongLong)
        } else if self.longs == 1 {
            pick(Prim::Long, Prim::ULong)
        } else {
            pick(Prim::Int, Prim::UInt)
        })
    }
}

/// The parser of one text.
pub(crate) struct Parser<'t, 's> {
    pub(crate) text: &'t str,
    toks: Vec<Token>,
    pos: usize,
    pub(crate) store: &'s mut TypeStore,
    depth: usize,
    pub(crate) consts: BTreeMap<String, i128>,
}

impl<'t, 's> Parser<'t, 's> {
    /// Makes a parser over the tokens of `text`.
    pub(crate) fn new(text: &'t str, toks: Vec<Token>, store: &'s mut TypeStore) -> Self {
        Self {
            text,
            toks,
            pos: 0,
            store,
            depth: 0,
            consts: BTreeMap::new(),
        }
    }

    /// Gives the current token.
    pub(crate) fn peek(&self) -> Option<Token> {
        self.toks.get(self.pos).copied()
    }

    /// Gives the token `k` places after the current token.
    pub(crate) fn peek_at(&self, k: usize) -> Option<Token> {
        self.toks.get(self.pos.saturating_add(k)).copied()
    }

    /// Moves to the next token.
    pub(crate) const fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Gives the text of a token.
    pub(crate) fn word(&self, t: Token) -> &'t str {
        self.text
            .get(t.byte..t.byte.saturating_add(t.len))
            .unwrap_or("")
    }

    /// Gives the place of the current token, or the end of the text.
    pub(crate) fn here(&self) -> (usize, usize) {
        self.peek()
            .map_or((self.text.len(), 0), |t| (t.byte, t.len))
    }

    /// Gives the current identifier and its text.
    pub(crate) fn peek_word(&self) -> Option<(Token, &'t str)> {
        self.peek()
            .filter(|t| t.tok == Tok::Ident)
            .map(|t| (t, self.word(t)))
    }

    /// Tells if the current token is the identifier `word`.
    pub(crate) fn is_word(&self, word: &str) -> bool {
        self.peek_word().is_some_and(|(_, w)| w == word)
    }

    /// Tells if the current token is the punctuator `p`.
    pub(crate) fn is_punct(&self, p: &str) -> bool {
        self.peek()
            .is_some_and(|t| matches!(t.tok, Tok::Punct(x) if x == p))
    }

    /// Takes the punctuator `p` when it is the current token.
    pub(crate) fn eat_punct(&mut self, p: &str) -> Option<Token> {
        let t = self
            .peek()
            .filter(|t| matches!(t.tok, Tok::Punct(x) if x == p))?;
        self.bump();
        Some(t)
    }

    /// Takes the punctuator `p`, or fails with `what` as the expected item.
    pub(crate) fn expect_punct(&mut self, p: &str, what: &str) -> PResult<Token> {
        self.eat_punct(p).ok_or_else(|| self.unexpected(&[what]))
    }

    /// Goes one level deeper.
    pub(crate) fn enter(&mut self) -> PResult<()> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            let (byte, len) = self.here();
            return Err(Fail::new(DiagCode::Limit, byte, len)
                .hint("The text nests deeper than 64 levels. Give a flatter text."));
        }
        Ok(())
    }

    /// Goes one level back.
    pub(crate) const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Gives the failure at an unexpected current token.
    pub(crate) fn unexpected(&self, expected: &[&str]) -> Fail {
        let Some(t) = self.peek() else {
            return Fail::new(DiagCode::Syntax, self.text.len(), 0)
                .expected(expected)
                .hint("The text ends too early.");
        };
        match t.tok {
            Tok::Hash => Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(PRAGMA),
            Tok::Punct("[[") => Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(C23_ATTRIBUTE),
            Tok::Bad => Fail::new(DiagCode::Syntax, t.byte, t.len)
                .expected(expected)
                .hint("The character starts no C token here."),
            _ => match unsupported(self.word(t)).filter(|_| t.tok == Tok::Ident) {
                Some(hint) => Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(hint),
                None => Fail::new(DiagCode::Syntax, t.byte, t.len).expected(expected),
            },
        }
    }

    /// Gives the failure of a store error at a place.
    pub(crate) fn store_fail(e: &StoreError, byte: usize, len: usize) -> Fail {
        let hint = match e {
            StoreError::IncompleteByValue { .. } => {
                "Use a pointer to the type, or a type with a known size."
            }
            StoreError::FlexibleNotLast(_) => {
                "A flexible array member can only come last, after another field."
            }
            StoreError::IncompleteElement(_) => "An array element needs a type with a known size.",
            StoreError::BadPart(_) => {
                "An array holds no functions. A function returns no array and no function."
            }
            StoreError::Duplicate(_) => "The tag names another complete record. Use another tag.",
            StoreError::DuplicateMember(_) => "Give each member another name.",
            _ => e.diag().info().hint,
        };
        Fail::new(e.diag(), byte, len).hint(hint)
    }

    /// Gives the failure of an unknown type name, with candidates.
    fn unknown_type(&self, t: Token, word: &str) -> Fail {
        let mut names: Vec<&str> = self.store.typedef_names().collect();
        names.extend(TYPE_WORDS);
        Fail::new(DiagCode::UnknownType, t.byte, t.len)
            .expected(&["a type name"])
            .candidates(candidates(word, &names))
    }

    /// Gives the failure of an unknown tag or a tag of another kind, with candidates.
    pub(crate) fn tag_fail(&self, t: Token, kind: TagKind, name: &str) -> Fail {
        let kind_of = |id: TypeId| match self.store.get(id) {
            Some(Type::Record(r)) => Some(TagKind::from(r.kind)),
            Some(Type::Enum(_)) => Some(TagKind::Enum),
            _ => None,
        };
        let found = self.store.lookup_tag(name).and_then(kind_of);
        let candidates = if let Some(have) = found {
            vec![format!("{} {name}", have.keyword())]
        } else {
            let same: Vec<&str> = self
                .store
                .tag_names()
                .filter(|n| self.store.lookup_tag(n).and_then(kind_of) == Some(kind))
                .collect();
            candidates(name, &same)
                .into_iter()
                .map(|s| format!("{} {s}", kind.keyword()))
                .collect()
        };
        Fail::new(DiagCode::UnknownType, t.byte, t.len)
            .expected(&["a known tag"])
            .candidates(candidates)
    }

    /// Gives the failure of a type keyword that does not combine with the keywords before it.
    fn combine_fail(t: Token) -> Fail {
        Fail::new(DiagCode::Syntax, t.byte, t.len)
            .hint("This type word does not combine with the type words before it.")
    }

    /// Parses a specifier list. Gives the qualified base type and the `_Noreturn` flag.
    pub(crate) fn specifiers(&mut self, ctx: Ctx) -> PResult<(TypeId, bool)> {
        let mut kws = Kw::default();
        let mut base: Option<TypeId> = None;
        let mut quals = Quals::NONE;
        let mut noreturn = false;
        while let Some((t, word)) = self.peek_word() {
            if let Some(q) = qual_word(word) {
                quals = quals.union(q);
                self.bump();
                continue;
            }
            if let Some(hint) = unsupported(word) {
                return Err(Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(hint));
            }
            if word == "_Noreturn" || is_storage(word) {
                let fits = match ctx {
                    Ctx::Sig => !matches!(word, "register" | "auto"),
                    Ctx::Param => word == "register",
                    Ctx::Type | Ctx::Field => false,
                };
                if !fits {
                    return Err(Fail::new(DiagCode::Syntax, t.byte, t.len)
                        .expected(&["a type name"])
                        .hint("This word does not fit here. Remove it."));
                }
                noreturn |= word == "_Noreturn";
                self.bump();
                continue;
            }
            let tag = match word {
                "struct" => Some(TagKind::Struct),
                "union" => Some(TagKind::Union),
                "enum" => Some(TagKind::Enum),
                _ => None,
            };
            if let Some(tag) = tag {
                if base.is_some() || !kws.is_empty() {
                    return Err(Self::combine_fail(t));
                }
                self.bump();
                base = Some(match tag {
                    TagKind::Struct => self.record_spec(RecordKind::Struct)?,
                    TagKind::Union => self.record_spec(RecordKind::Union)?,
                    TagKind::Enum => self.enum_spec()?,
                });
                continue;
            }
            if TYPE_WORDS.contains(&word) {
                if base.is_some() {
                    return Err(Self::combine_fail(t));
                }
                kws = kws.add(word).ok_or_else(|| Self::combine_fail(t))?;
                self.bump();
                continue;
            }
            if base.is_some() || !kws.is_empty() || is_keyword(word) {
                break;
            }
            match self.store.lookup_typedef(word) {
                Some(id) => {
                    base = Some(id);
                    self.bump();
                }
                None => return Err(self.unknown_type(t, word)),
            }
        }
        let Some(base) = base.or_else(|| kws.prim().map(|p| self.store.prim(p))) else {
            return Err(self.unexpected(&["a type name"]));
        };
        let (byte, len) = self.here();
        let ty = self
            .store
            .qual(quals, base)
            .map_err(|e| Self::store_fail(&e, byte, len))?;
        Ok((ty, noreturn))
    }

    /// Takes an optional `;` and checks the end of the text.
    fn end(&mut self) -> PResult<()> {
        self.eat_punct(";");
        if self.peek().is_some() {
            return Err(self.unexpected(&["the end of the text"]));
        }
        Ok(())
    }

    /// Parses the `type` mode.
    pub(crate) fn type_mode(&mut self) -> PResult<TypeId> {
        let (base, _) = self.specifiers(Ctx::Type)?;
        let d = self.declarator(NameMode::Forbidden)?;
        let ty = self.apply(base, &d)?;
        self.end()?;
        Ok(ty)
    }

    /// Parses the `sig` mode.
    pub(crate) fn sig_mode(&mut self) -> PResult<ParsedSig> {
        let (base, noreturn) = self.specifiers(Ctx::Sig)?;
        let (sb, sl) = self.here();
        let d = self.declarator(NameMode::Required)?;
        let ty = self.apply(base, &d)?;
        let (name, nb, nl) = d.name.unwrap_or_default();
        let (nb, nl) = if name.is_empty() { (sb, sl) } else { (nb, nl) };
        let Some(Type::Func(sig)) = self.store.get(ty).cloned() else {
            return Err(Fail::new(DiagCode::Syntax, nb, nl)
                .expected(&["a function declarator"])
                .hint("The sig mode reads one function prototype, for example `int puts(const char *s);`."));
        };
        self.end()?;
        if !noreturn {
            return Ok(ParsedSig { name, ty, sig });
        }
        let sig = Sig {
            noreturn: true,
            ..sig
        };
        let ty = self
            .store
            .func(sig.clone())
            .map_err(|e| Self::store_fail(&e, nb, nl))?;
        Ok(ParsedSig { name, ty, sig })
    }

    /// Gives the failure of a member count above the limit.
    pub(crate) fn members_fail(byte: usize, len: usize, what: &str) -> Fail {
        Fail::new(DiagCode::Limit, byte, len).hint(format!(
            "The {what} count is above {MAX_PARAMS}. Give fewer {what}s."
        ))
    }
}
