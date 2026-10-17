//! Record and enum specifiers: `struct`, `union` and `enum`, with or without a body.

use ghidorah_base::DiagCode;

use super::MAX_PARAMS;
use super::decl::NameMode;
use super::diag::Fail;
use super::lex::{Tok, Token};
use super::parser::{Ctx, PResult, Parser};
use super::words::{BIT_FIELD, NO_NAME_MEMBER, is_keyword};
use crate::store::StoreError;
use crate::ty::{Enumerator, Field, RecordKind, TagKind, Type, TypeId};

/// A field and the place of its name.
type PlacedField = (Field, (usize, usize));

impl Parser<'_, '_> {
    /// Takes an optional tag after `struct`, `union` or `enum`.
    fn tag(&mut self) -> Option<(Token, String)> {
        let (t, w) = self.peek_word().filter(|(_, w)| !is_keyword(w))?;
        self.bump();
        Some((t, w.to_string()))
    }

    /// Finds a tag without a body.
    fn lookup(&self, tag: Option<(Token, String)>, kind: TagKind) -> PResult<TypeId> {
        let Some((t, name)) = tag else {
            return Err(self.unexpected(&["a tag", "`{`"]));
        };
        let found = self
            .store
            .lookup_tag(&name)
            .filter(|id| match self.store.get(*id) {
                Some(Type::Record(r)) => TagKind::from(r.kind) == kind,
                Some(Type::Enum(_)) => kind == TagKind::Enum,
                _ => false,
            });
        found.ok_or_else(|| self.tag_fail(t, kind, &name))
    }

    /// Declares the tag of a body, so the body can name the tag.
    fn declare_tag(&mut self, tag: Option<&(Token, String)>, kind: TagKind) -> PResult<()> {
        let Some((t, name)) = tag else {
            return Ok(());
        };
        match self.store.declare(kind, name) {
            Ok(_) => Ok(()),
            Err(StoreError::KindMismatch { .. }) => Err(self.tag_fail(*t, kind, name)),
            Err(e) => Err(Self::store_fail(&e, t.byte, t.len)),
        }
    }

    /// Parses a record specifier after `struct` or `union`.
    pub(crate) fn record_spec(&mut self, kind: RecordKind) -> PResult<TypeId> {
        let tag = self.tag();
        let Some(open) = self.eat_punct("{") else {
            return self.lookup(tag, kind.into());
        };
        self.declare_tag(tag.as_ref(), kind.into())?;
        self.enter()?;
        let fields = self.fields()?;
        self.leave();
        let (tb, tl) = tag
            .as_ref()
            .map_or((open.byte, open.len), |(t, _)| (t.byte, t.len));
        let list: Vec<Field> = fields.iter().map(|(f, _)| f.clone()).collect();
        let name = tag.as_ref().map(|(_, n)| n.as_str());
        self.store.define_record(kind, name, list).map_err(|e| {
            let field = match &e {
                StoreError::IncompleteByValue { field, .. }
                | StoreError::FlexibleNotLast(field)
                | StoreError::DuplicateMember(field) => Some(field.as_str()),
                _ => None,
            };
            let (b, l) = field
                .and_then(|n| fields.iter().rev().find(|(f, _)| f.name == n))
                .map_or((tb, tl), |(_, place)| *place);
            Self::store_fail(&e, b, l)
        })
    }

    /// Parses the fields of a record body up to `}`.
    fn fields(&mut self) -> PResult<Vec<PlacedField>> {
        let mut out: Vec<PlacedField> = Vec::new();
        loop {
            if self.eat_punct("}").is_some() {
                return Ok(out);
            }
            if self.peek().is_none() {
                return Err(self.unexpected(&["`}`"]));
            }
            let (base, _) = self.specifiers(Ctx::Field)?;
            if let Some(t) = self.peek().filter(|t| t.tok == Tok::Punct(";")) {
                return Err(Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(NO_NAME_MEMBER));
            }
            loop {
                let d = self.declarator(NameMode::Required)?;
                if let Some(t) = self.peek().filter(|t| t.tok == Tok::Punct(":")) {
                    return Err(Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(BIT_FIELD));
                }
                let ty = self.apply(base, &d)?;
                let (name, b, l) = d.name.unwrap_or_default();
                if out.len() >= MAX_PARAMS {
                    return Err(Self::members_fail(b, l, "field"));
                }
                out.push((Field { name, ty }, (b, l)));
                if self.eat_punct(",").is_some() {
                    continue;
                }
                self.expect_punct(";", "`;`")?;
                break;
            }
        }
    }

    /// Parses an enum specifier after `enum`.
    pub(crate) fn enum_spec(&mut self) -> PResult<TypeId> {
        let tag = self.tag();
        let Some(open) = self.eat_punct("{") else {
            return self.lookup(tag, TagKind::Enum);
        };
        self.declare_tag(tag.as_ref(), TagKind::Enum)?;
        self.enter()?;
        let mut items: Vec<Enumerator> = Vec::new();
        let mut next: Option<i128> = Some(0);
        loop {
            if self.eat_punct("}").is_some() {
                break;
            }
            let Some((t, word)) = self.peek_word().filter(|(_, w)| !is_keyword(w)) else {
                return Err(self.unexpected(&["an enum constant", "`}`"]));
            };
            self.bump();
            let value = if self.eat_punct("=").is_some() {
                self.const_expr()?
            } else {
                next.ok_or_else(|| {
                    Fail::new(DiagCode::Overflow, t.byte, t.len)
                        .hint("The enum constant is above the 128-bit range.")
                })?
            };
            if self.consts.contains_key(word) {
                return Err(Fail::new(DiagCode::Syntax, t.byte, t.len)
                    .hint("Give each enum constant another name."));
            }
            if items.len() >= MAX_PARAMS {
                return Err(Self::members_fail(t.byte, t.len, "enum constant"));
            }
            self.consts.insert(word.to_string(), value);
            items.push(Enumerator {
                name: word.to_string(),
                value,
            });
            next = value.checked_add(1);
            if self.eat_punct(",").is_some() {
                continue;
            }
            self.expect_punct("}", "`}`")?;
            break;
        }
        self.leave();
        let (tb, tl) = tag
            .as_ref()
            .map_or((open.byte, open.len), |(t, _)| (t.byte, t.len));
        let name = tag.as_ref().map(|(_, n)| n.as_str());
        self.store
            .define_enum(name, items)
            .map_err(|e| Self::store_fail(&e, tb, tl))
    }
}
