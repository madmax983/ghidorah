//! Declarators, parameter lists and the derivation of a declared type.
//!
//! A declarator gives a list of derivations. They apply to the base type in order:
//! the pointers, the suffixes from the last to the first, then the inner declarator.
//! So `int *a[3]` gives an array of three pointers, and `int (*a)[3]` gives a pointer to
//! an array.

use std::collections::BTreeSet;

use ghidorah_base::DiagCode;

use super::MAX_NESTING;
use super::diag::Fail;
use super::lex::Tok;
use super::parser::{Ctx, PResult, Parser};
use super::words::{is_keyword, qual_word, unsupported};
use crate::ty::{Param, Prim, Quals, Sig, Type, TypeId};

/// The name rule of a declarator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameMode {
    /// The `type` mode: no name.
    Forbidden,
    /// A parameter: a name or no name.
    Optional,
    /// A prototype or a field: a name.
    Required,
}

/// One derivation.
#[derive(Debug, Clone)]
enum OpKind {
    /// A pointer with its qualifiers.
    Ptr(Quals),
    /// An array of a length, or of unknown length.
    Array(Option<u64>),
    /// A function with its parameters and its variadic flag.
    Func(Vec<Param>, bool),
}

/// One derivation and the place of its token.
#[derive(Debug, Clone)]
struct Op {
    kind: OpKind,
    byte: usize,
    len: usize,
}

/// A parsed declarator.
#[derive(Debug, Clone, Default)]
pub(crate) struct Decl {
    /// The name and its place.
    pub(crate) name: Option<(String, usize, usize)>,
    ops: Vec<Op>,
}

/// The C adjustment of a parameter type.
enum Adjust {
    /// An array becomes a pointer to its element.
    Elem(TypeId),
    /// A function becomes a pointer to the function.
    Func,
}

fn nesting_fail(byte: usize, len: usize) -> Fail {
    Fail::new(DiagCode::Limit, byte, len)
        .hint("A declarator has more than 64 pointer, array or function parts.")
}

impl Parser<'_, '_> {
    /// Parses the qualifiers after a `*`.
    fn pointer_quals(&mut self) -> PResult<Quals> {
        let mut q = Quals::NONE;
        while let Some((t, w)) = self.peek_word() {
            if let Some(x) = qual_word(w) {
                q = q.union(x);
                self.bump();
            } else if let Some(hint) = unsupported(w) {
                return Err(Fail::new(DiagCode::Unsupported, t.byte, t.len).hint(hint));
            } else {
                break;
            }
        }
        Ok(q)
    }

    /// Tells if the current `(` starts a nested declarator, not a parameter list.
    fn nested_paren(&self, mode: NameMode) -> bool {
        match self.peek_at(1) {
            Some(t) => match t.tok {
                Tok::Punct("*" | "(" | "[") => true,
                Tok::Ident => {
                    let w = self.word(t);
                    mode != NameMode::Forbidden
                        && !is_keyword(w)
                        && self.store.lookup_typedef(w).is_none()
                }
                _ => false,
            },
            None => false,
        }
    }

    /// Parses a declarator.
    pub(crate) fn declarator(&mut self, mode: NameMode) -> PResult<Decl> {
        self.enter()?;
        let (start, start_len) = self.here();
        let mut ops = Vec::new();
        while let Some(t) = self.eat_punct("*") {
            let q = self.pointer_quals()?;
            ops.push(Op {
                kind: OpKind::Ptr(q),
                byte: t.byte,
                len: t.len,
            });
            if ops.len() > MAX_NESTING {
                return Err(nesting_fail(t.byte, t.len));
            }
        }
        let mut name = None;
        let mut inner = Vec::new();
        if self.is_punct("(") && self.nested_paren(mode) {
            self.bump();
            let d = self.declarator(mode)?;
            self.expect_punct(")", "`)`")?;
            name = d.name;
            inner = d.ops;
        } else if let Some((t, word)) = self.peek_word().filter(|(_, w)| !is_keyword(w)) {
            if mode == NameMode::Forbidden {
                return Err(Fail::new(DiagCode::Syntax, t.byte, t.len)
                    .expected(&["the end of the text"])
                    .hint("The type mode reads a type without a name. Remove the name."));
            }
            self.bump();
            name = Some((word.to_string(), t.byte, t.len));
        }
        let mut suffixes = Vec::new();
        while let Some(t) = self.peek() {
            let kind = if self.is_punct("[") {
                self.bump();
                OpKind::Array(self.array_len()?)
            } else if self.is_punct("(") {
                self.bump();
                let (params, variadic) = self.params()?;
                OpKind::Func(params, variadic)
            } else {
                break;
            };
            suffixes.push(Op {
                kind,
                byte: t.byte,
                len: t.len,
            });
            let count = ops
                .len()
                .saturating_add(suffixes.len())
                .saturating_add(inner.len());
            if count > MAX_NESTING {
                return Err(nesting_fail(t.byte, t.len));
            }
        }
        if mode == NameMode::Required && name.is_none() {
            return Err(Fail::new(DiagCode::Syntax, start, start_len)
                .expected(&["a name"])
                .hint("Give the declaration a name."));
        }
        self.leave();
        ops.extend(suffixes.into_iter().rev());
        ops.extend(inner);
        Ok(Decl { name, ops })
    }

    /// Parses an array length after `[`. `None` for `[]`.
    fn array_len(&mut self) -> PResult<Option<u64>> {
        if self.eat_punct("]").is_some() {
            return Ok(None);
        }
        let (byte, len) = self.here();
        let value = self.const_expr()?;
        self.expect_punct("]", "`]`")?;
        if value < 0 {
            return Err(Fail::new(DiagCode::ConstExpr, byte, len)
                .hint("An array length is not negative. Use a length of 0 or more."));
        }
        u64::try_from(value).map(Some).map_err(|_| {
            Fail::new(DiagCode::Overflow, byte, len).hint("An array length fits in 64 bits.")
        })
    }

    /// Parses a parameter list after `(`.
    fn params(&mut self) -> PResult<(Vec<Param>, bool)> {
        self.enter()?;
        let mut params = Vec::new();
        let mut variadic = false;
        let empty = self.is_punct(")")
            || (self.is_word("void") && self.peek_at(1).is_some_and(|t| t.tok == Tok::Punct(")")));
        if empty {
            if self.is_word("void") {
                self.bump();
            }
            self.bump();
            self.leave();
            return Ok((params, false));
        }
        let void = self.store.prim(Prim::Void);
        let mut names = BTreeSet::new();
        loop {
            if self.eat_punct("...").is_some() {
                variadic = true;
                self.expect_punct(")", "`)`")?;
                break;
            }
            let (sb, sl) = self.here();
            let (base, _) = self.specifiers(Ctx::Param)?;
            let d = self.declarator(NameMode::Optional)?;
            let ty = self.apply(base, &d)?;
            let ty = self.adjust_param(ty, sb, sl)?;
            if self.store.strip(ty) == Some(void) {
                return Err(Fail::new(DiagCode::Syntax, sb, sl)
                    .hint("A void parameter comes alone. Write `(void)` for no parameters."));
            }
            if params.len() >= super::MAX_PARAMS {
                return Err(Self::members_fail(sb, sl, "parameter"));
            }
            let name = match d.name {
                Some((n, nb, nl)) => {
                    if !names.insert(n.clone()) {
                        return Err(Fail::new(DiagCode::Syntax, nb, nl)
                            .hint("Give each parameter another name."));
                    }
                    Some(n)
                }
                None => None,
            };
            params.push(Param { name, ty });
            if self.eat_punct(",").is_some() {
                continue;
            }
            self.expect_punct(")", "`)`")?;
            break;
        }
        self.leave();
        Ok((params, variadic))
    }

    /// Applies the C adjustment of a parameter: arrays and functions become pointers.
    fn adjust_param(&mut self, ty: TypeId, byte: usize, len: usize) -> PResult<TypeId> {
        let adjust = match self.store.strip(ty).and_then(|t| self.store.get(t)) {
            Some(Type::Array { elem, .. }) => Some(Adjust::Elem(*elem)),
            Some(Type::Func(_)) => Some(Adjust::Func),
            _ => None,
        };
        let r = match adjust {
            Some(Adjust::Elem(elem)) => self.store.ptr(elem),
            Some(Adjust::Func) => self.store.ptr(ty),
            None => return Ok(ty),
        };
        r.map_err(|e| Self::store_fail(&e, byte, len))
    }

    /// Applies the derivations of a declarator to the base type.
    pub(crate) fn apply(&mut self, base: TypeId, d: &Decl) -> PResult<TypeId> {
        let mut t = base;
        for op in &d.ops {
            let r = match &op.kind {
                OpKind::Ptr(q) => match self.store.ptr(t) {
                    Ok(p) => self.store.qual(*q, p),
                    Err(e) => Err(e),
                },
                OpKind::Array(len) => self.store.array(t, *len),
                OpKind::Func(params, variadic) => self.store.func(Sig {
                    ret: t,
                    params: params.clone(),
                    variadic: *variadic,
                    cc: None,
                    noreturn: false,
                }),
            };
            t = r.map_err(|e| Self::store_fail(&e, op.byte, op.len))?;
        }
        Ok(t)
    }
}
