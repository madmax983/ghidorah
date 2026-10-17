//! The canonical C text of a type and the type reference (design Sections 3.5 and 9.1).
//!
//! The C parser reads the canonical text back to the same type. The rules:
//!
//! - A declarator follows the base type after one space: `char *`, `int [4]`, `char *name`.
//! - A pointer to an array or a function gets parentheses: `int (*)[4]`, `void (*)(int)`.
//! - A qualifier comes before the base type, `const char *`, or after the star, `char *const`.
//! - A named record or enum prints its tag. A record without a tag prints its fields.
//! - An empty parameter list prints `void`. A variadic list ends with `, ...`.
//! - A function that does not return starts with `_Noreturn`. The calling convention has no text.
//!
//! A named type has the reference `t:<name>`. Another type has the reference `t:#<fnv64>`,
//! the FNV-1a hash of its canonical text.

use ghidorah_base::{TypeRef, fnv1a64};

use crate::store::{MAX_DEPTH, StoreError, TypeStore};
use crate::ty::{Enum, Prim, Quals, Record, Sig, Type, TypeId};

/// The longest canonical C text in bytes.
pub const MAX_TEXT: usize = 1 << 20;

/// Gives `text` when it fits in [`MAX_TEXT`].
fn fit(text: String) -> Result<String, StoreError> {
    if text.len() > MAX_TEXT {
        Err(StoreError::TextLimit)
    } else {
        Ok(text)
    }
}

/// Joins a base type and a declarator with one space.
fn join(base: &str, inner: &str) -> Result<String, StoreError> {
    if inner.is_empty() {
        Ok(base.to_string())
    } else {
        fit(format!("{base} {inner}"))
    }
}

/// Gives the qualifier words in canonical order.
fn qual_words(quals: Quals) -> String {
    let words = [
        (quals.is_const, "const"),
        (quals.is_volatile, "volatile"),
        (quals.is_restrict, "restrict"),
    ];
    words
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, w)| *w)
        .collect::<Vec<_>>()
        .join(" ")
}

impl TypeStore {
    /// Tells if a pointer to `to` needs parentheses around its declarator.
    fn needs_parens(&self, to: TypeId) -> bool {
        let pointee = match self.get(to) {
            Some(Type::Qual { inner, .. }) => self.get(*inner),
            other => other,
        };
        matches!(pointee, Some(Type::Array { .. } | Type::Func(_)))
    }

    /// Gives the declaration of `inner` with the type `id`, from the inside out.
    fn decl(&self, id: TypeId, inner: &str, depth: usize) -> Result<String, StoreError> {
        if depth > MAX_DEPTH {
            return Err(StoreError::Depth);
        }
        let next = depth.saturating_add(1);
        match self.get(id).ok_or(StoreError::UnknownId(id))? {
            Type::Prim(p) => join(p.c_name(), inner),
            Type::Record(r) => match &r.name {
                Some(name) => join(&format!("{} {name}", r.kind.keyword()), inner),
                None => join(
                    &format!("{} {}", r.kind.keyword(), self.fields_text(r, next)?),
                    inner,
                ),
            },
            Type::Enum(e) => match &e.name {
                Some(name) => join(&format!("enum {name}"), inner),
                None => join(&format!("enum {}", items_text(e)), inner),
            },
            Type::Typedef { name, .. } => join(name, inner),
            Type::Ptr(to) => self.pointer(*to, "*", inner, next),
            Type::Qual { quals, inner: base } => match self.get(*base) {
                Some(Type::Ptr(to)) => {
                    let star = format!("*{}", qual_words(*quals));
                    self.pointer(*to, &star, inner, next)
                }
                _ => fit(format!(
                    "{} {}",
                    qual_words(*quals),
                    self.decl(*base, inner, next)?
                )),
            },
            Type::Array { elem, len } => {
                let suffix = len.map_or_else(|| "[]".to_string(), |n| format!("[{n}]"));
                self.decl(*elem, &fit(format!("{inner}{suffix}"))?, next)
            }
            Type::Func(sig) => {
                let params = self.params_text(sig, next)?;
                let text = self.decl(sig.ret, &fit(format!("{inner}({params})"))?, next)?;
                if sig.noreturn {
                    fit(format!("_Noreturn {text}"))
                } else {
                    Ok(text)
                }
            }
        }
    }

    /// Gives the declaration of a pointer to `to`. `star` is `*` with its qualifiers.
    fn pointer(
        &self,
        to: TypeId,
        star: &str,
        inner: &str,
        depth: usize,
    ) -> Result<String, StoreError> {
        let mut s = star.to_string();
        if !inner.is_empty() {
            if star.len() > 1 {
                s.push(' ');
            }
            s.push_str(inner);
        }
        if self.needs_parens(to) {
            s = format!("({s})");
        }
        self.decl(to, &fit(s)?, depth)
    }

    /// Gives the parameter list of a signature, without the parentheses.
    fn params_text(&self, sig: &Sig, depth: usize) -> Result<String, StoreError> {
        if sig.params.is_empty() {
            return Ok(if sig.variadic { "..." } else { "void" }.to_string());
        }
        let mut out = String::new();
        for (i, p) in sig.params.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&self.decl(p.ty, p.name.as_deref().unwrap_or(""), depth)?);
            if out.len() > MAX_TEXT {
                return Err(StoreError::TextLimit);
            }
        }
        if sig.variadic {
            out.push_str(", ...");
        }
        Ok(out)
    }

    /// Gives the field list of a record in braces: `{ int a; char *b; }`.
    fn fields_text(&self, r: &Record, depth: usize) -> Result<String, StoreError> {
        let mut out = String::from("{");
        for f in &r.fields {
            out.push(' ');
            out.push_str(&self.decl(f.ty, &f.name, depth)?);
            out.push(';');
            if out.len() > MAX_TEXT {
                return Err(StoreError::TextLimit);
            }
        }
        out.push_str(" }");
        fit(out)
    }

    /// Gives the canonical C text of the type `id`, for example `const char *`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_text(&self, id: TypeId) -> Result<String, StoreError> {
        self.decl(id, "", 0)
    }

    /// Gives the canonical C declaration of `name` with the type `id`, for example `char *argv[]`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_decl(&self, id: TypeId, name: &str) -> Result<String, StoreError> {
        self.decl(id, name, 0)
    }

    /// Gives the C definition of a type, with a final `;`.
    ///
    /// A record gives `struct s { char a; int b; };`. An enum gives its constants.
    /// A typedef gives `typedef unsigned long size_t;`. Another type gives its declaration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_definition(&self, id: TypeId) -> Result<String, StoreError> {
        let text = match self.get(id).ok_or(StoreError::UnknownId(id))? {
            Type::Record(r) => {
                let head = match &r.name {
                    Some(name) => format!("{} {name}", r.kind.keyword()),
                    None => r.kind.keyword().to_string(),
                };
                if r.complete {
                    format!("{head} {}", self.fields_text(r, 1)?)
                } else {
                    head
                }
            }
            Type::Enum(e) => {
                let head = e
                    .name
                    .as_ref()
                    .map_or_else(|| "enum".to_string(), |n| format!("enum {n}"));
                if e.complete {
                    format!("{head} {}", items_text(e))
                } else {
                    head
                }
            }
            Type::Typedef { name, target } => format!("typedef {}", self.c_decl(*target, name)?),
            _ => self.c_text(id)?,
        };
        fit(format!("{text};"))
    }

    /// Gives the reference of the type `id`.
    ///
    /// A record or an enum with a tag, a typedef and a primitive type have a name.
    /// Another type has the hash of its canonical text.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`TypeStore::c_text`].
    pub fn type_ref(&self, id: TypeId) -> Result<TypeRef, StoreError> {
        let name = match self.get(id).ok_or(StoreError::UnknownId(id))? {
            Type::Record(Record { name: Some(n), .. })
            | Type::Enum(Enum { name: Some(n), .. })
            | Type::Typedef { name: n, .. } => Some(n.as_str()),
            Type::Prim(p) => Some(p.c_name()),
            _ => None,
        };
        match name {
            Some(n) => TypeRef::named(n).map_err(|_| StoreError::BadName(n.to_string())),
            None => Ok(TypeRef::anon(fnv1a64(self.c_text(id)?.as_bytes()))),
        }
    }

    /// Finds the type of a reference.
    ///
    /// A name finds a typedef first, then a tag, then a primitive type. A hash finds the
    /// first type in ID order whose canonical text has that hash.
    #[must_use]
    pub fn by_ref(&self, reference: &TypeRef) -> Option<TypeId> {
        if let Some(name) = reference.name() {
            return self
                .lookup_typedef(name)
                .or_else(|| self.lookup_tag(name))
                .or_else(|| Prim::from_c_name(name).map(|p| self.prim(p)));
        }
        let hash = reference.hash()?;
        self.ids().find(|id| {
            self.c_text(*id)
                .is_ok_and(|t| fnv1a64(t.as_bytes()) == hash)
        })
    }
}

/// Gives the constants of an enum in braces: `{ A = 0, B = 1 }`.
fn items_text(e: &Enum) -> String {
    if e.items.is_empty() {
        return "{ }".to_string();
    }
    let items: Vec<String> = e
        .items
        .iter()
        .map(|i| format!("{} = {}", i.name, i.value))
        .collect();
    format!("{{ {} }}", items.join(", "))
}
