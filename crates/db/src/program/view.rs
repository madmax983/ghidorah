//! The merged reads of a program over its two layers.
//!
//! The module doc of [`crate::program`] gives the merge rules. Default names come from
//! [`Program::default_name`] on each read. The DB never stores them.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, DefaultKind, DefaultName, FuncId, JumpTableId, VarId};
use ghidorah_loader::Perms;
use ghidorah_types::TypeId;

use super::Program;
use crate::comments::CommentKind;
use crate::fact::{Fact, higher};
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::{CodeUnit, DataDef};
use crate::overrides::FlowOverride;
use crate::refs::{Ref, RefKey};
use crate::source::Source;
use crate::strings::StrInfo;
use crate::symbols::Symbol;
use crate::why::{FactKey, Why};

/// A function as a read sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuncView<'a> {
    /// The record with the body and the parts. The analysis record comes first.
    pub func: &'a Function,
    /// The source: the base record gives it when it exists.
    pub source: Source,
    /// The signature fact of the higher rank.
    pub sig: Option<&'a Fact<TypeId>>,
    /// The noreturn fact of the higher rank.
    pub noreturn: Option<&'a Fact<bool>>,
}

impl FuncView<'_> {
    /// Gives the ID.
    #[must_use]
    pub const fn id(&self) -> FuncId {
        self.func.id()
    }
}

/// The facts of a variable as a read sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VarView<'a> {
    /// The name fact of the higher rank.
    pub name: Option<&'a Fact<String>>,
    /// The type fact of the higher rank.
    pub ty: Option<&'a Fact<TypeId>>,
}

/// The name of an address: a symbol name or a computed default name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// The text.
    pub text: String,
    /// The source. A computed default name has the source `Default`.
    pub source: Source,
}

impl Name {
    /// Tells if the name is a computed default name.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.source == Source::Default
    }
}

impl Program {
    /// Merges the base record `b` and the analysis record `a` of one function.
    fn view<'a>(b: Option<&'a Function>, a: Option<&'a Function>) -> Option<FuncView<'a>> {
        let func = a.or(b)?;
        Some(FuncView {
            func,
            source: b.map_or(func.source, |f| f.source),
            sig: higher(
                b.and_then(|f| f.sig.as_ref()),
                a.and_then(|f| f.sig.as_ref()),
            ),
            noreturn: higher(
                b.and_then(|f| f.flags.noreturn.as_ref()),
                a.and_then(|f| f.flags.noreturn.as_ref()),
            ),
        })
    }

    /// Gives a function.
    #[must_use]
    pub fn func(&self, id: FuncId) -> Option<FuncView<'_>> {
        Self::view(self.base.funcs.get(id), self.analysis.funcs.get(id))
    }

    /// Gives all functions in entry order.
    #[must_use]
    pub fn funcs(&self) -> Vec<FuncView<'_>> {
        let ids: BTreeSet<FuncId> = self
            .base
            .funcs
            .iter()
            .chain(self.analysis.funcs.iter())
            .map(Function::id)
            .collect();
        ids.into_iter().filter_map(|id| self.func(id)).collect()
    }

    /// Gives the function whose body holds `addr`. The analysis layer comes first.
    #[must_use]
    pub fn owner_of(&self, addr: Address) -> Option<FuncId> {
        if !addr.is_ram() {
            return None;
        }
        self.analysis
            .funcs
            .owner_of(addr.off)
            .or_else(|| self.base.funcs.owner_of(addr.off))
    }

    /// Gives the symbols of an address: the base layer first, each layer in key order.
    #[must_use]
    pub fn symbols_at(&self, addr: Address) -> Vec<&Symbol> {
        self.base
            .symbols
            .at(addr)
            .chain(self.analysis.symbols.at(addr))
            .collect()
    }

    /// Gives the primary symbol of an address. The base layer wins.
    #[must_use]
    pub fn primary_symbol(&self, addr: Address) -> Option<&Symbol> {
        self.base
            .symbols
            .primary(addr)
            .or_else(|| self.analysis.symbols.primary(addr))
    }

    /// Gives the addresses with a symbol of this name in address order. A default name has
    /// no symbol.
    #[must_use]
    pub fn addrs_named(&self, name: &str) -> Vec<Address> {
        let all: BTreeSet<Address> = self
            .base
            .symbols
            .by_name(name)
            .iter()
            .chain(self.analysis.symbols.by_name(name))
            .copied()
            .collect();
        all.into_iter().collect()
    }

    /// Gives the computed default name of an address:
    ///
    /// | Address | Name |
    /// |---|---|
    /// | in the EXTERNAL space | `EXT_` |
    /// | a function entry | `FUN_` |
    /// | an instruction start, or in an executable region | `LAB_` |
    /// | a data definition, or in another mapped region | `DAT_` |
    /// | not mapped | `None` |
    #[must_use]
    pub fn default_name(&self, addr: Address) -> Option<DefaultName> {
        if !addr.is_ram() {
            return Some(DefaultName::new(DefaultKind::Ext, addr.off));
        }
        let kind = if self.func(FuncId(addr)).is_some() {
            DefaultKind::Fun
        } else if self.code_unit(addr.off).is_some() {
            DefaultKind::Lab
        } else if self.data_def(addr.off).is_some() {
            DefaultKind::Dat
        } else if self.mem.region_at(addr.off)?.perms.contains(Perms::EXECUTE) {
            DefaultKind::Lab
        } else {
            DefaultKind::Dat
        };
        Some(DefaultName::new(kind, addr.off))
    }

    /// Gives the name of an address: the primary symbol name, else the default name.
    #[must_use]
    pub fn name(&self, addr: Address) -> Option<Name> {
        if let Some(s) = self.primary_symbol(addr) {
            return Some(Name {
                text: s.name.value.clone(),
                source: s.name.source,
            });
        }
        self.default_name(addr).map(|d| Name {
            text: d.to_string(),
            source: Source::Default,
        })
    }

    /// Merges the reference lists of both layers in the order of `order`. The base layer wins
    /// for the same key.
    fn merge_refs<'a, K: Ord>(
        base: impl Iterator<Item = &'a Fact<Ref>>,
        analysis: impl Iterator<Item = &'a Fact<Ref>>,
        order: impl Fn(&RefKey) -> K,
    ) -> Vec<&'a Fact<Ref>> {
        let mut all: BTreeMap<K, &'a Fact<Ref>> = BTreeMap::new();
        for r in analysis.chain(base) {
            all.insert(order(&r.value.key), r);
        }
        all.into_values().collect()
    }

    /// Gives the references from `from`: both layers in key order. The base layer wins for
    /// the same key.
    #[must_use]
    pub fn refs_from(&self, from: Address) -> Vec<&Fact<Ref>> {
        Self::merge_refs(
            self.base.refs.from(from),
            self.analysis.refs.from(from),
            |k| *k,
        )
    }

    /// Gives the references to `to` in the order of the to-index. The base layer wins for
    /// the same key.
    #[must_use]
    pub fn refs_to(&self, to: Address) -> Vec<&Fact<Ref>> {
        Self::merge_refs(self.base.refs.to(to), self.analysis.refs.to(to), |k| {
            (k.to, k.from, k.op_index, k.kind)
        })
    }

    /// Gives the comment of `kind` at `addr` with the higher rank.
    #[must_use]
    pub fn comment(&self, addr: Address, kind: CommentKind) -> Option<&Fact<String>> {
        higher(
            self.base.comments.get(addr, kind),
            self.analysis.comments.get(addr, kind),
        )
    }

    /// Gives the jump table of an indirect jump with the higher rank.
    #[must_use]
    pub fn jump_table(&self, id: JumpTableId) -> Option<&Fact<JumpTable>> {
        higher(
            self.base.jumptables.get(id),
            self.analysis.jumptables.get(id),
        )
    }

    /// Gives the flow override at `at` with the higher rank.
    #[must_use]
    pub fn flow_override(&self, at: Address) -> Option<&Fact<FlowOverride>> {
        higher(self.base.overrides.get(at), self.analysis.overrides.get(at))
    }

    /// Gives the data definition at the RAM offset `off` with the higher rank.
    #[must_use]
    pub fn data_def(&self, off: u64) -> Option<&Fact<DataDef>> {
        higher(self.base.listing.data(off), self.analysis.listing.data(off))
    }

    /// Gives the code unit at the RAM offset `off`. The analysis layer comes first.
    #[must_use]
    pub fn code_unit(&self, off: u64) -> Option<&CodeUnit> {
        self.analysis
            .listing
            .unit(off)
            .or_else(|| self.base.listing.unit(off))
    }

    /// Gives the facts of a variable. Each fact has the higher rank.
    #[must_use]
    pub fn var(&self, id: &VarId) -> VarView<'_> {
        let b = self.base.vars.get(id);
        let a = self.analysis.vars.get(id);
        VarView {
            name: higher(
                b.and_then(|v| v.name.as_ref()),
                a.and_then(|v| v.name.as_ref()),
            ),
            ty: higher(b.and_then(|v| v.ty.as_ref()), a.and_then(|v| v.ty.as_ref())),
        }
    }

    /// Gives the string at the RAM offset `off`. The analysis layer comes first.
    #[must_use]
    pub fn string(&self, off: u64) -> Option<&StrInfo> {
        self.analysis
            .strings
            .get(off)
            .or_else(|| self.base.strings.get(off))
    }

    /// Gives the why-record of a fact. The analysis layer comes first.
    #[must_use]
    pub fn why(&self, key: &FactKey) -> Option<&Why> {
        self.analysis
            .why
            .get(key)
            .or_else(|| self.base.why.get(key))
    }
}
