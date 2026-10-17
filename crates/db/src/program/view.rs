//! The merged reads of a program over its two layers.
//!
//! The module doc of [`crate::program`] gives the merge rules. Default names come from
//! [`Program::default_name`] on each read. The DB never stores them.

use ghidorah_base::{Address, DefaultName, FuncId, JumpTableId, VarId};
use ghidorah_types::TypeId;

use super::Program;
use crate::comments::CommentKind;
use crate::fact::Fact;
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::{CodeUnit, DataDef};
use crate::overrides::FlowOverride;
use crate::refs::Ref;
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
    /// Gives a function.
    #[must_use]
    pub fn func(&self, id: FuncId) -> Option<FuncView<'_>> {
        let _ = id;
        None
    }

    /// Gives all functions in entry order.
    #[must_use]
    pub fn funcs(&self) -> Vec<FuncView<'_>> {
        Vec::new()
    }

    /// Gives the function whose body holds `addr`. The analysis layer comes first.
    #[must_use]
    pub fn owner_of(&self, addr: Address) -> Option<FuncId> {
        let _ = addr;
        None
    }

    /// Gives the symbols of an address: the base layer first, each layer in key order.
    #[must_use]
    pub fn symbols_at(&self, addr: Address) -> Vec<&Symbol> {
        let _ = addr;
        Vec::new()
    }

    /// Gives the primary symbol of an address. The base layer wins.
    #[must_use]
    pub fn primary_symbol(&self, addr: Address) -> Option<&Symbol> {
        let _ = addr;
        None
    }

    /// Gives the addresses with a symbol of this name in address order. A default name has
    /// no symbol.
    #[must_use]
    pub fn addrs_named(&self, name: &str) -> Vec<Address> {
        let _ = name;
        Vec::new()
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
        let _ = addr;
        None
    }

    /// Gives the name of an address: the primary symbol name, else the default name.
    #[must_use]
    pub fn name(&self, addr: Address) -> Option<Name> {
        let _ = addr;
        None
    }

    /// Gives the references from `from`: both layers in key order. The base layer wins for
    /// the same key.
    #[must_use]
    pub fn refs_from(&self, from: Address) -> Vec<&Fact<Ref>> {
        let _ = from;
        Vec::new()
    }

    /// Gives the references to `to` in the order of the to-index. The base layer wins for
    /// the same key.
    #[must_use]
    pub fn refs_to(&self, to: Address) -> Vec<&Fact<Ref>> {
        let _ = to;
        Vec::new()
    }

    /// Gives the comment of `kind` at `addr` with the higher rank.
    #[must_use]
    pub fn comment(&self, addr: Address, kind: CommentKind) -> Option<&Fact<String>> {
        let _ = (addr, kind);
        None
    }

    /// Gives the jump table of an indirect jump with the higher rank.
    #[must_use]
    pub fn jump_table(&self, id: JumpTableId) -> Option<&Fact<JumpTable>> {
        let _ = id;
        None
    }

    /// Gives the flow override at `at` with the higher rank.
    #[must_use]
    pub fn flow_override(&self, at: Address) -> Option<&Fact<FlowOverride>> {
        let _ = at;
        None
    }

    /// Gives the data definition at the RAM offset `off` with the higher rank.
    #[must_use]
    pub fn data_def(&self, off: u64) -> Option<&Fact<DataDef>> {
        let _ = off;
        None
    }

    /// Gives the code unit at the RAM offset `off`. The analysis layer comes first.
    #[must_use]
    pub fn code_unit(&self, off: u64) -> Option<&CodeUnit> {
        let _ = off;
        None
    }

    /// Gives the facts of a variable. Each fact has the higher rank.
    #[must_use]
    pub fn var(&self, id: &VarId) -> VarView<'_> {
        let _ = id;
        VarView::default()
    }

    /// Gives the string at the RAM offset `off`. The analysis layer comes first.
    #[must_use]
    pub fn string(&self, off: u64) -> Option<&StrInfo> {
        let _ = off;
        None
    }

    /// Gives the why-record of a fact. The analysis layer comes first.
    #[must_use]
    pub fn why(&self, key: &FactKey) -> Option<&Why> {
        let _ = key;
        None
    }
}
