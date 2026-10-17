//! Const tables of the crate.

pub(crate) mod prelude;

use crate::ty::RecordKind;

/// One prelude item.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Item {
    /// `typedef <type text> <name>;`: the name, then the type text.
    Typedef(&'static str, &'static str),
    /// A declared record without fields: the kind, then the tag.
    Opaque(RecordKind, &'static str),
    /// A record with fields: the kind, the tag, then each field name and its type text.
    Record(
        RecordKind,
        &'static str,
        &'static [(&'static str, &'static str)],
    ),
}
