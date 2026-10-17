//! The layout and the write of a full file.

use super::{ElfBuilder, Layout, malformed};

/// Lays out and writes the file of `builder`.
pub(crate) fn build(builder: &ElfBuilder) -> (Vec<u8>, Layout) {
    let mut bytes = Vec::new();
    malformed::apply(&mut bytes, &builder.malformed);
    (bytes, Layout::default())
}
