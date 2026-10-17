//! [`Program::from_binary`]: the `Imported` facts of a loaded binary.

use std::collections::BTreeMap;

use ghidorah_base::Limits;
use ghidorah_loader::{Binary, MemoryMap};

use super::{BinaryMeta, Program, ProgramError, Tables};
use crate::notes::Notes;
use crate::progress::Progress;
use crate::typesglue::Types;

/// Makes the program of a loaded binary.
pub(super) fn from_binary(
    binary: Binary,
    mem: MemoryMap,
    limits: &Limits,
) -> Result<Program, ProgramError> {
    let _ = limits;
    let types = Types::for_format(binary.format).map_err(ProgramError::Prelude)?;
    let meta = BinaryMeta {
        binary_id: binary.identity.binary_id(),
        sha256: binary.identity.sha256,
        format: binary.format,
        arch: binary.arch,
        bits: binary.bits,
        kind: binary.kind,
        image_base: binary.image_base,
        file_size: 0,
    };
    Ok(Program {
        binary,
        mem,
        meta,
        imports: BTreeMap::new(),
        exports: BTreeMap::new(),
        types,
        base: Tables::default(),
        analysis: Box::default(),
        notes: Notes::default(),
        progress: Progress::default(),
        rev: ghidorah_base::Rev(0),
    })
}
