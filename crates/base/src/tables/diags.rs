//! The catalog data of `DiagCode` (design Sections 4.8 and 9.2).
//!
//! Loader diagnostics and C parser errors use these codes. They are data, never stderr text.

use crate::catalog::{CodeInfo, DiagCode, RepairClass};

/// Makes one catalog row. A diagnostic has no repair class and no retry.
const fn row(
    code: DiagCode,
    name: &'static str,
    message: &'static str,
    hint: &'static str,
) -> CodeInfo {
    CodeInfo {
        num: code as u16,
        name,
        class: RepairClass::None,
        retry: false,
        message,
        hint,
    }
}

/// Gives the catalog data of `code`.
pub(crate) const fn info(code: DiagCode) -> CodeInfo {
    use DiagCode as D;
    match code {
        D::Oob => row(
            code,
            "E_OOB",
            "A read goes past the end of its buffer or its table.",
            "The parser skips the item or stops the walk.",
        ),
        D::Overflow => row(
            code,
            "E_OVERFLOW",
            "An address or a size computation overflows 64 bits.",
            "The parser skips the item.",
        ),
        D::BadMagic => row(
            code,
            "E_BAD_MAGIC",
            "The magic value of a header or a record is wrong.",
            "Load the file as a raw blob when the format is not ELF or PE.",
        ),
        D::Limit => row(
            code,
            "E_LIMIT",
            "A count is above its limit. The parser keeps the clamped count.",
            "The limits table of the design gives each cap.",
        ),
        D::Loop => row(
            code,
            "E_LOOP",
            "A walk does not advance, or it comes back to a visited item.",
            "The parser stops the walk.",
        ),
        D::BadAlign => row(
            code,
            "E_BAD_ALIGN",
            "A value does not have the alignment of its type.",
            "The parser skips the item.",
        ),
        D::BadEntsize => row(
            code,
            "E_BAD_ENTSIZE",
            "A table entry size does not match its type.",
            "The parser skips the table.",
        ),
        D::UnsupportedReloc => row(
            code,
            "E_UNSUPPORTED_RELOC",
            "The relocation type is not in the MVP set.",
            "The parser skips the entry and reports each type once.",
        ),
        D::CfaOpcode => row(
            code,
            "E_CFA_OPCODE",
            "A CFA instruction has an unknown opcode.",
            "The parser stops the instructions of the FDE.",
        ),
        D::Overlap => row(
            code,
            "E_OVERLAP",
            "Two PE sections overlap. The later section replaces the overlapped part.",
            "The memory map keeps the later section.",
        ),
        D::Syntax => row(
            code,
            "E_SYNTAX",
            "The C text has a syntax error.",
            "The error gives the location and the expected tokens.",
        ),
        D::UnknownType => row(
            code,
            "E_UNKNOWN_TYPE",
            "The C text names a type that does not exist.",
            "The candidates hold the closest type names.",
        ),
        D::IncompleteByValue => row(
            code,
            "E_INCOMPLETE_BY_VALUE",
            "A record holds an incomplete type by value. A record cannot hold itself by value.",
            "Use a pointer to the type.",
        ),
        D::ConstExpr => row(
            code,
            "E_CONST_EXPR",
            "A constant expression does not evaluate to an integer.",
            "Use an integer constant.",
        ),
        D::Unsupported => row(
            code,
            "E_UNSUPPORTED",
            "The C text uses a feature outside the MVP: bit-fields, attributes, declspec or pragma pack.",
            "Remove the feature from the C text.",
        ),
    }
}
