//! The keywords of the C parser and the hints of the features outside the MVP.

use crate::ty::Quals;

/// The type keywords.
pub(crate) const TYPE_WORDS: [&str; 13] = [
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "bool", "__int128", "wchar_t",
];

/// The storage-class and function specifiers that the `sig` mode accepts.
const STORAGE_WORDS: [&str; 7] = [
    "extern",
    "static",
    "inline",
    "__inline",
    "__inline__",
    "register",
    "auto",
];

/// The hint of `__attribute__`.
const ATTRIBUTE: &str =
    "Remove __attribute__ from the text. The Tier-0 attribute comment holds function attributes.";

/// The hint of a preprocessor line.
pub(crate) const PRAGMA: &str =
    "Remove the #pragma or other preprocessor line. Packing is not in the MVP.";

/// The hint of a bit-field.
pub(crate) const BIT_FIELD: &str =
    "The parser does not read bit-fields. Give the field its full integer type.";

/// The hint of a member without a name.
pub(crate) const NO_NAME_MEMBER: &str = "Give each member a name.";

/// The hint of a C23 attribute.
pub(crate) const C23_ATTRIBUTE: &str = "Remove the [[...]] attribute from the text.";

/// The words of features outside the MVP and their hints.
const UNSUPPORTED: [(&str, &str); 15] = [
    ("__attribute__", ATTRIBUTE),
    ("__attribute", ATTRIBUTE),
    ("__declspec", "Remove __declspec from the text."),
    (
        "_Alignas",
        "Remove _Alignas. The natural layout gives the alignment.",
    ),
    (
        "alignas",
        "Remove _Alignas. The natural layout gives the alignment.",
    ),
    (
        "_Atomic",
        "Remove _Atomic. The parser reads no atomic type.",
    ),
    (
        "_Complex",
        "Remove _Complex. The parser reads no complex type.",
    ),
    (
        "__complex__",
        "Remove _Complex. The parser reads no complex type.",
    ),
    (
        "_Imaginary",
        "Remove _Complex. The parser reads no complex type.",
    ),
    ("_BitInt", "Remove _BitInt. Use a standard integer type."),
    (
        "typedef",
        "The parser reads one type or one prototype. A typedef declaration needs the decls mode, which is not in the MVP.",
    ),
    ("asm", "Remove the asm label from the text."),
    ("__asm", "Remove the asm label from the text."),
    ("__asm__", "Remove the asm label from the text."),
    (
        "_Thread_local",
        "Remove _Thread_local. The parser reads types, not objects.",
    ),
];

/// The words that end a constant expression with `E_CONST_EXPR`.
pub(crate) const SIZE_WORDS: [&str; 4] = ["sizeof", "_Alignof", "alignof", "__alignof__"];

/// Gives the qualifier of a qualifier word.
pub(crate) fn qual_word(word: &str) -> Option<Quals> {
    let mut q = Quals::NONE;
    match word {
        "const" | "__const" | "__const__" => q.is_const = true,
        "volatile" | "__volatile" | "__volatile__" => q.is_volatile = true,
        "restrict" | "__restrict" | "__restrict__" => q.is_restrict = true,
        _ => return None,
    }
    Some(q)
}

/// Tells if `word` is a storage-class or function specifier other than `_Noreturn`.
pub(crate) fn is_storage(word: &str) -> bool {
    STORAGE_WORDS.contains(&word)
}

/// Gives the hint of a word of a feature outside the MVP.
pub(crate) fn unsupported(word: &str) -> Option<&'static str> {
    UNSUPPORTED
        .iter()
        .find(|(w, _)| *w == word)
        .map(|(_, hint)| *hint)
}

/// Tells if `word` is a keyword. A keyword is never a declarator name.
pub(crate) fn is_keyword(word: &str) -> bool {
    TYPE_WORDS.contains(&word)
        || qual_word(word).is_some()
        || is_storage(word)
        || unsupported(word).is_some()
        || SIZE_WORDS.contains(&word)
        || matches!(word, "struct" | "union" | "enum" | "_Noreturn")
}
