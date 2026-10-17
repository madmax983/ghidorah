//! The type core (design Section 9.1).
//!
//! A [`Type`] lives in a [`TypeStore`](crate::TypeStore) and has a [`TypeId`] there.
//! Types refer to other types by ID. The store keeps one ID for each derived type.

use crate::cc::CallConv;

/// The ID of a type inside one [`TypeStore`](crate::TypeStore).
///
/// Outside the store, a type has the text form `t:<name>` or `t:#<fnv64>` of
/// [`TypeRef`](ghidorah_base::TypeRef).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(u32);

impl TypeId {
    /// Makes the ID with the index `index`. The store checks each ID that it gets.
    #[must_use]
    pub const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Gives the index of the ID in its store.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// A primitive C type. The [`DataModel`](crate::DataModel) gives its size and alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prim {
    /// `void`.
    Void,
    /// `_Bool`.
    Bool,
    /// `char`. The data model tells if it is signed.
    Char,
    /// `signed char`.
    SChar,
    /// `unsigned char`.
    UChar,
    /// `short`.
    Short,
    /// `unsigned short`.
    UShort,
    /// `int`.
    Int,
    /// `unsigned int`.
    UInt,
    /// `long`.
    Long,
    /// `unsigned long`.
    ULong,
    /// `long long`.
    LongLong,
    /// `unsigned long long`.
    ULongLong,
    /// `__int128`.
    Int128,
    /// `unsigned __int128`.
    UInt128,
    /// `float`.
    Float,
    /// `double`.
    Double,
    /// `long double`.
    LongDouble,
    /// `wchar_t`. The data model gives its size.
    WChar,
}

impl Prim {
    /// All primitive types in declaration order.
    pub const ALL: [Self; 19] = [
        Self::Void,
        Self::Bool,
        Self::Char,
        Self::SChar,
        Self::UChar,
        Self::Short,
        Self::UShort,
        Self::Int,
        Self::UInt,
        Self::Long,
        Self::ULong,
        Self::LongLong,
        Self::ULongLong,
        Self::Int128,
        Self::UInt128,
        Self::Float,
        Self::Double,
        Self::LongDouble,
        Self::WChar,
    ];

    /// Gives the canonical C spelling, for example `unsigned long`.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "_Bool",
            Self::Char => "char",
            Self::SChar => "signed char",
            Self::UChar => "unsigned char",
            Self::Short => "short",
            Self::UShort => "unsigned short",
            Self::Int => "int",
            Self::UInt => "unsigned int",
            Self::Long => "long",
            Self::ULong => "unsigned long",
            Self::LongLong => "long long",
            Self::ULongLong => "unsigned long long",
            Self::Int128 => "__int128",
            Self::UInt128 => "unsigned __int128",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "long double",
            Self::WChar => "wchar_t",
        }
    }

    /// Finds the primitive type with the canonical C spelling `name`.
    #[must_use]
    pub fn from_c_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.c_name() == name)
    }

    /// Tells if the type is an integer type. `_Bool`, the character types and `wchar_t` count.
    #[must_use]
    pub const fn is_integer(self) -> bool {
        !matches!(
            self,
            Self::Void | Self::Float | Self::Double | Self::LongDouble
        )
    }

    /// Tells if the type is a floating type.
    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::Float | Self::Double | Self::LongDouble)
    }
}

/// The qualifiers of a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Quals {
    /// `const`.
    pub is_const: bool,
    /// `volatile`.
    pub is_volatile: bool,
    /// `restrict`.
    pub is_restrict: bool,
}

impl Quals {
    /// No qualifier.
    pub const NONE: Self = Self {
        is_const: false,
        is_volatile: false,
        is_restrict: false,
    };

    /// Only `const`.
    pub const CONST: Self = Self {
        is_const: true,
        is_volatile: false,
        is_restrict: false,
    };

    /// Tells if the value holds no qualifier.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.is_const && !self.is_volatile && !self.is_restrict
    }

    /// Gives the qualifiers of `self` and `other` together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            is_const: self.is_const || other.is_const,
            is_volatile: self.is_volatile || other.is_volatile,
            is_restrict: self.is_restrict || other.is_restrict,
        }
    }
}

/// The kind of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// `struct`.
    Struct,
    /// `union`.
    Union,
}

impl RecordKind {
    /// Gives the C keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Union => "union",
        }
    }
}

/// The kind of a tag. Records and enums share the tag name space of C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TagKind {
    /// `struct`.
    Struct,
    /// `union`.
    Union,
    /// `enum`.
    Enum,
}

impl TagKind {
    /// Gives the C keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
        }
    }
}

impl From<RecordKind> for TagKind {
    fn from(kind: RecordKind) -> Self {
        match kind {
            RecordKind::Struct => Self::Struct,
            RecordKind::Union => Self::Union,
        }
    }
}

/// One field of a record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field {
    /// The field name.
    pub name: String,
    /// The field type.
    pub ty: TypeId,
}

impl Field {
    /// Makes a field.
    #[must_use]
    pub fn new(name: &str, ty: TypeId) -> Self {
        Self {
            name: name.to_string(),
            ty,
        }
    }
}

/// A `struct` or a `union`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Record {
    /// The kind.
    pub kind: RecordKind,
    /// The tag, or `None` for a record without a tag.
    pub name: Option<String>,
    /// The fields in declaration order.
    pub fields: Vec<Field>,
    /// `false` for a declared record without a definition.
    pub complete: bool,
}

/// One constant of an enum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Enumerator {
    /// The constant name.
    pub name: String,
    /// The value.
    pub value: i128,
}

/// An `enum`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Enum {
    /// The tag, or `None` for an enum without a tag.
    pub name: Option<String>,
    /// The constants in declaration order.
    pub items: Vec<Enumerator>,
    /// `false` for a declared enum without a definition.
    pub complete: bool,
}

/// One parameter of a signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Param {
    /// The parameter name, if the signature gives one.
    pub name: Option<String>,
    /// The parameter type, after the array and function adjustment of C.
    pub ty: TypeId,
}

/// A function signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sig {
    /// The return type.
    pub ret: TypeId,
    /// The parameters in order.
    pub params: Vec<Param>,
    /// `true` when the parameter list ends with `...`.
    pub variadic: bool,
    /// The calling convention table. `None` selects the table of the binary format.
    pub cc: Option<&'static CallConv>,
    /// `true` when the function does not return.
    pub noreturn: bool,
}

/// A type of the store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    /// A primitive type.
    Prim(Prim),
    /// A pointer to the type.
    Ptr(TypeId),
    /// An array. `len: None` is an array of unknown length, for example a flexible member.
    Array {
        /// The element type.
        elem: TypeId,
        /// The element count.
        len: Option<u64>,
    },
    /// A `struct` or a `union`.
    Record(Record),
    /// An `enum`.
    Enum(Enum),
    /// A typedef name.
    Typedef {
        /// The typedef name.
        name: String,
        /// The type that the name stands for.
        target: TypeId,
    },
    /// A function type.
    Func(Sig),
    /// A qualified type.
    Qual {
        /// The qualifiers.
        quals: Quals,
        /// The type without the qualifiers.
        inner: TypeId,
    },
}
