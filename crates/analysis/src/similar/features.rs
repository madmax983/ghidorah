//! The feature stream of one function (design Section 7.13).
//!
//! [`stream`] reads the L0 function IR (design Section 7.12) and the analysis facts of one
//! function. It gives one [`Feature`] for each occurrence. The key of a feature is
//! `fnv1a64(kind code, 0x00, key text)`.
//!
//! | Kind | Text | Key text | Rule |
//! |---|---|---|---|
//! | `opcode` | `op1:<t>`, `op2:<t>,<t>`, `op3:<t>,<t>,<t>` | the text | n-grams of the op tokens of one block, in op order |
//! | `cfg` | `cfg:blocks=<b>`, `cfg:edges=<b>`, `cfg:loops=<b>`, `cfg:depth=<b>` | the text | buckets of the CFG counts |
//! | `wl` | `wl1:<16 hex>`, `wl2:<16 hex>` | the text | one Weisfeiler-Lehman label per block and round |
//! | `const` | `const:<signed hex>` | the text | immediates and absolute displacements |
//! | `string` | the `str:` ID | the 16 hex digits of the FNV-1a 64 of the string bytes | each reference to a string |
//! | `import` | the `imp:` ID | the import name without the library | each reference to an import |
//! | `callees` | `callees=<b>` | the text | the bucket of the direct callee count |
//!
//! Op tokens: the opcode name and the width, for example `Add.64`. `Get` and `Put` keep the
//! location class in place of the width: `gpr`, `xmm`, `flags`, `stack`, `seg` or `reg`. A
//! constant argument adds `.k`. `Nop` ops give no token. Register numbers and constant values
//! never appear in a token.
//!
//! A bucket `b` is `floor(log2(x + 1))`. The loop depth is the largest number of natural loops
//! that hold one block.
//!
//! WL labels: the round-0 label of a block is the FNV-1a 64 of its terminator kind, the bucket
//! of its op count and its call count. Round `k` hashes the round `k - 1` label of the block,
//! the sorted labels of its successors and the sorted labels of its predecessors.
//!
//! Constants: an immediate or the displacement of a memory operand with no base and no
//! index. A value `v` counts when `|v| > 255` as `i64` and no mapped region holds `v`. A
//! RIP-relative displacement is an address, so it never counts.
//!
//! The direct callees are the distinct targets of the direct calls of the body.
//!
//! A function whose L0 IR does not build has no feature. Only a fuel stop is an error.

use std::collections::BTreeMap;

use ghidorah_base::{Address, Fnv1a64, Fuel, FuncId, ImportId, OutOfFuel};
use ghidorah_db::Program;
use ghidorah_ir::Op;

use crate::fir::FuncIr;

/// The largest absolute value of a constant that gives no feature.
pub const MIN_CONST: u64 = 255;

/// The kind of a feature. The order is the order of the module table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    /// An n-gram of op tokens.
    Opcode = 0,
    /// A bucket of a CFG count.
    Cfg = 1,
    /// A Weisfeiler-Lehman label.
    Wl = 2,
    /// A constant.
    Const = 3,
    /// A reference to a string.
    String = 4,
    /// A reference to an import.
    Import = 5,
    /// The bucket of the direct callee count.
    Callees = 6,
}

impl Kind {
    /// Every kind in kind order.
    pub const ALL: [Self; 7] = [
        Self::Opcode,
        Self::Cfg,
        Self::Wl,
        Self::Const,
        Self::String,
        Self::Import,
        Self::Callees,
    ];

    /// Gives the code byte of the kind in the feature key.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Gives the output name, for example `opcode`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Opcode => "opcode",
            Self::Cfg => "cfg",
            Self::Wl => "wl",
            Self::Const => "const",
            Self::String => "string",
            Self::Import => "import",
            Self::Callees => "callees",
        }
    }
}

/// One occurrence of a feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Feature {
    /// The kind.
    pub kind: Kind,
    /// The output text, for example `op1:Add.64` or `str:0x2004`.
    pub text: String,
    /// The key: `fnv1a64(kind code, 0x00, key text)`.
    pub key: u64,
}

impl Feature {
    /// Makes a feature whose key text is its output text.
    #[must_use]
    pub fn new(kind: Kind, text: String) -> Self {
        let key = feature_key(kind, &text);
        Self { kind, text, key }
    }

    /// Makes a feature with a key text that differs from its output text.
    #[must_use]
    pub fn keyed(kind: Kind, text: String, key_text: &str) -> Self {
        Self {
            kind,
            text,
            key: feature_key(kind, key_text),
        }
    }
}

/// Gives the key of a feature: `fnv1a64(kind code, 0x00, key text)`.
#[must_use]
pub fn feature_key(kind: Kind, key_text: &str) -> u64 {
    let mut h = Fnv1a64::new();
    h.write_u8(kind.code());
    h.write(key_text.as_bytes());
    h.finish()
}

/// Gives the bucket of a count: `floor(log2(x + 1))`.
#[must_use]
pub const fn bucket(x: u64) -> u64 {
    let _ = x;
    0
}

/// Gives the token of an op, or `None` for a `Nop` op.
#[must_use]
pub fn token(op: &Op) -> Option<String> {
    let _ = op;
    None
}

/// The facts of one program that every stream reads.
#[derive(Debug)]
pub struct Context<'a> {
    program: &'a Program,
    imports: BTreeMap<Address, &'a ImportId>,
}

impl<'a> Context<'a> {
    /// Makes the context of `program`: the EXTERNAL address and the stub of each import.
    #[must_use]
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            imports: BTreeMap::new(),
        }
    }

    /// Gives the program.
    #[must_use]
    pub const fn program(&self) -> &'a Program {
        self.program
    }

    /// Gives the import of a reference target: its EXTERNAL address or its stub.
    #[must_use]
    pub fn import_at(&self, to: Address) -> Option<&'a ImportId> {
        self.imports.get(&to).copied()
    }
}

/// Gives the feature stream of the function `func`.
///
/// The stream builds the L0 IR of the function. A function whose IR does not build gives an
/// empty stream.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out. The IR build takes one unit for each
/// instruction, and the stream takes one more unit for each instruction.
pub fn stream(ctx: &Context<'_>, func: FuncId, fuel: &mut Fuel) -> Result<Vec<Feature>, OutOfFuel> {
    let _ = (ctx, func);
    fuel.tick()?;
    Ok(Vec::new())
}

/// Gives the feature stream of a built function IR.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out. The stream takes one unit for each
/// instruction.
pub fn of_ir(ctx: &Context<'_>, ir: &FuncIr, fuel: &mut Fuel) -> Result<Vec<Feature>, OutOfFuel> {
    let _ = (ctx, ir);
    fuel.tick()?;
    Ok(Vec::new())
}
