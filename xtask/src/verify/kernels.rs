//! The kernel table of `xtask verify` (design Section 13.1).
//!
//! This file uses only `std`. The kernel test `proofs` includes it with `#[path]`.
//! So the test and the command read one table.

/// The Verus message of a failed `ensures` clause.
pub const POSTCONDITION: &str = "postcondition not satisfied";

/// The Verus message of a failed `assert`.
pub const ASSERTION: &str = "assertion failed";

/// The Verus message of a failed `requires` clause.
pub const PRECONDITION: &str = "precondition not satisfied";

/// The Verus messages that count as a verification error of a negative run.
pub const VERIFY_ERRORS: &[&str] = &[POSTCONDITION, ASSERTION, PRECONDITION];

/// One negative patch: a change to a kernel that Verus must reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negative {
    /// The patch name, for example `K1b`.
    pub name: &'static str,
    /// The Verus error that the patched copy must give, one of [`VERIFY_ERRORS`].
    pub kind: &'static str,
}

impl Negative {
    /// Gives the patch file, relative to the workspace root.
    #[must_use]
    pub fn path(&self) -> String {
        format!("verify/negative/{}.patch", self.name)
    }
}

/// One kernel of design Section 13.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kernel {
    /// The kernel name, for example `K1`.
    pub name: &'static str,
    /// The module of the kernel in `ghidorah-kernel`.
    pub module: &'static str,
    /// The negative patches of the kernel. Each patch gives one row of the record.
    pub negatives: &'static [Negative],
}

impl Kernel {
    /// Gives the main source file of the kernel, relative to the workspace root.
    #[must_use]
    pub fn file(&self) -> String {
        format!("crates/kernel/src/{}.rs", self.module)
    }

    /// Gives the directory of the submodules of the kernel, relative to the workspace root.
    #[must_use]
    pub fn dir(&self) -> String {
        format!("crates/kernel/src/{}", self.module)
    }
}

/// The kernels that `xtask verify` proves, in name order.
pub const KERNELS: &[Kernel] = &[
    Kernel {
        name: "K1",
        module: "reader",
        negatives: &[Negative {
            name: "K1",
            kind: POSTCONDITION,
        }],
    },
    Kernel {
        name: "K2",
        module: "range",
        negatives: &[Negative {
            name: "K2",
            kind: POSTCONDITION,
        }],
    },
    Kernel {
        name: "K3",
        module: "rangeset",
        negatives: &[Negative {
            name: "K3",
            kind: PRECONDITION,
        }],
    },
    Kernel {
        name: "K5",
        module: "flags",
        negatives: &[Negative {
            name: "K5",
            kind: POSTCONDITION,
        }],
    },
    Kernel {
        name: "K6",
        module: "budget",
        negatives: &[Negative {
            name: "K6",
            kind: POSTCONDITION,
        }],
    },
    Kernel {
        name: "K7",
        module: "source",
        negatives: &[Negative {
            name: "K7",
            kind: POSTCONDITION,
        }],
    },
];
