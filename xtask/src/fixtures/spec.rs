//! The fixture table: programs, build configurations and variants (design Section 12.3).
//!
//! A fixture name is `<program>.<build>` for a build and `<program>.<build>.<variant>` for a
//! variant. A variant has the same code as its build, so it shares the truth file of the build.
//!
//! | Build | Compiler flags | Link flags | Twin | Leaf vectors |
//! |---|---|---|---|---|
//! | `gcc-O0` | `-O0` | - | yes | yes |
//! | `gcc-O2` | `-O2` | - | yes | no |
//! | `clang-O2` | `-O2` | - | yes | no |
//! | `gcc-O2nv` | `-O2 -fno-tree-vectorize` | - | no | yes |
//! | `clang-O2nv` | `-O2 -fno-vectorize -fno-slp-vectorize` | - | no | yes |
//! | `gcc-O2-nocet-nopie` | `-O2 -fcf-protection=none -fno-pie` | `-no-pie` | no | no |
//! | `gcc-O2-noplt` | `-O2 -fno-plt` | - | no | no |
//! | `gcc-O2-at400000` | `-O2 -fno-pie` | `-no-pie -Wl,-Ttext-segment=0x400000` | no | no |
//! | `gcc-O2-at800000` | `-O2 -fno-pie` | `-no-pie -Wl,-Ttext-segment=0x800000` | no | no |
//!
//! Host defaults stay on: PIE, CET (`-fcf-protection`), the stack protector and FORTIFY.

/// A C compiler of the fixture build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Compiler {
    /// GCC 13.
    Gcc,
    /// Clang 18.
    Clang,
}

impl Compiler {
    /// Gives the program name of the compiler driver.
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Clang => "clang",
        }
    }
}

/// The fixture tier of design Section 12.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Small first-party C programs.
    T1,
    /// The generated large program.
    T2,
}

impl Tier {
    /// Gives the tier name, `T1` or `T2`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::T1 => "T1",
            Self::T2 => "T2",
        }
    }
}

/// One build configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Build {
    /// The build ID in fixture names, for example `gcc-O2`.
    pub id: &'static str,
    /// The compiler.
    pub compiler: Compiler,
    /// The compiler flags.
    pub cflags: &'static [&'static str],
    /// The link flags.
    pub ldflags: &'static [&'static str],
    /// Tells if the build also gets a stripped twin.
    pub twin: bool,
    /// Tells if the leaf driver runs on the build.
    pub leaf_vectors: bool,
}

/// GCC without optimization.
pub const GCC_O0: Build = Build {
    id: "gcc-O0",
    compiler: Compiler::Gcc,
    cflags: &["-O0"],
    ldflags: &[],
    twin: true,
    leaf_vectors: true,
};

/// GCC at `-O2` with the host defaults.
pub const GCC_O2: Build = Build {
    id: "gcc-O2",
    compiler: Compiler::Gcc,
    cflags: &["-O2"],
    ldflags: &[],
    twin: true,
    leaf_vectors: false,
};

/// Clang at `-O2`.
pub const CLANG_O2: Build = Build {
    id: "clang-O2",
    compiler: Compiler::Clang,
    cflags: &["-O2"],
    ldflags: &[],
    twin: true,
    leaf_vectors: false,
};

/// GCC at `-O2` without the vectorizer, for leaf subjects.
pub const GCC_O2NV: Build = Build {
    id: "gcc-O2nv",
    compiler: Compiler::Gcc,
    cflags: &["-O2", "-fno-tree-vectorize"],
    ldflags: &[],
    twin: false,
    leaf_vectors: true,
};

/// Clang at `-O2` without the vectorizers, for leaf subjects.
pub const CLANG_O2NV: Build = Build {
    id: "clang-O2nv",
    compiler: Compiler::Clang,
    cflags: &["-O2", "-fno-vectorize", "-fno-slp-vectorize"],
    ldflags: &[],
    twin: false,
    leaf_vectors: true,
};

/// GCC at `-O2` without CET and without PIE.
pub const GCC_O2_NOPIE: Build = Build {
    id: "gcc-O2-nocet-nopie",
    compiler: Compiler::Gcc,
    cflags: &["-O2", "-fcf-protection=none", "-fno-pie"],
    ldflags: &["-no-pie"],
    twin: false,
    leaf_vectors: false,
};

/// GCC at `-O2` with `-fno-plt`.
pub const GCC_O2_NOPLT: Build = Build {
    id: "gcc-O2-noplt",
    compiler: Compiler::Gcc,
    cflags: &["-O2", "-fno-plt"],
    ldflags: &[],
    twin: false,
    leaf_vectors: false,
};

/// The first build of the rebase pair: the text segment at `0x400000`.
pub const GCC_O2_AT400000: Build = Build {
    id: "gcc-O2-at400000",
    compiler: Compiler::Gcc,
    cflags: &["-O2", "-fno-pie"],
    ldflags: &["-no-pie", "-Wl,-Ttext-segment=0x400000"],
    twin: false,
    leaf_vectors: false,
};

/// The second build of the rebase pair: the text segment at `0x800000`.
pub const GCC_O2_AT800000: Build = Build {
    id: "gcc-O2-at800000",
    compiler: Compiler::Gcc,
    cflags: &["-O2", "-fno-pie"],
    ldflags: &["-no-pie", "-Wl,-Ttext-segment=0x800000"],
    twin: false,
    leaf_vectors: false,
};

/// Every build configuration, in table order.
pub const BUILDS: &[Build] = &[
    GCC_O0,
    GCC_O2,
    CLANG_O2,
    GCC_O2NV,
    CLANG_O2NV,
    GCC_O2_NOPIE,
    GCC_O2_NOPLT,
    GCC_O2_AT400000,
    GCC_O2_AT800000,
];

/// A variant that the build makes from a built binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    /// `strip` removes `.symtab` and `.strtab`.
    Stripped,
    /// Stripped, then `objcopy` removes `.eh_frame` and `.eh_frame_hdr`.
    NoEh,
    /// Stripped, then without the table of section headers.
    NoShdr,
}

impl Variant {
    /// Gives the suffix of the variant in fixture names.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Stripped => "stripped",
            Self::NoEh => "noeh",
            Self::NoShdr => "noshdr",
        }
    }
}

/// One program of the fixture corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    /// The program name. It is the first part of each fixture name.
    pub name: &'static str,
    /// The tier.
    pub tier: Tier,
    /// The C sources in `fixtures/src`, in link order.
    pub sources: &'static [&'static str],
    /// Extra compiler flags of the program.
    pub cflags: &'static [&'static str],
    /// Extra link flags of the program.
    pub ldflags: &'static [&'static str],
    /// The builds of the program.
    pub builds: &'static [Build],
    /// The variants: a build ID and a variant kind.
    pub variants: &'static [(&'static str, Variant)],
}

/// The three builds of every program.
const BASE: &[Build] = &[GCC_O0, GCC_O2, CLANG_O2];

/// The builds of a leaf subject.
const LEAF: &[Build] = &[GCC_O0, GCC_O2, CLANG_O2, GCC_O2NV, CLANG_O2NV];

/// The no-`.eh_frame` variants of the two `-O2` builds.
const NOEH: &[(&str, Variant)] = &[("gcc-O2", Variant::NoEh), ("clang-O2", Variant::NoEh)];

const fn t1(name: &'static str, sources: &'static [&'static str]) -> Program {
    Program {
        name,
        tier: Tier::T1,
        sources,
        cflags: &[],
        ldflags: &[],
        builds: BASE,
        variants: &[],
    }
}

/// The programs of the corpus, in name order.
pub const PROGRAMS: &[Program] = &[
    t1("adversarial_names", &["adversarial_names.c"]),
    t1("canary", &["canary.c"]),
    Program {
        variants: NOEH,
        ..t1("cold_split", &["cold_split.c"])
    },
    Program {
        variants: NOEH,
        ..t1("crackme", &["crackme.c"])
    },
    Program {
        variants: NOEH,
        ..t1("func_ptrs", &["func_ptrs.c"])
    },
    Program {
        builds: &[GCC_O0, GCC_O2, CLANG_O2, GCC_O2_NOPIE, GCC_O2_NOPLT],
        variants: &[("gcc-O2", Variant::NoEh), ("gcc-O2", Variant::NoShdr)],
        ..t1("hello", &["hello.c"])
    },
    t1("hostile_strings", &["hostile_strings.c"]),
    Program {
        tier: Tier::T2,
        builds: &[GCC_O2, CLANG_O2],
        variants: NOEH,
        ..t1("large", &["large.c"])
    },
    Program {
        builds: LEAF,
        variants: NOEH,
        ..t1("loops", &["loops.c"])
    },
    t1("noreturn_wrappers", &["noreturn_wrappers.c"]),
    Program {
        variants: NOEH,
        ..t1("recursion", &["recursion.c"])
    },
    Program {
        builds: &[GCC_O0, GCC_O2, CLANG_O2, GCC_O2_NOPLT],
        variants: &[("gcc-O2", Variant::NoShdr)],
        ..t1("socket_client", &["socket_client.c"])
    },
    t1("strings", &["strings.c"]),
    t1("struct_access", &["struct_access.c"]),
    Program {
        builds: &[
            GCC_O0,
            GCC_O2,
            CLANG_O2,
            GCC_O2NV,
            CLANG_O2NV,
            GCC_O2_AT400000,
            GCC_O2_AT800000,
        ],
        variants: NOEH,
        ..t1("switch", &["switch.c"])
    },
    Program {
        cflags: &["-fno-stack-protector"],
        ldflags: &["-nostdlib", "-static"],
        ..t1("syscall_only", &["syscall_only.c"])
    },
    t1("two_helpers", &["two_helpers.c", "two_helpers_right.c"]),
    t1("varargs", &["varargs.c"]),
    Program {
        builds: LEAF,
        ..t1("xor_decode", &["xor_decode.c"])
    },
];

/// The leaf driver source in `fixtures/src`.
pub const LEAF_DRIVER: &str = "leaf_driver.c";

/// The shared header of the fixture sources in `fixtures/src`.
pub const HEADER: &str = "fixture.h";

/// One fixture binary of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixture {
    /// The program.
    pub program: &'static Program,
    /// The build.
    pub build: &'static Build,
    /// The variant, or `None` for the build output itself.
    pub variant: Option<Variant>,
}

impl Fixture {
    /// Gives the fixture name, for example `hello.gcc-O2.stripped`.
    #[must_use]
    pub fn name(&self) -> String {
        let base = build_name(self.program, self.build);
        match self.variant {
            Some(v) => format!("{base}.{}", v.suffix()),
            None => base,
        }
    }

    /// Gives the name of the build that holds the code and the truth of this fixture.
    #[must_use]
    pub fn truth_name(&self) -> String {
        build_name(self.program, self.build)
    }

    /// Tells if the fixture binary keeps its `.symtab`.
    #[must_use]
    pub const fn has_symtab(&self) -> bool {
        self.variant.is_none()
    }
}

/// Gives the name of the build output of a program, for example `hello.gcc-O2`.
#[must_use]
pub fn build_name(program: &Program, build: &Build) -> String {
    format!("{}.{}", program.name, build.id)
}

/// Gives every fixture of the table, in name order.
#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    for program in PROGRAMS {
        for build in program.builds {
            out.push(Fixture {
                program,
                build,
                variant: None,
            });
            if build.twin {
                out.push(Fixture {
                    program,
                    build,
                    variant: Some(Variant::Stripped),
                });
            }
            for (id, variant) in program.variants {
                if *id == build.id {
                    out.push(Fixture {
                        program,
                        build,
                        variant: Some(*variant),
                    });
                }
            }
        }
    }
    out.sort_by_key(Fixture::name);
    out
}

/// Gives the program of a name.
#[must_use]
pub fn program(name: &str) -> Option<&'static Program> {
    PROGRAMS.iter().find(|p| p.name == name)
}
