//! The generator of the T2 program `fixtures/src/large.c` (`xtask fixtures gen-large`).
//!
//! The generator uses `SplitMix64` with the fixed seed [`SEED`], so its output never changes.
//! It writes [`FUNCTIONS`] functions `fNNNN(u64 a, u64 b)`. A function calls only functions
//! with a lower number, so the call graph has no cycle. The function kinds are arithmetic,
//! loops, dense switches (jump tables), cold paths, tail calls, calls through a function
//! pointer table and callers of two functions.

use std::fmt::Write as _;

use ghidorah_testkit::rng::{Rng, SplitMix64, below};

/// The seed of the generator.
pub const SEED: u64 = 0x6768_6964_6f72_6168;

/// The number of generated functions.
pub const FUNCTIONS: usize = 640;

/// The source path of the generated program, relative to the workspace root.
pub const SOURCE_PATH: &str = "fixtures/src/large.c";

/// The binary operators of the generated expressions. All operands are `u64`.
const OPS: &[&str] = &["+", "-", "*", "^", "|", "&"];

/// The function kinds, with their weights out of 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Arith,
    Loop,
    Switch,
    Cold,
    Tail,
    Table,
    Caller,
}

const KINDS: &[(Kind, u64)] = &[
    (Kind::Arith, 20),
    (Kind::Loop, 15),
    (Kind::Switch, 15),
    (Kind::Cold, 10),
    (Kind::Tail, 10),
    (Kind::Table, 10),
    (Kind::Caller, 20),
];

/// The state of one generator run.
struct Gen {
    rng: SplitMix64,
    out: String,
}

impl Gen {
    fn pick(&mut self, n: usize) -> usize {
        let bound = u64::try_from(n).unwrap_or(u64::MAX);
        usize::try_from(below(&mut self.rng, bound)).unwrap_or(0)
    }

    fn op(&mut self) -> &'static str {
        OPS.get(self.pick(OPS.len())).copied().unwrap_or("+")
    }

    /// A constant above 255, so it is a `const` feature (design Section 7.13).
    fn konst(&mut self) -> String {
        let v = 0x100 + below(&mut self.rng, 0xffff_ff00);
        format!("0x{v:x}u")
    }

    fn kind(&mut self, index: usize) -> Kind {
        let roll = below(&mut self.rng, 100);
        let mut acc = 0;
        let mut kind = Kind::Arith;
        for (k, weight) in KINDS {
            acc += weight;
            if roll < acc {
                kind = *k;
                break;
            }
        }
        let needs_callee = matches!(kind, Kind::Tail | Kind::Table | Kind::Caller);
        if index < 8 && needs_callee {
            Kind::Arith
        } else {
            kind
        }
    }

    /// A function with a lower number than `index`. The caller makes sure that `index > 0`.
    fn callee(&mut self, index: usize) -> String {
        format!("f{:04}", self.pick(index))
    }

    /// The expression of a default path: a call when a callee exists, else arithmetic.
    fn fallback(&mut self, index: usize) -> String {
        if index == 0 {
            let (op, k) = (self.op(), self.konst());
            format!("b {op} {k}")
        } else {
            let (callee, op, k) = (self.callee(index), self.op(), self.konst());
            format!("{callee}(b {op} {k}, a)")
        }
    }

    fn arith(&mut self) -> String {
        let (op1, k1, op2, op3, k2, op4, k3) = (
            self.op(),
            self.konst(),
            self.op(),
            self.op(),
            self.konst(),
            self.op(),
            self.konst(),
        );
        format!("    return ((a {op1} {k1}) {op2} (b {op3} {k2})) {op4} {k3};\n")
    }

    fn looped(&mut self) -> String {
        let masks = [7u64, 15, 31, 63];
        let mask = masks.get(self.pick(masks.len())).copied().unwrap_or(7);
        let (k1, op1, op2, op3, k2) = (self.konst(), self.op(), self.op(), self.op(), self.konst());
        format!(
            "    u64 s = {k1};\n    for (u64 i = 0; i < (a & {mask}u); i++) {{\n        s = s {op1} (i {op2} b);\n    }}\n    return s {op3} {k2};\n"
        )
    }

    fn switch(&mut self, index: usize) -> String {
        let cases = 5 + self.pick(8);
        let hole = self.pick(cases + 4);
        let mut body = String::from("    switch (a & 15u) {\n");
        for case in 0..cases {
            if case == hole {
                continue;
            }
            let (op, k) = (self.op(), self.konst());
            let _ = writeln!(body, "    case {case}:\n        return b {op} {k};");
        }
        let fallback = self.fallback(index);
        let _ = write!(body, "    default:\n        return {fallback};\n    }}\n");
        body
    }

    fn cold(&mut self, index: usize) -> String {
        let (k1, k2, k3) = (self.konst(), self.konst(), self.konst());
        let fallback = self.fallback(index);
        format!(
            "    if (__builtin_expect(a == {k1}, 0)) {{\n        lg_fail({k2}, b);\n        return {k3};\n    }}\n    return {fallback};\n"
        )
    }

    fn tail(&mut self, index: usize) -> String {
        let (callee, op1, k1, op2, k2) = (
            self.callee(index),
            self.op(),
            self.konst(),
            self.op(),
            self.konst(),
        );
        format!("    return {callee}(b {op1} {k1}, a {op2} {k2});\n")
    }

    fn caller(&mut self, index: usize) -> String {
        let (c1, k1, c2, op1, op2) = (
            self.callee(index),
            self.konst(),
            self.callee(index),
            self.op(),
            self.op(),
        );
        format!(
            "    u64 x = {c1}(a, {k1});\n    u64 y = {c2}(x {op1} b, a);\n    return x {op2} y;\n"
        )
    }

    fn function(&mut self, index: usize) {
        let kind = self.kind(index);
        if kind == Kind::Table {
            let entries: Vec<String> = (0..4).map(|_| self.callee(index)).collect();
            let _ = writeln!(
                self.out,
                "static fn2 const t{index:04}[4] = {{{}}};\n",
                entries.join(", ")
            );
        }
        let body = match kind {
            Kind::Arith => self.arith(),
            Kind::Loop => self.looped(),
            Kind::Switch => self.switch(index),
            Kind::Cold => self.cold(index),
            Kind::Tail => self.tail(index),
            Kind::Table => {
                let (op, k) = (self.op(), self.konst());
                format!("    return t{index:04}[a & 3u](b, a {op} {k});\n")
            }
            Kind::Caller => self.caller(index),
        };
        let _ = write!(
            self.out,
            "NI u64 f{index:04}(u64 a, u64 b) {{\n{body}}}\n\n"
        );
    }
}

const PROLOGUE: &str = "/* large: the generated T2 program (Apache-2.0, first-party code).
 * Do not edit this file. `cargo xtask fixtures gen-large` writes it from a fixed seed.
 */
#include <stdint.h>
#include <stdio.h>

#define NI __attribute__((noinline))

typedef uint64_t u64;
typedef u64 (*fn2)(u64, u64);

__attribute__((cold, noinline)) void lg_fail(u64 code, u64 v) {
    fprintf(stderr, \"fail %llu %llu\\n\", (unsigned long long)code, (unsigned long long)v);
}

";

/// Gives the text of `fixtures/src/large.c`.
#[must_use]
pub fn generate() -> String {
    let mut g = Gen {
        rng: SplitMix64::new(SEED),
        out: String::from(PROLOGUE),
    };
    // One draw first, so a seed change shows in the first function.
    let _ = g.rng.next_u64();
    for index in 0..FUNCTIONS {
        g.function(index);
    }
    g.out.push_str("int main(int argc, char **argv) {\n    (void)argv;\n    u64 a = (u64)argc;\n    u64 s = 0;\n");
    for index in FUNCTIONS.saturating_sub(16)..FUNCTIONS {
        let _ = writeln!(g.out, "    s ^= f{index:04}(a, s);");
    }
    g.out
        .push_str("    printf(\"%llu\\n\", (unsigned long long)s);\n    return 0;\n}\n");
    g.out
}
