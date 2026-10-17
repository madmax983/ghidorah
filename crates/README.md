# Crates

Each directory here holds one package of design Section 2.1.
The root `Cargo.toml` finds them with the member glob `crates/*`.
A new crate needs no edit of the root manifest.

The work package that owns a crate creates its skeleton first.
Each package sets `publish = false`, `license = "Apache-2.0"` and `[lints] workspace = true`.
