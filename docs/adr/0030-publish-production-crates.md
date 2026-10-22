# ADR-0030: Publish the production crates to crates.io

Status: Accepted
Date: 2026-10-22
Verified by: AC-001e

## Context

- The owner wants `cargo install ghidorah` to work. Today a user must clone the repository and build the binary.
- crates.io takes a package only when each of its dependencies is on crates.io too. The `ghidorah` binary needs the 12 production library crates of design Section 2.1.
- ADR-0001 set `publish = false` on every package. It gave no reason for that rule. The zero-dependency rule controls what comes in, and `publish` controls only what goes out.
- Since Rust 1.90, `cargo publish --workspace` publishes the selected packages in dependency order. It skips each package with `publish = false`.
- `cargo publish` packs only the files of the package directory. The root `LICENSE` and `NOTICE` do not go with a package. Apache-2.0 sections 4(a) and 4(d) need both with each copy.
- `ghidorah-types` embeds two Ghidra data files under Apache-2.0. Their attribution is in `NOTICE`.
- crates.io keeps a version for all time. A yank only stops new lock files from selecting it.

## Decision

- The 13 production packages of design Section 2.1 set `publish = true`. The dev packages `ghidorah-eval`, `ghidorah-testkit`, `ghidorah-oracle` and `xtask` keep `publish = false`.
- The root `[workspace.package]` keeps `publish = false`. A new package stays private until its row in `PACKAGES` is `Kind::Prod`.
- The root `[workspace.dependencies]` gives each production crate a path and the workspace version. A production package takes each normal dependency on a production crate with `.workspace = true`.
- A dev dependency keeps a path only. Cargo removes it from the packed manifest.
- Each production package holds byte copies of the root `LICENSE` and `NOTICE`.
- The production packages take `repository`, `readme`, `keywords` and `categories` from the workspace. The clippy lint `cargo_common_metadata` then passes.
- AC-001e checks all of these rules.
- The release command is `cargo publish --workspace --config net.offline=false`. The owner runs it with a crates.io token. CI does not publish.

## Alternatives

- Keep `publish = false`. Users then run `cargo install --git`. Rejected: the owner wants a crates.io install.
- Merge the production crates into one package. Rejected: it breaks the crate graph of design Section 2.2 and the per-crate gates.
- Symbolic links to the root `LICENSE` and `NOTICE`. Rejected: a Windows checkout without symbolic links gets text files that hold only the link path.
- Set `license-file` to the root `LICENSE`. Rejected: Cargo copies that file, but `NOTICE` has no such field.
- A `version` on each path dependency in each manifest. Rejected: a version change then edits about 35 lines in 13 files. The workspace table holds 12 lines.

## Consequences

- crates.io keeps the 13 crate names for this project. Each library crate is a public API. A breaking change needs a new minor version while the version is `0.x`.
- A change of `LICENSE` or `NOTICE` needs the same change in 13 copies. AC-001e finds a copy that differs.
- A version change edits `[workspace.package]` and the 12 lines of `[workspace.dependencies]`. Cargo stops the build when the two do not agree.
- crates.io limits the rate of new crate names. The first publish can stop partway. Run the same command again to continue.
- The offline rule of ADR-0001 stays. The publish command opens the network for that command only.
