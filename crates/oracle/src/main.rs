//! The `ghidorah-oracle` binary: the child process of `xtask oracle semantics`.
//!
//! | Command | Output |
//! |---|---|
//! | `ghidorah-oracle list` | one line `<file>\t<form name>` for each form |
//! | `ghidorah-oracle form <name>` | the header line of the form, then one line for each vector |
//!
//! The exit code is 0 on success and 2 for a usage error or an unknown form.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the binary writes vector lines and its errors"
)]

use std::process::ExitCode;

#[cfg(target_arch = "x86_64")]
fn run(args: &[String]) -> Result<String, String> {
    use ghidorah_oracle::native;
    match args {
        [cmd] if cmd == "list" => Ok(native::forms().fold(String::new(), |mut out, f| {
            out.push_str(f.file);
            out.push('\t');
            out.push_str(f.name);
            out.push('\n');
            out
        })),
        [cmd, name] if cmd == "form" => {
            let form = native::find(name).ok_or_else(|| format!("no form `{name}`"))?;
            let mut out = form.header_line();
            out.push('\n');
            for v in form.vectors() {
                out.push_str(&form.vector_line(&v));
                out.push('\n');
            }
            Ok(out)
        }
        _ => Err("usage: ghidorah-oracle <list|form <name>>".to_owned()),
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn run(_args: &[String]) -> Result<String, String> {
    Err("the native oracle needs an x86-64 host".to_owned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ghidorah-oracle: {e}");
            ExitCode::from(2)
        }
    }
}
