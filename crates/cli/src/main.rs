//! The `ghidorah` binary: the CLI and the MCP stdio server (design Section 10.14).
//!
//! The binary reads the process environment once, then runs [`ghidorah_cli::main_with`] with
//! the shipped backend. stdout carries only data. The panic hook writes to stderr only.

use std::io::Write;
use std::process::ExitCode;

use ghidorah_cli::{Env, Shipped, Streams, main_with};

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(std::io::stderr(), "ghidorah: panic: {info}");
    }));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    let env = match Env::from_lookup(cwd, &|name| std::env::var(name).ok()) {
        Ok(env) => env,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "ghidorah: {error}");
            return ExitCode::from(2);
        }
    };
    ExitCode::from(main_with::<Shipped>(&args, &env, Streams::process()))
}
