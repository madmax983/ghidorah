//! The `ghidorah` command line and the MCP stdio server (design Sections 10.13 and 10.14).
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`argv`] | The command-line parser and the usage text | Section 10.14 |
//! | [`backend`] | The [`Backend`] trait and the session [`Options`] | Section 10.14 |
//! | [`bare`] | [`bare::Bare`], a backend with no session state | Section 10.14 |
//! | [`shipped`] | [`Shipped`], the backend of the `ghidorah` binary | Section 10.14 |
//! | [`config`] | [`RunConfig`], [`Env`] and [`SystemClock`] | Section 10.11, ADR-0012 |
//! | [`exit`] | The exit codes 0, 1 and 2 | Section 10.14 |
//! | [`out`] | Writes to stdout with the broken-pipe rule | Section 10.14 |
//! | [`select`] | The `--select` output | Section 10.14, AC-185 |
//! | [`call`] | `ghidorah call` and `ghidorah jsonl` | Section 10.14 |
//! | [`catalog`] | `ghidorah tools` and the `tools/list` result | Sections 10.3, 10.14 |
//! | [`doctor`] | `ghidorah doctor` | Section 10.14 |
//! | [`record`] | The call recorder and its replay | Section 12.7, AC-201 |
//! | [`mcp`] | The MCP stdio server: reader, worker and writer threads | Sections 2.4, 10.13, ADR-0003, ADR-0006 |
//!
//! [`main_with`] runs one command line. The binary calls it with [`Shipped`].
//! Tests call it with a test backend and in-memory [`Streams`].
//!
//! stdout carries only data or protocol lines. Logs and usage errors go to stderr.
//! The command line prints no color, so it agrees with `NO_COLOR`. It never prompts.

pub mod argv;
pub mod backend;
pub mod bare;
pub mod call;
pub mod catalog;
pub mod config;
pub mod doctor;
pub mod exit;
pub mod mcp;
pub mod out;
pub mod record;
pub mod select;
pub mod shipped;

use std::io::{self, BufRead, Write};
use std::thread;

pub use argv::{Command, UsageError};
pub use backend::{Backend, OpenError, Options, Source};
pub use config::{Env, EnvError, RunConfig, SystemClock};
pub use exit::Exit;
pub use shipped::Shipped;

/// The stack size of the worker thread: 64 MiB (design Section 2.4).
pub const WORKER_STACK: usize = 64 * 1024 * 1024;

/// The version of the `ghidorah` package.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The standard streams of one run.
pub struct Streams {
    /// The input stream.
    pub stdin: Box<dyn BufRead + Send>,
    /// The data stream. It carries only data or protocol lines.
    pub stdout: Box<dyn Write + Send>,
    /// The log stream.
    pub stderr: Box<dyn Write + Send>,
}

impl Streams {
    /// Gives the streams of the process.
    #[must_use]
    pub fn process() -> Self {
        Self {
            stdin: Box::new(io::BufReader::with_capacity(1 << 16, io::stdin())),
            stdout: Box::new(io::stdout()),
            stderr: Box::new(io::stderr()),
        }
    }
}

/// Runs `f` on a thread with a stack of [`WORKER_STACK`] bytes and gives its exit code.
///
/// A panic or a failed thread start gives [`Exit::Usage`].
pub fn on_worker<F>(f: F) -> Exit
where
    F: FnOnce() -> Exit + Send + 'static,
{
    thread::Builder::new()
        .name("ghidorah-worker".to_owned())
        .stack_size(WORKER_STACK)
        .spawn(f)
        .map_or(Exit::Usage, |handle| handle.join().unwrap_or(Exit::Usage))
}

/// Runs the command line `args` (without the program name) with the backend `B`.
///
/// Gives the exit code of Section 10.14: 0 for a success, 1 for a tool error and 2 for a
/// usage or protocol error.
#[must_use]
pub fn main_with<B: Backend>(args: &[String], env: &Env, mut streams: Streams) -> u8 {
    let command = match argv::parse(args) {
        Ok(command) => command,
        Err(error) => {
            out::log(&mut streams.stderr, &error.to_string());
            return Exit::Usage.code();
        }
    };
    let env = env.clone();
    let exit = match command {
        Command::Help => print(&mut streams, argv::USAGE.trim_end()),
        Command::Version => print(&mut streams, &format!("ghidorah {VERSION}")),
        Command::Mcp(args) => {
            let options = Options::with_flags(&env, &args.session, MCP_SESSION);
            let serve = mcp::ServeOptions {
                content: args.content,
                record: args.record.map(|path| env.cwd.join(path)),
            };
            mcp::serve::<B>(options, &serve, streams)
        }
        Command::Call(args) => on_worker(move || call::call::<B>(&args, &env, &mut streams)),
        Command::Jsonl(flags) => on_worker(move || call::jsonl::<B>(&flags, &env, &mut streams)),
        Command::Tools(args) => on_worker(move || catalog::tools::<B>(args, &env, &mut streams)),
        Command::Doctor(args) => on_worker(move || doctor::doctor::<B>(&args, &env, &mut streams)),
    };
    exit.code()
}

/// The default session label of `ghidorah mcp`.
pub const MCP_SESSION: &str = "mcp-1";

/// Prints `text` and one line end on stdout.
fn print(streams: &mut Streams, text: &str) -> Exit {
    match out::line(&mut streams.stdout, text) {
        Ok(()) => Exit::Ok,
        Err(stop) => stop.exit(),
    }
}
