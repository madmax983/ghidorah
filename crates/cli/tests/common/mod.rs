//! Shared helpers of the cli tests: in-memory streams, runs of the command line in the test
//! process and runs of the `ghidorah` binary.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

pub mod registry;
pub mod transcript;

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghidorah_cli::{Backend, Env, RunConfig, Streams, main_with};
use ghidorah_json::{Limits, Value};

/// The fixed time of the test runs: 2026-10-17T00:00:00Z.
pub const FIXED_TIME: u64 = 1_792_195_200_000;

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &Limits::DEFAULT)
        .unwrap_or_else(|e| panic!("the test JSON parses: {e}: {text}"))
}

/// Gives a new empty directory for one test under the cargo temp directory.
pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Gives the environment of an in-process run: a fixed time and the temp directory `name`.
pub fn env(name: &str) -> Env {
    let mut env = Env::new(tmp(name));
    env.run = RunConfig {
        fixed_time: Some(FIXED_TIME),
        eval_mode: false,
    };
    env
}

/// A shared byte buffer that implements `Write`.
#[derive(Debug, Clone, Default)]
pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    /// Gives the bytes as text.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("the buffer lock").clone())
            .expect("the output is UTF-8")
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The result of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The exit code.
    pub code: u8,
    /// The stdout text.
    pub stdout: String,
    /// The stderr text.
    pub stderr: String,
}

impl Output {
    /// Gives the stdout lines.
    pub fn lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }
}

/// Gives in-memory streams with `stdin` and the buffers of stdout and stderr.
pub fn streams(stdin: &[u8]) -> (Streams, SharedBuf, SharedBuf) {
    let out = SharedBuf::default();
    let err = SharedBuf::default();
    let streams = Streams {
        stdin: Box::new(io::Cursor::new(stdin.to_vec())),
        stdout: Box::new(out.clone()),
        stderr: Box::new(err.clone()),
    };
    (streams, out, err)
}

/// Runs the command line `args` in this process with the backend `B` in `env`.
pub fn run_in<B: Backend>(args: &[&str], stdin: &str, env: &Env) -> Output {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let (streams, out, err) = streams(stdin.as_bytes());
    let code = main_with::<B>(&args, env, streams);
    Output {
        code,
        stdout: out.text(),
        stderr: err.text(),
    }
}

/// Runs the command line `args` in this process with the backend `B` and a new environment.
pub fn run<B: Backend>(args: &[&str], stdin: &str) -> Output {
    run_in::<B>(args, stdin, &env("run"))
}

/// Gives a command of the `ghidorah` binary with `args`, a fixed time and piped streams.
pub fn binary(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ghidorah"));
    command
        .args(args)
        .env("GHIDORAH_FIXED_TIME", FIXED_TIME.to_string())
        .env_remove("GHIDORAH_EVAL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Waits for `child` for at most `secs` seconds. It kills the child after the limit.
pub fn wait_for(child: &mut Child, secs: u64) -> ExitStatus {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().expect("the child status") {
            return status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("the child runs longer than {secs} s");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Runs the binary with `args` and `stdin`, then gives its output.
pub fn run_binary(args: &[&str], stdin: &str) -> Output {
    let mut child = binary(args).spawn().expect("the binary starts");
    let mut input = child.stdin.take().expect("the stdin pipe");
    let text = stdin.to_owned();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(text.as_bytes());
    });
    let mut stdout = child.stdout.take().expect("the stdout pipe");
    let mut stderr = child.stderr.take().expect("the stderr pipe");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("the stdout text");
    let status = wait_for(&mut child, 20);
    writer.join().expect("the stdin writer");
    let err = reader.join().expect("the stderr reader");
    Output {
        code: status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .unwrap_or(255),
        stdout: out,
        stderr: err,
    }
}
