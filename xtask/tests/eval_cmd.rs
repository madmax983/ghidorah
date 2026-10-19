//! `xtask eval`: the argument rules and the replay compare (WP-26).
#![allow(clippy::expect_used, reason = "the helper fails the calling test")]

use std::path::PathBuf;

use xtask::Error;
use xtask::eval::{self, diffs};
use xtask::json::{self, Value};

fn root() -> PathBuf {
    xtask::workspace::root()
}

fn parse(text: &str) -> Value {
    json::parse(text).expect("the test JSON parses")
}

#[test]
fn eval_rejects_bad_arguments() {
    let bad = [
        vec!["--colour"],
        vec!["--bless"],
        vec!["--reason", "why"],
        vec!["replay"],
        vec!["--reason"],
    ];
    for args in bad {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        let result = eval::run(&root(), &args);
        assert!(
            matches!(result, Err(Error::Usage(_))),
            "{args:?}: {result:?}"
        );
    }
}

#[test]
fn replay_compares_replies_by_id() {
    let request = |id: u64| parse(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#));
    let reply = |id: u64, x: u64| {
        parse(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"x":{x}}}}}"#
        ))
    };
    let records = vec![
        (1, request(1), reply(1, 7)),
        (2, request(2), reply(2, 8)),
        (3, request(3), reply(3, 9)),
    ];
    let replies = vec![reply(2, 8), reply(1, 7), reply(3, 0)];
    assert_eq!(diffs(&records, &replies), [3]);
    assert_eq!(diffs(&records, &[]), [1, 2, 3]);
}

#[test]
fn replay_of_a_missing_record_is_an_io_error() {
    let result = eval::run(
        &root(),
        &["replay".to_owned(), "no/such/record.jsonl".to_owned()],
    );
    assert!(matches!(result, Err(Error::Io { .. })), "{result:?}");
}
