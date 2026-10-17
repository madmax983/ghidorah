//! AC-235: line windows page through the full decompile of every T2 function, and no page
//! exceeds its budget.

use ghidorah_base::{Fuel, FuncId};
use ghidorah_decomp::Opts;
use ghidorah_json::Value;
use ghidorah_tools::Session;

use crate::support::{call_value, chars, data, fixture, json, program, t2_fixtures, text_at};

/// The budget of the pages: the default `max_chars` of `func_get`.
const MAX_CHARS: u64 = 24_000;

/// Pages through the decompile of `func` with windows of `count` lines. Gives the text of
/// the pages and the number of pages.
fn pages(s: &mut Session, func: FuncId, count: u64) -> (String, usize) {
    let mut text = String::new();
    let mut cursor: Option<String> = None;
    let mut next_line = 1;
    for page in 1..=10_000 {
        let mut args = Value::object([
            ("target", Value::from(func.to_string())),
            ("include", json(r#"["decomp"]"#)),
            ("max_chars", Value::from(MAX_CHARS)),
            (
                "decomp_opts",
                Value::object([("lines", Value::object([("count", Value::from(count))]))]),
            ),
        ]);
        if let (Some(c), Value::Object(o)) = (&cursor, &mut args) {
            o.push(
                "cursors",
                Value::object([("decomp", Value::from(c.as_str()))]),
            );
        }
        let envelope = call_value(s, "func_get", args);
        let size = chars(&envelope);
        assert!(
            u64::try_from(size).expect("small") <= MAX_CHARS,
            "{func} page {page}: {size} characters"
        );
        let section = data(&envelope).get("decomp").expect("a decomp section");
        assert_eq!(
            section.get("line_start").and_then(Value::as_u64),
            Some(next_line),
            "{func} page {page}"
        );
        let got = section
            .get("line_count")
            .and_then(Value::as_u64)
            .expect("a count");
        assert!(got <= count, "{func} page {page}: {got} lines");
        next_line += got;
        text.push_str(&text_at(section, "/text"));
        cursor = section
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            let total = section.get("total_lines").and_then(Value::as_u64);
            assert_eq!(total, Some(next_line - 1), "{func}");
            return (text, page);
        }
        assert!(got > 0, "{func} page {page} is empty");
    }
    panic!("the pages of {func} do not end");
}

#[test]
fn ac_235_window_paging() {
    let names = t2_fixtures();
    assert!(names.len() >= 4, "{names:?}");
    let checked: Vec<(usize, usize)> = std::thread::scope(|scope| {
        let handles: Vec<_> = names
            .iter()
            .map(|name| {
                scope.spawn(move || {
                    let (mut s, id) = fixture(name);
                    let funcs: Vec<FuncId> = program(&s, id)
                        .funcs()
                        .iter()
                        .filter(|f| !f.func.flags.thunk)
                        .map(|f| f.id())
                        .collect();
                    let mut multi = 0;
                    for func in &funcs {
                        let want = ghidorah_decomp::render(
                            program(&s, id),
                            *func,
                            &Opts::default(),
                            &ghidorah_x86::lift::Names,
                            &mut Fuel::new(50_000_000),
                        )
                        .map(|o| o.text())
                        .unwrap_or_default();
                        let (got, n) = pages(&mut s, *func, 40);
                        assert_eq!(got, want, "{name} {func}");
                        if n > 1 {
                            multi += 1;
                        }
                    }
                    (funcs.len(), multi)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let funcs: usize = checked.iter().map(|c| c.0).sum();
    let multi: usize = checked.iter().map(|c| c.1).sum();
    assert!(funcs > 200, "only {funcs} functions");
    assert!(multi > 20, "only {multi} functions need more than one page");
}
