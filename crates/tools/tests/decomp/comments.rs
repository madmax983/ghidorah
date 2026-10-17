//! AC-237: the decompile text prints PLATE, PRE, POST and EOL comments, each with a line map
//! row.

use ghidorah_base::Address;
use ghidorah_db::{CommentKind, Edit};
use ghidorah_json::Value;

use crate::support::{commit, decomp, entry_of, fixture, program, text_at, text_of};

#[test]
fn ac_237_comments() {
    let (mut s, id) = fixture("hello.gcc-O0");
    let entry = entry_of(program(&s, id), "finish");
    let target = format!("{entry:#x}");
    let before = decomp(&mut s, &target, "{}");
    let rows = before
        .get("line_map")
        .and_then(Value::as_array)
        .expect("rows");
    let starts: Vec<u64> = rows
        .iter()
        .filter_map(|r| ghidorah_base::hex::parse_u64(&text_at(r, "/start")))
        .collect();
    assert!(starts.len() >= 3, "{before}");
    let (pre, post, eol) = (
        starts[0],
        starts[starts.len() / 2],
        starts[starts.len() - 1],
    );
    let notes = [
        (entry, CommentKind::Plate, "plate text"),
        (pre, CommentKind::Pre, "pre text"),
        (post, CommentKind::Post, "post text"),
        (eol, CommentKind::Eol, "eol text"),
    ];
    for (addr, kind, text) in notes {
        commit(&mut s, id, |tx| Edit::SetComment {
            addr: Address::ram(addr),
            kind,
            text: Some(tx.fact(text.to_owned())),
        });
    }
    let after = decomp(&mut s, &target, "{}");
    let text = text_of(&after);
    let lines: Vec<&str> = text.lines().collect();
    let rows = after
        .get("line_map")
        .and_then(Value::as_array)
        .expect("rows");
    for (_, kind, note) in notes {
        let at = lines
            .iter()
            .position(|l| l.contains(note))
            .unwrap_or_else(|| panic!("no {note} in\n{text}"));
        let line = u64::try_from(at + 1).expect("small");
        let row = rows
            .iter()
            .find(|r| r.get("line").and_then(Value::as_u64) == Some(line))
            .unwrap_or_else(|| panic!("no row for line {line} of {note}"));
        assert_eq!(text_at(row, "/comment"), kind.name(), "{row}");
    }
    let plate = lines
        .iter()
        .position(|l| l.contains("plate text"))
        .expect("plate");
    let head = lines
        .iter()
        .position(|l| l.contains("finish("))
        .expect("the head");
    assert!(
        plate < head,
        "the PLATE comment comes before the function:\n{text}"
    );
    let eol_line = lines.iter().find(|l| l.contains("eol text")).expect("eol");
    assert!(
        eol_line.trim_start().len() > "// eol text".len(),
        "the EOL comment ends a line with code: {eol_line}"
    );
    let pre_at = lines
        .iter()
        .position(|l| l.contains("pre text"))
        .expect("pre");
    let post_at = lines
        .iter()
        .position(|l| l.contains("post text"))
        .expect("post");
    assert!(pre_at < post_at, "{text}");
}
