//! Named sets: the `in` filter (AC-164a) and set algebra against a `BTreeSet` model (AC-164b).

use std::collections::BTreeSet;

use ghidorah_base::SetName;
use ghidorah_db::SetMembers;
use ghidorah_json::Value;
use ghidorah_testkit::model::{Settings, model_check};
use ghidorah_testkit::pbt::Gen;
use ghidorah_tools::Session;

use crate::support::{STRIPPED, call, call_value, code, fixture, ids, items, program, str_of};

/// Writes the set `name` with `members` and the operation `op`. Gives the envelope.
fn write_set(session: &mut Session, name: &str, members: Value, op: &str) -> Value {
    let args = Value::object([
        ("kind", Value::from("set")),
        (
            "set",
            Value::object([
                ("name", Value::from(name)),
                ("members", members),
                ("op", Value::from(op)),
            ]),
        ),
    ]);
    call_value(session, "note_write", args)
}

/// Gives the items of `func_list` with the optional set filter `set`.
fn funcs(session: &mut Session, set: Option<&str>) -> Vec<Value> {
    let mut args = ghidorah_json::Object::new();
    args.push("limit", Value::from(1000));
    if let Some(set) = set {
        args.push("in", Value::from(set));
    }
    items(&call_value(session, "func_list", Value::Object(args)))
}

#[test]
fn ac_164a_set_filter() {
    let (mut session, _) = fixture(STRIPPED);
    let picked = ["fn:0x11e0", "fn:0x1080", "fn:0x1110"];
    let members = Value::Array(picked.iter().map(|s| Value::from(*s)).collect());
    let made = write_set(&mut session, "picked", members, "replace");
    assert_eq!(code(&made), "", "{made}");
    let all = funcs(&mut session, None);
    let explicit: Vec<Value> = all
        .iter()
        .filter(|i| picked.contains(&str_of(i, "id").as_str()))
        .cloned()
        .collect();
    assert_eq!(explicit.len(), 3);
    assert_eq!(funcs(&mut session, Some("set:picked")), explicit);

    let searched = call(&mut session, "search", r#"{"kind":"name","limit":1000}"#);
    let explicit: Vec<String> = ids(&searched)
        .into_iter()
        .filter(|id| picked.contains(&id.as_str()))
        .collect();
    let filtered = call(
        &mut session,
        "search",
        r#"{"kind":"name","limit":1000,"in":"set:picked"}"#,
    );
    assert_eq!(ids(&filtered), explicit, "{filtered}");

    let ranges = ghidorah_json::parse(
        r#"[{"start":"0x1080","size":"0x10"},{"start":"0x1100","end":"0x1150"}]"#,
        &ghidorah_json::Limits::DEFAULT,
    )
    .expect("JSON");
    let made = write_set(&mut session, "region", ranges, "replace");
    assert_eq!(crate::support::int_at(&made, "/data/ranges"), 2, "{made}");
    let in_ranges: Vec<Value> = all
        .iter()
        .filter(|i| {
            let a = ghidorah_base::hex::parse_u64(&str_of(i, "addr")).unwrap_or(0);
            (0x1080..0x1090).contains(&a) || (0x1100..0x1150).contains(&a)
        })
        .cloned()
        .collect();
    assert_eq!(in_ranges.len(), 3, "main, 0x1110 and 0x1140");
    assert_eq!(funcs(&mut session, Some("set:region")), in_ranges);
}

/// One step of the set model.
#[derive(Debug, Clone)]
enum Step {
    /// Applies `op` to the set `target` with the operand `members` or the set `from`.
    Op {
        target: usize,
        op: &'static str,
        members: Vec<u64>,
        from: Option<usize>,
    },
}

const NAMES: [&str; 2] = ["a", "b"];
const OPS: [&str; 4] = ["replace", "union", "intersect", "subtract"];

/// Gives the ID text of the model member `m`.
fn member_id(m: u64) -> String {
    format!("fn:0x{:x}", 0x1000 + m)
}

/// Gives the members of the set `name` as model values, or `None` when the set is absent.
fn observed_ids(session: &Session, name: &str) -> Option<BTreeSet<u64>> {
    let binary = session.binaries().next()?;
    let set = SetName::new(name).ok()?;
    let note = binary.program.notes().set(&set)?;
    match note.set.as_ref().map(|s| &s.members) {
        Some(SetMembers::Addrs(ranges)) if ranges.ranges().is_empty() => Some(BTreeSet::new()),
        Some(SetMembers::Ids(list)) => Some(
            list.iter()
                .filter_map(|t| t.strip_prefix("fn:0x"))
                .filter_map(|h| u64::from_str_radix(h, 16).ok())
                .map(|v| v - 0x1000)
                .collect(),
        ),
        _ => None,
    }
}

/// Gives the members of the address set `name` as single addresses.
fn observed_addrs(session: &Session, name: &str) -> Option<BTreeSet<u64>> {
    let binary = session.binaries().next()?;
    let set = SetName::new(name).ok()?;
    let note = binary.program.notes().set(&set)?;
    match note.set.as_ref().map(|s| &s.members) {
        Some(SetMembers::Ids(list)) if list.is_empty() => Some(BTreeSet::new()),
        Some(SetMembers::Addrs(ranges)) => Some(
            ranges
                .ranges()
                .iter()
                .flat_map(|r| r.first..=r.last)
                .map(|a| a - 0x1000)
                .collect(),
        ),
        _ => None,
    }
}

/// Draws one step over a domain of `domain` values.
fn draw(g: &mut Gen, domain: u64) -> Step {
    let target = usize::from(g.bool());
    let op = OPS[usize::try_from(g.draw(4)).unwrap_or(0)];
    let from = if g.draw(4) == 0 {
        Some(1 - target)
    } else {
        None
    };
    let members = g.vec(6, |g| g.draw(domain));
    Step::Op {
        target,
        op,
        members,
        from,
    }
}

/// Applies a step to the model. Gives the observation of both sets.
fn model_step(model: &mut [Option<BTreeSet<u64>>; 2], step: &Step) -> [Option<BTreeSet<u64>>; 2] {
    let Step::Op {
        target,
        op,
        members,
        from,
    } = step;
    let operand: BTreeSet<u64> = match from {
        Some(other) => match &model[*other] {
            Some(set) => set.clone(),
            None => return model.clone(),
        },
        None => members.iter().copied().collect(),
    };
    let old = model[*target].clone().unwrap_or_default();
    let new = match *op {
        "replace" => operand,
        "union" => old.union(&operand).copied().collect(),
        "intersect" => old.intersection(&operand).copied().collect(),
        _ => old.difference(&operand).copied().collect(),
    };
    model[*target] = Some(new);
    model.clone()
}

/// Applies a step through `note_write`. `addrs` selects address members.
fn tool_step(session: &mut Session, step: &Step, addrs: bool) -> [Option<BTreeSet<u64>>; 2] {
    let Step::Op {
        target,
        op,
        members,
        from,
    } = step;
    let mut set = ghidorah_json::Object::new();
    set.push("name", Value::from(NAMES[*target]));
    match from {
        Some(other) => set.push("from_set", Value::from(format!("set:{}", NAMES[*other]))),
        None => {
            let list = members
                .iter()
                .map(|m| {
                    if addrs {
                        Value::object([
                            ("start", Value::from(format!("0x{:x}", 0x1000 + m))),
                            ("size", Value::from(1)),
                        ])
                    } else {
                        Value::from(member_id(*m))
                    }
                })
                .collect();
            set.push("members", Value::Array(list));
        }
    }
    set.push("op", Value::from(*op));
    let args = Value::object([("kind", Value::from("set")), ("set", Value::Object(set))]);
    let envelope = call_value(session, "note_write", args);
    let ok = envelope.get("ok") == Some(&Value::Bool(true));
    let missing_from = code(&envelope) == "NOT_FOUND" && from.is_some();
    assert!(ok || missing_from, "{envelope}");
    let observe = if addrs { observed_addrs } else { observed_ids };
    [observe(session, NAMES[0]), observe(session, NAMES[1])]
}

#[test]
fn ac_164b_set_algebra_model() {
    for addrs in [false, true] {
        model_check(
            if addrs {
                "ac_164b_addr_sets"
            } else {
                "ac_164b_id_sets"
            },
            Settings {
                cases: 24,
                max_steps: 12,
            },
            || {
                let (session, _) = fixture(STRIPPED);
                (session, [None, None])
            },
            |g| draw(g, if addrs { 24 } else { 10 }),
            |session, step| tool_step(session, step, addrs),
            model_step,
        );
    }
}

#[test]
fn set_operand_errors() {
    let (mut session, id) = fixture(STRIPPED);
    let made = write_set(
        &mut session,
        "ids",
        ghidorah_json::parse(r#"["fn:0x1080"]"#, &ghidorah_json::Limits::DEFAULT).expect("JSON"),
        "replace",
    );
    assert_eq!(code(&made), "", "{made}");
    let cases = [
        r#"{"kind":"set","set":{"name":"bad","members":["fn:0x1080",{"start":"0x1000","size":"0x10"}]}}"#,
        r#"{"kind":"set","set":{"name":"bad","members":[true]}}"#,
        r#"{"kind":"set","set":{"name":"bad","members":[{"start":"0x1000","size":"0x0"}]}}"#,
        r#"{"kind":"set","set":{"name":"bad","members":["fn:0x1080"],"from_set":"set:ids"}}"#,
        r#"{"kind":"set","set":{"name":"ids","members":[{"start":"0x1000","size":"0x10"}],"op":"union"}}"#,
        r#"{"kind":"set","set":{"name":"bad name"}}"#,
    ];
    for args in cases {
        let envelope = call(&mut session, "note_write", args);
        assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{args}: {envelope}");
    }
    let missing = call(
        &mut session,
        "note_write",
        r#"{"kind":"set","set":{"name":"c","from_set":"set:nope"}}"#,
    );
    assert_eq!(code(&missing), "NOT_FOUND", "{missing}");
    let union = call(
        &mut session,
        "note_write",
        r#"{"kind":"set","set":{"name":"ids","members":["fn:0x11e0"],"op":"union"}}"#,
    );
    assert_eq!(
        crate::support::text_at(&union, "/data/note"),
        "note:1",
        "a set op keeps its note"
    );
    assert_eq!(crate::support::int_at(&union, "/data/members"), 2);
    let notes = program(&session, id).notes().len();
    assert_eq!(notes, 1);
}
