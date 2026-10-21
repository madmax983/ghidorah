//! AC-133: every example of every shipped tool, with `limit` at its cap, stays within 60,000
//! characters on a synthetic ELF file with 5,000 or 50,000 functions.
//!
//! The examples name places of the demo binary. [`Synthetic`] holds the places of the
//! synthetic file, and [`Synthetic::value`] moves each demo place to one of them:
//!
//! | Demo place | Synthetic place |
//! |---|---|
//! | `main`, `fn:0x1000` | `func_00000`: the helper, which calls `puts` and `strlen` |
//! | `check_password` | `func_00480`, the function of `0x11e0` |
//! | `0x10a1` (the call of `puts`), `0x1060` (the stub of `puts`) | the call of `puts` in the helper, the stub of `puts` |
//! | `0x1090` and `0x1094` (instructions of `main` with no symbol) | instructions of the helper with no symbol |
//! | `0x10c7` (a call), `0x1014` (an indirect call), `0x1170` and `0x1178` (an indirect jump and its target) | the same kinds of instruction in the helper |
//! | `0x11d0` (no function) | an `int3` byte after the helper |
//! | other `0x1000..0x1300` | the function `func_NNNNN` with `NNNNN` = the offset |
//! | `0x2000..0x2040` | the same offset in `.rodata`, which holds the strings of the demo |
//! | `0x3db0` | `.data`, which holds two pointers |
//!
//! A `binary_load` example loads the synthetic file. The run skips the destructive examples:
//! the `delete` and `remove_ref` actions of `func_edit` and the `history_undo` example that
//! undoes an edit.

use ghidorah_json::{Object, Value};
use ghidorah_testkit::elf::{ElfBuilder, FixupKind, ImportKind, Loc, Section, Symbol};
use ghidorah_tools::registry::shipped;
use ghidorah_tools::spec::{ArgKind, ToolSpec};
use ghidorah_tools::{Session, budget};

use crate::support::{DEMO_ID, call, call_value, chars, code, json, load_bytes_args, text_at};

/// The largest result of a call in characters (AC-133).
const BUDGET: usize = 60_000;

/// The size of the helper function `func_00000`, with its two `int3` bytes.
const HELPER: u64 = 48;

/// The bytes of the helper. Each `0` run is a fixup of the builder.
const HELPER_CODE: [u8; 48] = [
    0x48, 0x8d, 0x3d, 0, 0, 0, 0, // 0: lea rdi, [rip+usage]
    0xe8, 0, 0, 0, 0, // 7: call puts@plt
    0x48, 0x8d, 0x3d, 0, 0, 0, 0, // 12: lea rdi, [rip+granted]
    0xe8, 0, 0, 0, 0, // 19: call puts@plt
    0x48, 0x8d, 0x3d, 0, 0, 0, 0, // 24: lea rdi, [rip+denied]
    0xe8, 0, 0, 0, 0, // 31: call strlen@plt
    0xff, 0xd0, // 36: call rax
    0xff, 0xe0, // 38: jmp rax
    0xe8, 0, 0, 0, 0,    // 40: call func_00001
    0xc3, // 45: ret
    0xcc, 0xcc, // 46: int3, no function
];

/// The strings of the demo `.rodata` at their demo offsets.
const STRINGS: [(usize, &[u8]); 3] = [
    (0x04, b"usage: crackme <password>\0"),
    (0x1e, b"Access granted\0"),
    (0x2d, b"Access denied\0"),
];

/// The demo sites of `main` and the stub of `puts`, with their offset in the helper. `None`
/// names the stub of `puts`.
const SITES: [(u64, Option<u64>); 9] = [
    (0x1060, None),
    (0x1090, Some(12)),
    (0x1094, Some(19)),
    (0x10a1, Some(7)),
    (0x10c7, Some(40)),
    (0x1014, Some(36)),
    (0x1170, Some(38)),
    (0x1178, Some(40)),
    (0x11d0, Some(46)),
];

/// A synthetic ELF file and its places.
struct Synthetic {
    /// The file bytes.
    bytes: Vec<u8>,
    /// The address of each function `func_NNNNN` by `NNNNN`.
    funcs: Vec<u64>,
    /// The address of `.rodata`.
    rodata: u64,
    /// The address of `.data`.
    data: u64,
    /// The address of the stub of `puts`.
    puts: u64,
}

/// Makes a synthetic ELF file with `count` functions. `func_00000` is the helper, and each
/// other function is one `ret`.
fn synthetic(count: u32) -> Synthetic {
    let rest = usize::try_from(count - 1).expect("a size");
    let mut text = HELPER_CODE.to_vec();
    text.extend(std::iter::repeat_n(0xc3, rest));
    let mut rodata = vec![0u8; 0x40];
    rodata[..4].copy_from_slice(&[1, 0, 2, 0]);
    for (at, s) in STRINGS {
        rodata[at..at + s.len()].copy_from_slice(s);
    }
    let rodata_at = |off: u64| Loc::section(".rodata", off);
    let code = Section::code(".text", &text)
        .fixup(3, FixupKind::Rel32, rodata_at(0x04))
        .fixup(8, FixupKind::Rel32, Loc::Plt("puts".into()))
        .fixup(15, FixupKind::Rel32, rodata_at(0x1e))
        .fixup(20, FixupKind::Rel32, Loc::Plt("puts".into()))
        .fixup(27, FixupKind::Rel32, rodata_at(0x2d))
        .fixup(32, FixupKind::Rel32, Loc::Plt("strlen".into()))
        .fixup(41, FixupKind::Rel32, Loc::symbol("func_00001"));
    let data = Section::data(".data", &[0; 16])
        .fixup(0, FixupKind::Abs64, Loc::symbol("func_00000"))
        .fixup(8, FixupKind::Abs64, Loc::symbol("func_00001"));
    let mut b = ElfBuilder::exec()
        .section(code)
        .section(Section::rodata(".rodata", &rodata))
        .section(data)
        .import("puts", ImportKind::Plt)
        .import("strlen", ImportKind::Plt)
        .symbol(Symbol::func("func_00000", Loc::section(".text", 0), 46));
    for i in 1..count {
        let name = format!("func_{i:05}");
        let at = Loc::section(".text", HELPER + u64::from(i - 1));
        b = b.symbol(Symbol::func(&name, at, 1));
    }
    let (bytes, layout) = b.entry(Loc::symbol("func_00000")).build_with_layout();
    let addr = |name: &str| layout.section(name).expect("a built section").addr;
    let text_at = addr(".text");
    let mut funcs = vec![text_at];
    funcs.extend((1..u64::from(count)).map(|i| text_at + HELPER + i - 1));
    Synthetic {
        bytes,
        funcs,
        rodata: addr(".rodata"),
        data: addr(".data"),
        puts: layout.plt["puts"],
    }
}

impl Synthetic {
    /// Gives the synthetic place of the demo address `a`, or `None` for an address that the
    /// table of the module docs does not name.
    fn place(&self, a: u64) -> Option<u64> {
        if let Some((_, off)) = SITES.iter().find(|(demo, _)| *demo == a) {
            return Some(off.map_or(self.puts, |o| self.funcs[0] + o));
        }
        match a {
            0x1000..0x1300 => self.funcs.get(usize::try_from(a - 0x1000).ok()?).copied(),
            0x2000..0x2040 => Some(self.rodata + (a - 0x2000)),
            0x3db0 => Some(self.data),
            _ => None,
        }
    }

    /// Gives the synthetic text of the demo address text `text`, or `None`.
    fn addr_text(&self, text: &str) -> Option<String> {
        let a = text.strip_prefix("0x")?;
        let a = u64::from_str_radix(a, 16).ok()?;
        self.place(a).map(|p| format!("{p:#x}"))
    }

    /// Gives the synthetic text of one demo text: a name, an address or an ID.
    fn text(&self, text: &str) -> String {
        let names = [("main", "func_00000"), ("check_password", "func_00480")];
        for (demo, synthetic) in names {
            if text == demo {
                return synthetic.to_owned();
            }
            if let Some(rest) = text.strip_prefix(demo).filter(|r| r.starts_with('+')) {
                return format!("{synthetic}{rest}");
            }
        }
        if let Some(p) = self.addr_text(text) {
            return p;
        }
        for prefix in ["fn:", "str:", "var:"] {
            if let Some(rest) = text.strip_prefix(prefix) {
                let (head, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
                if let Some(p) = self.addr_text(head) {
                    return format!("{prefix}{p}{tail}");
                }
            }
        }
        if let Some(rest) = text.strip_prefix("ref:")
            && let Some((from, rest)) = rest.split_once('>')
            && let Some((to, kind)) = rest.split_once(':')
            && let (Some(from), Some(to)) = (self.addr_text(from), self.addr_text(to))
        {
            return format!("ref:{from}>{to}:{kind}");
        }
        text.to_owned()
    }

    /// Gives `value` with each demo text moved to its synthetic place.
    fn value(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::from(self.text(s)),
            Value::Array(list) => Value::Array(list.iter().map(|v| self.value(v)).collect()),
            Value::Object(o) => {
                let mut out = Object::new();
                for (k, v) in o.iter() {
                    out.push(k, self.value(v));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

/// Gives the cap of `limit` for `tool`: the largest value of its own `limit` argument, else
/// the page cap of a list tool.
fn limit_cap(tool: &ToolSpec<Session>) -> Option<u64> {
    let own = tool.args.iter().find(|a| a.name == "limit").map(|a| a.kind);
    match own {
        Some(ArgKind::Int { max, .. }) => u64::try_from(max).ok(),
        _ => tool.list.map(|_| u64::from(budget::MAX_LIMIT)),
    }
}

/// Sets `limit` of the arguments `args` of `tool` to its cap. A `batch_run` step keeps its
/// limit: the list argument that reads the step sets the cap of a source step.
fn capped(tool: &ToolSpec<Session>, args: &Value) -> Value {
    let mut object = args.as_object().cloned().unwrap_or_default();
    if let Some(cap) = limit_cap(tool) {
        let _ = object.insert("limit", Value::from(cap));
    }
    Value::Object(object)
}

/// Tells if the example `args` of `tool` destroys data: a destructive action, or a destructive
/// tool with no actions outside a dry run.
fn destructive(tool: &ToolSpec<Session>, args: &Value) -> bool {
    if let Some(action) = args.get("action").and_then(Value::as_str) {
        return tool
            .actions
            .iter()
            .any(|a| a.value == action && a.destructive);
    }
    tool.annotations.destructive && args.get("dry_run") != Some(&Value::Bool(true))
}

/// Gives the synthetic arguments of a `binary_load` example: the file of the session, the
/// helper as the raw entry and the ID of the file.
fn load_args(s: &Synthetic, args: &Value, id: &str) -> Value {
    let mut out = Object::new();
    if args.get("builtin").is_some() {
        out.push("path", Value::from("input.elf"));
    }
    for (k, v) in args.as_object().into_iter().flat_map(Object::iter) {
        match k {
            "builtin" => {}
            "path" => out.push(k, Value::from("input.elf")),
            "entry" => out.push(k, Value::from(format!("{:#x}", s.funcs[0]))),
            "binary_id" if v.as_str() == Some(DEMO_ID) => out.push(k, Value::from(id)),
            _ => out.push(k, v.clone()),
        }
    }
    Value::Object(out)
}

/// Checks one envelope: a success within the budget. A `batch_run` result also needs a
/// success in each step.
fn check(tool: &str, args: &Value, envelope: &Value) {
    let size = chars(envelope);
    assert!(size <= BUDGET, "{tool} {args}: {size} characters");
    assert_ne!(code(envelope), "OUTPUT_BUDGET_EXCEEDED", "{tool} {args}");
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "{tool} {args}: {envelope}"
    );
    if tool == "batch_run" {
        let steps = envelope
            .pointer("/data/steps")
            .and_then(Value::as_array)
            .unwrap_or_default();
        assert!(!steps.is_empty(), "{args}: {envelope}");
        for step in steps {
            assert_eq!(step.get("ok"), Some(&Value::Bool(true)), "{args}: {step}");
        }
    }
}

/// Runs every example of the shipped tools with `limit` at its cap on a synthetic file with
/// `count` functions. The `binary_load` examples run last, so that the other examples read
/// the first load.
fn budget_check(count: u32) {
    let s = synthetic(count);
    let name = format!("ac_133_{count}");
    let first = json(r#"{"path":"input.elf"}"#);
    let (mut session, load) = load_bytes_args(&name, &s.bytes, first);
    assert_eq!(text_at(&load, "/data/analysis/state"), "complete", "{load}");
    let id = text_at(&load, "/data/binary_id");
    let mut runs = 0;
    let mut loads = Vec::new();
    for tool in shipped().tools() {
        for example in tool.examples {
            let demo = json(example.args);
            if destructive(tool, &demo) {
                continue;
            }
            if tool.name == "binary_load" {
                loads.push(load_args(&s, &demo, &id));
                continue;
            }
            let args = capped(tool, &s.value(&demo));
            let envelope = call_value(&mut session, tool.name, args.clone());
            check(tool.name, &args, &envelope);
            runs += 1;
        }
    }
    for args in loads {
        // A raw load of the file needs its own session: the session holds the ELF load.
        let envelope = if args.get("file_format").and_then(Value::as_str) == Some("raw") {
            load_bytes_args(&format!("{name}_raw"), &s.bytes, args.clone()).1
        } else {
            call_value(&mut session, "binary_load", args.clone())
        };
        check("binary_load", &args, &envelope);
        runs += 1;
    }
    assert!(runs >= 85, "{runs} examples");
    let big = call(
        &mut session,
        "func_list",
        r#"{"limit":1000,"max_chars":60000}"#,
    );
    assert!(chars(&big) <= BUDGET);
    assert_eq!(big.pointer("/page/truncated"), Some(&Value::Bool(true)));
}

#[test]
fn ac_133_output_budget() {
    budget_check(5_000);
}

#[test]
#[ignore = "tier2"]
fn ac_133_output_budget_large() {
    budget_check(50_000);
}
