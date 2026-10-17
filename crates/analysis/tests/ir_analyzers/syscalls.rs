//! Syscall sites, names, `sys:` IDs and argument values (design Section 7.11, AC-089).

use ghidorah_analysis::callargs::ArgValue;
use ghidorah_analysis::syscalls::{self, Site};
use ghidorah_base::Fuel;
use ghidorah_json::Value;

use crate::support::{cached, fid, fixtures, hex, list, truth, truth_funcs};

/// Gives the truth form of an argument value: `int:0x1`, `str:0x402010:text` and so on.
fn arg_text(v: &ArgValue) -> String {
    match v {
        ArgValue::Int(n) => format!("int:{n:#x}"),
        ArgValue::Str { addr, text } => format!("str:{addr:#x}:{text}"),
        ArgValue::Func(id) => format!("func:{}", id.0),
        ArgValue::Addr(a) => format!("addr:{a:#x}"),
        ArgValue::Unknown => "unknown".to_owned(),
    }
}

/// Gives the same form of a truth argument.
fn truth_arg(v: &Value) -> String {
    let kind = v.get("kind").and_then(Value::as_str).expect("a kind");
    match kind {
        "int" => format!("int:{:#x}", hex(v.get("v").expect("a value"))),
        "str" => format!(
            "str:{:#x}:{}",
            hex(v.get("addr").expect("an address")),
            v.get("text").and_then(Value::as_str).expect("a text")
        ),
        other => other.to_owned(),
    }
}

#[test]
fn ac_089_syscalls() {
    let mut checked = 0;
    for f in fixtures() {
        if f.program != "syscall_only" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        let sites = syscalls::sites(p, &mut Fuel::unlimited());
        let want = list(&t, "syscalls");
        assert_eq!(sites.len(), want.len(), "{}: {sites:?}", f.path);
        for (got, w) in sites.iter().zip(want) {
            let name = w.get("name").and_then(Value::as_str).expect("a name");
            let func = w.get("func").and_then(Value::as_str).expect("a function");
            assert_eq!(got.site, hex(w.get("site").expect("a site")), "{}", f.path);
            assert_eq!(got.func, fid(funcs[func]), "{}", f.path);
            assert_eq!(got.nr, w.get("nr").and_then(Value::as_u64), "{}", f.path);
            assert_eq!(got.name, Some(name), "{}", f.path);
            assert_eq!(
                got.id().map(|id| id.to_string()),
                Some(format!("sys:{name}"))
            );
            let args: Vec<String> = got.args.iter().map(arg_text).collect();
            let want_args: Vec<String> = list(w, "args").iter().map(truth_arg).collect();
            assert_eq!(args, want_args, "{} {name}", f.path);
            checked += 1;
        }
    }
    assert!(checked >= 24, "six builds of four sites: {checked}");
}

#[test]
fn syscall_site_ids() {
    let site = |nr: Option<u64>, name: Option<&'static str>| Site {
        site: 0x10,
        func: fid(0x10),
        nr,
        name,
        args: Vec::new(),
    };
    assert_eq!(
        site(Some(1), Some("write")).note().as_deref(),
        Some("sys:write")
    );
    assert_eq!(site(Some(999), None).note().as_deref(), Some("sys:999"));
    assert_eq!(site(None, None).id(), None);
    assert_eq!(site(Some(1 << 20), None).id(), None, "no u16 number");
    // A program with no syscall site.
    let p = cached("fixtures/bin/hello.gcc-O2");
    assert!(syscalls::sites(p, &mut Fuel::unlimited()).is_empty());
}
