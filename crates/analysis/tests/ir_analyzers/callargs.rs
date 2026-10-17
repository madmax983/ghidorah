//! Call-site argument values (design Section 7.11).

use ghidorah_analysis::callargs::{self, ArgValue};
use ghidorah_base::Fuel;
use ghidorah_db::FlowKind;
use ghidorah_ir::LocalValue;

use crate::support::{cached, fid, fir_of, named};

/// Gives the sites of the function at `entry` with the flow kind `flow`.
fn sites(p: &ghidorah_db::Program, entry: u64, flow: FlowKind) -> Vec<u64> {
    fir_of(p, entry)
        .units
        .iter()
        .filter(|(_, u)| u.flow == flow)
        .map(|(at, _)| *at)
        .collect()
}

#[test]
fn call_args_of_hello() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let finish = named(p, "finish");
    let [site] = sites(p, finish, FlowKind::Call)[..] else {
        panic!("finish has one call");
    };
    let args = callargs::at(p, site, &mut Fuel::unlimited()).expect("the args");
    let [ArgValue::Str { text, .. }] = &args[..] else {
        panic!("puts takes one string: {args:?}");
    };
    assert_eq!(text, "Goodbye.");
    let greet = named(p, "greet");
    let [site] = sites(p, greet, FlowKind::Jmp)[..] else {
        panic!("greet has one tail call");
    };
    let args = callargs::at(p, site, &mut Fuel::unlimited()).expect("the args");
    assert_eq!(args.len(), 2, "__printf_chk names two parameters: {args:?}");
    assert_eq!(args[0], ArgValue::Int(2));
    assert!(
        matches!(&args[1], ArgValue::Str { text, .. } if text == "Hello, %s!\n"),
        "{args:?}"
    );
    assert!(callargs::at(p, 0x3, &mut Fuel::unlimited()).is_err());
}

#[test]
fn classify_kinds() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let main = named(p, "main");
    assert_eq!(
        callargs::classify(p, LocalValue::Const(5)),
        ArgValue::Int(5)
    );
    assert_eq!(
        callargs::classify(p, LocalValue::Addr(main)),
        ArgValue::Func(fid(main))
    );
    assert_eq!(
        callargs::classify(p, LocalValue::Unknown),
        ArgValue::Unknown
    );
    // An address in the middle of a function is a plain address.
    assert_eq!(
        callargs::classify(p, LocalValue::Addr(main + 1)),
        ArgValue::Addr(main + 1)
    );
    for (v, kind) in [
        (ArgValue::Int(1), "int"),
        (ArgValue::Addr(1), "addr"),
        (ArgValue::Func(fid(1)), "func"),
        (
            ArgValue::Str {
                addr: 1,
                text: String::new(),
            },
            "str",
        ),
        (ArgValue::Unknown, "unknown"),
    ] {
        assert_eq!(v.kind(), kind);
    }
}
