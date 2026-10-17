//! Parameter recovery and the varargs prologue (design Section 7.10, AC-090a).

use ghidorah_analysis::cc::{self, ParamSource, Params};
use ghidorah_base::Fuel;
use ghidorah_json::Value;
use ghidorah_types::cc::SYSV_X86_64;

use crate::support::{cached, fid, fir_of, fixtures, list, named, truth, truth_funcs};

/// The prototypes of the calling-convention fixture: name, count and varargs.
fn prototypes(t: &Value) -> Vec<(String, u32, bool)> {
    let protos = t
        .get("facts")
        .and_then(|f| f.get("prototypes"))
        .and_then(Value::as_array)
        .expect("prototypes");
    protos
        .iter()
        .map(|p| {
            let name = p.get("name").and_then(Value::as_str).expect("a name");
            let count = p.get("params").and_then(Value::as_u64).expect("a count");
            let varargs = p.get("varargs").and_then(Value::as_bool).expect("a flag");
            (
                name.to_owned(),
                u32::try_from(count).expect("a small count"),
                varargs,
            )
        })
        .collect()
}

#[test]
fn ac_090a_param_counts() {
    let (mut total, mut right) = (0, 0);
    let mut misses = Vec::new();
    for f in fixtures() {
        if f.program != "varargs" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for (name, count, _) in prototypes(&t) {
            let (params, _) =
                cc::params(p, fid(funcs[&name]), &mut Fuel::unlimited()).expect("the params");
            total += 1;
            if params.count() == count {
                right += 1;
            } else {
                misses.push(format!("{} {name}: {params:?}", f.path));
            }
        }
    }
    assert!(total >= 60, "six builds of 13 functions: {total}");
    assert!(right * 100 >= total * 95, "{right} of {total}: {misses:?}");
}

#[test]
fn varargs_prologues() {
    for f in fixtures() {
        if f.program != "varargs" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for (name, count, varargs) in prototypes(&t) {
            let ir = fir_of(p, funcs[&name]);
            let got = cc::recover(&ir, &SYSV_X86_64);
            assert_eq!(got.varargs, varargs, "{} {name}", f.path);
            if varargs {
                assert_eq!(got.count(), count, "{} {name}: named params", f.path);
            }
        }
    }
}

#[test]
fn params_from_prototypes() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let puts = named(p, "puts@plt");
    let (params, source) = cc::params(p, fid(puts), &mut Fuel::unlimited()).expect("params");
    assert_eq!(source, ParamSource::Prototype);
    assert_eq!(params.count(), 1);
    let finish = named(p, "finish");
    let (params, source) = cc::params(p, fid(finish), &mut Fuel::unlimited()).expect("params");
    assert_eq!(source, ParamSource::Recovered);
    assert_eq!(
        params,
        Params {
            int: 1,
            ..Params::default()
        }
    );
    assert!(cc::params(p, fid(0x3), &mut Fuel::unlimited()).is_err());
    assert_eq!(cc::conv_of(p).name, "sysv");
    let t = truth("fixtures/truth/hello.gcc-O2.json");
    assert!(list(&t, "functions").len() > 5);
}
