use ghidorah_base::Address;
use ghidorah_json::{Limits, Value, parse, write};

use super::ExtMap;

fn ext(n: u64) -> Address {
    Address::external(n)
}

fn json(text: &str) -> Value {
    parse(text, &Limits::DEFAULT).unwrap()
}

#[test]
fn remap_changes_only_exact_old_addresses() {
    // Two imports swap their addresses, and a third keeps its address.
    let map = ExtMap::from_pairs([(ext(1), ext(2)), (ext(2), ext(1)), (ext(3), ext(3))]);
    assert!(!map.is_empty());
    let value = json(
        r#"{"a":"ext:0x1","b":["ext:0x2",{"c":"ext:0x1"}],"d":"ext:0x3","e":"ext:0x10",
        "f":"x ext:0x1","g":"0x1","h":1,"ext:0x1":null}"#,
    );
    let want = json(
        r#"{"a":"ext:0x2","b":["ext:0x1",{"c":"ext:0x2"}],"d":"ext:0x3","e":"ext:0x10",
        "f":"x ext:0x1","g":"0x1","h":1,"ext:0x1":null}"#,
    );
    assert_eq!(write(&map.remap(value)), write(&want));
    let same = ExtMap::from_pairs([(ext(1), ext(1))]);
    assert!(same.is_empty());
    assert_eq!(same, ExtMap::default());
}
