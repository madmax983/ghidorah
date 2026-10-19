use super::eval;

#[test]
fn key_functions_of_the_fixtures_evaluate() {
    let text = "(uint64_t)(uint32_t)(param_1 + (param_1 << 1) + 0x5a)";
    assert_eq!(eval(text, "param_1", 0), Ok(0x5a));
    assert_eq!(eval(text, "param_1", 2), Ok(0x60));
    assert_eq!(eval("0x5a", "i", 9), Ok(0x5a));
}

#[test]
fn precedence_follows_c() {
    assert_eq!(eval("1 + 2 * 3", "x", 0), Ok(7));
    assert_eq!(eval("1 << 2 + 1", "x", 0), Ok(8));
    assert_eq!(eval("6 & 3 ^ 1", "x", 0), Ok(3));
    assert_eq!(eval("~0 & 0xff", "x", 0), Ok(0xff));
    assert_eq!(eval("(uint8_t)(x * 3 + 0x5a)", "x", 100), Ok(0x86));
    assert_eq!(eval("-1 & 0xf", "x", 0), Ok(0xf));
}

#[test]
fn bad_expressions_give_errors() {
    assert!(eval("y + 1", "x", 0).is_err());
    assert!(eval("1 +", "x", 0).is_err());
    assert!(eval("(1", "x", 0).is_err());
    assert!(eval("1 / 0", "x", 0).is_err());
    assert!(eval("1 2", "x", 0).is_err());
    assert!(eval("$", "x", 0).is_err());
    let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
    assert!(eval(&deep, "x", 0).is_err());
}
