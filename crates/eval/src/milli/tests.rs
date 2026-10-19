use super::Milli;

#[test]
fn parse_reads_two_and_three_decimals() {
    assert_eq!(Milli::parse("0.70"), Some(Milli(700)));
    assert_eq!(Milli::parse("1.00"), Some(Milli(1000)));
    assert_eq!(Milli::parse("0.739"), Some(Milli(739)));
    assert_eq!(Milli::parse("3"), Some(Milli(3000)));
    assert_eq!(Milli::parse("0.1234"), None);
    assert_eq!(Milli::parse("-1"), None);
    assert_eq!(Milli::parse(".5"), None);
}

#[test]
fn ratio_rounds_down_and_empty_is_one() {
    assert_eq!(Milli::ratio(2, 3), Milli(666));
    assert_eq!(Milli::ratio(0, 0), Milli::ONE);
    assert_eq!(Milli::ratio(34, 46).to_string(), "0.739");
    assert_eq!(Milli(1000).to_json().to_string(), "1.000");
}
