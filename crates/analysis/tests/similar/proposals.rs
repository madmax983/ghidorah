//! The four rules of a name proposal (design Section 7.13).

use ghidorah_analysis::similar::{MARGIN, MIN_PROPOSAL_SCORE, Named, propose};
use ghidorah_db::Source;

const fn named(name: &str, source: Source, score: u32) -> Named<'_> {
    Named {
        name,
        source,
        score,
    }
}

#[test]
fn proposal_needs_default_query_name() {
    let ranked = [
        named("check_password", Source::Imported, 990),
        named("FUN_1200", Source::Default, 600),
    ];
    let cases = [
        (Source::Default, true),
        (Source::Analysis, true),
        (Source::Agent, false),
        (Source::Imported, false),
        (Source::User, false),
    ];
    for (query, want) in cases {
        assert_eq!(
            propose(query, &ranked),
            want,
            "rule 1 with a {query:?} query"
        );
    }
    let cases = [
        (Source::Default, false),
        (Source::Analysis, false),
        (Source::Agent, true),
        (Source::Imported, true),
        (Source::User, true),
    ];
    for (source, want) in cases {
        let ranked = [named("check_password", source, 990)];
        assert_eq!(
            propose(Source::Default, &ranked),
            want,
            "rule 2 with a {source:?} match"
        );
    }
    assert_eq!(MIN_PROPOSAL_SCORE, 800);
    let low = [named("check_password", Source::Imported, 799)];
    assert!(!propose(Source::Default, &low), "rule 3 below 800");
    let edge = [named("check_password", Source::Imported, 800)];
    assert!(propose(Source::Default, &edge), "rule 3 at 800");
    assert!(!propose(Source::Default, &[]), "no match gives no proposal");
}

#[test]
fn proposal_margin_uses_other_name() {
    assert_eq!(MARGIN, 50);
    let twins = [
        named("init", Source::Imported, 950),
        named("init", Source::Imported, 950),
        named("other", Source::Imported, 900),
    ];
    assert!(
        propose(Source::Default, &twins),
        "two twins with the same name do not block a proposal"
    );
    let close = [
        named("init", Source::Imported, 950),
        named("FUN_2000", Source::Default, 901),
    ];
    assert!(!propose(Source::Default, &close), "a margin of 49");
    let edge = [
        named("init", Source::Imported, 950),
        named("FUN_2000", Source::Default, 900),
    ];
    assert!(propose(Source::Default, &edge), "a margin of 50");
    let later = [
        named("init", Source::Imported, 990),
        named("init", Source::Agent, 960),
        named("FUN_3000", Source::Default, 950),
    ];
    assert!(
        !propose(Source::Default, &later),
        "the best other name counts, not rank 2"
    );
    let alone = [named("init", Source::Imported, 800)];
    assert!(
        propose(Source::Default, &alone),
        "no other name gives a margin over 0"
    );
}
