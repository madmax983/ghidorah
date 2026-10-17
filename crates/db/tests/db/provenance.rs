//! AC-121: the write rule of design Section 3.6 and the golden rank constants.

use std::fmt::Write as _;
use std::path::PathBuf;

use ghidorah_db::{Source, Verdict, write_rule};
use ghidorah_kernel::may_overwrite;
use ghidorah_testkit::golden::{self, Header};

/// The rule of Section 3.6 in its own words, written apart from the crate.
fn spec(old: Source, new: Source, force: bool) -> Verdict {
    let agent_over_imported = old == Source::Imported && new == Source::Agent;
    if new.rank() >= old.rank() {
        Verdict::Allowed
    } else if agent_over_imported && force {
        Verdict::Forced
    } else {
        Verdict::Blocked {
            force_applies: agent_over_imported,
        }
    }
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Allowed => "allowed",
        Verdict::Forced => "forced",
        Verdict::Blocked {
            force_applies: true,
        } => "blocked force_applies",
        Verdict::Blocked {
            force_applies: false,
        } => "blocked",
    }
}

#[test]
fn ac_121_provenance_lattice() {
    let golden_ranks = [
        (Source::Default, 1, "default"),
        (Source::Analysis, 2, "analysis"),
        (Source::Agent, 3, "agent"),
        (Source::Imported, 4, "imported"),
        (Source::User, 5, "user"),
    ];
    for (source, rank, name) in golden_ranks {
        assert_eq!(source.rank(), rank, "{name}");
        assert_eq!(Source::from_rank(rank), Some(source));
        assert_eq!(source.name(), name);
        assert_eq!(Source::parse(name), Some(source));
        assert_eq!(source.to_string(), name);
    }
    assert_eq!(Source::ALL.map(Source::rank), [1, 2, 3, 4, 5]);
    assert_eq!(Source::from_rank(0), None);
    assert_eq!(Source::from_rank(6), None);
    assert_eq!(Source::parse("Agent"), None);

    let mut body =
        String::from("# The ranks of design Section 3.6. Persisted numbers never change.\n");
    for s in Source::ALL {
        let _ = writeln!(body, "rank {} {}", s.name(), s.rank());
    }
    body.push_str("# old new force -> verdict\n");
    let mut count = 0;
    for old in Source::ALL {
        for new in Source::ALL {
            for force in [false, true] {
                let got = write_rule(old, new, force);
                assert_eq!(got, spec(old, new, force), "{old} {new} {force}");
                assert_eq!(
                    got.is_allowed(),
                    may_overwrite(old.rank(), new.rank(), force),
                    "the verdict agrees with kernel K7"
                );
                let mode = if force { "force" } else { "plain" };
                let _ = writeln!(body, "{old} {new} {mode} -> {}", verdict_text(got));
                count += 1;
            }
        }
    }
    assert_eq!(count, 5 * 5 * 2);
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/db/provenance.txt");
    golden::assert_text(&path, &Header::new("db_provenance", "1"), &body);
}
