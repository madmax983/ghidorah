use ghidorah_base::{Address, FuncId, Rev};

use super::{FuncProgress, Mark, Progress, ProgressCounts};
use crate::fact::SessionLabel;

fn f(entry: u64) -> FuncId {
    FuncId(Address::ram(entry))
}

#[test]
fn rows_counts_and_marks() {
    let mut p = Progress::default();
    let visited = FuncProgress {
        visited: true,
        ..FuncProgress::default()
    };
    assert_eq!(p.set(f(1), visited), FuncProgress::default());
    let full = FuncProgress {
        visited: true,
        named: true,
        typed: true,
        commented: true,
    };
    p.set(f(2), full);
    assert_eq!(p.get(f(1)), visited);
    assert_eq!(p.get(f(9)), FuncProgress::default());
    assert_eq!(
        p.counts(),
        ProgressCounts {
            visited: 2,
            named: 1,
            typed: 1,
            commented: 1
        }
    );
    assert_eq!(p.set(f(1), FuncProgress::default()), visited);
    assert_eq!(
        p.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        [f(2)],
        "a default row goes"
    );

    let s = SessionLabel::new("mcp-1").unwrap();
    assert_eq!(
        p.set_mark(
            s.clone(),
            Mark {
                last_brief_rev: Rev(4)
            }
        ),
        None
    );
    assert_eq!(
        p.set_mark(
            s.clone(),
            Mark {
                last_brief_rev: Rev(9)
            }
        ),
        Some(Mark {
            last_brief_rev: Rev(4)
        })
    );
    assert_eq!(
        p.mark(&s),
        Some(Mark {
            last_brief_rev: Rev(9)
        })
    );
    assert_eq!(p.mark(&SessionLabel::new("cli").unwrap()), None);
    assert_eq!(p.marks().count(), 1);
}
