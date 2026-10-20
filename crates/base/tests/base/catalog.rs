//! Tests of the frozen code catalogs (design Section 10.8, ADR-0002).

use std::collections::BTreeSet;

use ghidorah_base::catalog::{
    self, ERRORS_DOC_PATH, ERRORS_DOC_VERSION, errors_markdown, placeholders, render,
};
use ghidorah_base::{CodeInfo, DiagCode, ErrorCode, RepairClass, WarningCode};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste;

use crate::support::repo_root;

/// The frozen error list of design Section 10.8: number, name, class and retry flag.
/// A reserved row has the class `-`.
const ERRORS: [(u16, &str, &str, bool); 41] = [
    (1, "INVALID_ARGUMENT", "N", false),
    (2, "UNKNOWN_ARGUMENT", "R", false),
    (3, "MISSING_ARGUMENT", "H", false),
    (4, "UNKNOWN_TOOL", "H", false),
    (5, "TOOL_NOT_IN_PROFILE", "H", false),
    (6, "ADDRESS_INVALID", "R*", false),
    (7, "ADDRESS_UNMAPPED", "C", false),
    (8, "ADDRESS_BASE_AMBIGUOUS", "C", false),
    (9, "AMBIGUOUS_NAME", "C", false),
    (10, "NOT_FOUND", "C", false),
    (11, "UNKNOWN_BINARY", "R*", false),
    (12, "BINARY_REQUIRED", "R", false),
    (13, "PATH_OUTSIDE_ROOT", "N", false),
    (14, "FILE_UNREADABLE", "N", false),
    (15, "UNSUPPORTED_FORMAT", "N", false),
    (16, "UNSUPPORTED_ARCH", "N", false),
    (17, "FORMAT_MALFORMED", "N", false),
    (18, "CURSOR_INVALID", "R", false),
    (19, "CURSOR_STALE", "R", false),
    (20, "CONFLICT", "H", true),
    (21, "BLOCKED_BY_HIGHER_PRIORITY_SOURCE", "N", false),
    (22, "BODY_OVERLAP", "N", false),
    (23, "NOT_IN_FUNCTION", "N", false),
    (24, "NO_FILE_BYTES", "-", false),
    (25, "PATCH_INVALID", "-", false),
    (26, "C_PARSE_ERROR", "N", false),
    (27, "NOTHING_TO_UNDO", "N", false),
    (28, "LIMIT_EXCEEDED", "R", false),
    (29, "BAD_REFERENCE", "C", false),
    (30, "SKIPPED_DEPENDENCY", "N", false),
    (31, "EXPECT_FAILED", "N", false),
    (32, "PLUCK_TOO_LONG", "R", false),
    (33, "BUDGET_EXCEEDED", "R", true),
    (34, "PROJECT_LOCKED", "N", true),
    (35, "JOURNAL_CORRUPT", "N", false),
    (36, "READ_ONLY_PROJECT", "N", false),
    (37, "OUTPUT_BUDGET_EXCEEDED", "N", false),
    (38, "INTERNAL_ERROR", "N", false),
    (39, "IDEMPOTENCY_MISMATCH", "-", false),
    (40, "NO_BINARY_OPEN", "H", false),
    (41, "NOTHING_TO_REDO", "N", false),
];

/// The frozen warning list: number, name, class and retry flag.
const WARNINGS: [(u16, &str, &str, bool); 20] = [
    (1, "W_COERCED", "N", false),
    (2, "W_ARCH_UNSUPPORTED", "N", false),
    (3, "W_NOT_DEMANGLED", "N", false),
    (4, "W_JOURNAL_TAIL_DISCARDED", "N", false),
    (5, "W_AGENT_OVERRIDE_CONFLICT", "C", false),
    (6, "W_FACT_ORPHANED", "H", false),
    (7, "W_STALE_OP_ID", "N", false),
    (8, "W_UNGROUNDED_FINDING", "H", false),
    (9, "W_NORETURN_SUSPECT", "H", false),
    (10, "W_NORETURN_ASSUMED", "N", false),
    (11, "W_JUMPTABLE_UNRESOLVED", "H", false),
    (12, "W_JUMPTABLE_DISAGREE", "-", false),
    (13, "W_INDIRECT_CALL_UNRESOLVED", "H", false),
    (14, "W_LIFT_UNSUPPORTED", "N", false),
    (15, "W_SP_MISMATCH", "N", false),
    (16, "W_CC_CONFLICT", "-", false),
    (17, "W_BUDGET_FLAT", "N", false),
    (18, "W_STRUCTURE_SELFCHECK", "N", false),
    (19, "W_ANALYSIS_STALE", "R", false),
    (20, "W_TIME_STOP", "R", true),
];

/// The frozen diagnostic list: number and name.
const DIAGS: [(u16, &str); 15] = [
    (1, "E_OOB"),
    (2, "E_OVERFLOW"),
    (3, "E_BAD_MAGIC"),
    (4, "E_LIMIT"),
    (5, "E_LOOP"),
    (6, "E_BAD_ALIGN"),
    (7, "E_BAD_ENTSIZE"),
    (8, "E_UNSUPPORTED_RELOC"),
    (9, "E_CFA_OPCODE"),
    (10, "E_OVERLAP"),
    (11, "E_SYNTAX"),
    (12, "E_UNKNOWN_TYPE"),
    (13, "E_INCOMPLETE_BY_VALUE"),
    (14, "E_CONST_EXPR"),
    (15, "E_UNSUPPORTED"),
];

/// Gives the rows `(num, name, class, retry)` of a catalog, reserved numbers included.
fn rows(infos: &[CodeInfo], reserved: &[catalog::Reserved]) -> Vec<(u16, String, String, bool)> {
    let mut out: Vec<(u16, String, String, bool)> = infos
        .iter()
        .map(|i| {
            (
                i.num,
                i.name.to_string(),
                i.class.as_str().to_string(),
                i.retry,
            )
        })
        .chain(
            reserved
                .iter()
                .map(|r| (r.num, r.name.to_string(), "-".to_string(), false)),
        )
        .collect();
    out.sort();
    out
}

fn want_rows(table: &[(u16, &str, &str, bool)]) -> Vec<(u16, String, String, bool)> {
    table
        .iter()
        .map(|&(n, name, class, retry)| (n, name.to_string(), class.to_string(), retry))
        .collect()
}

#[test]
fn error_codes_frozen() {
    let infos: Vec<CodeInfo> = ErrorCode::ALL.iter().map(|c| c.info()).collect();
    assert_eq!(rows(&infos, &ErrorCode::RESERVED), want_rows(&ERRORS));
    for code in ErrorCode::ALL {
        assert_eq!(code.num(), code.info().num, "{code:?}");
        assert_eq!(code as u16, code.num(), "{code:?}");
        assert_eq!(ErrorCode::from_num(code.num()), Some(code));
        assert_eq!(ErrorCode::from_name(code.name()), Some(code));
        assert_eq!(code.to_string(), code.name());
    }
    for reserved in ErrorCode::RESERVED {
        assert_eq!(ErrorCode::from_num(reserved.num), None);
        assert_eq!(ErrorCode::from_name(reserved.name), None);
        assert!(reserved.stretch.starts_with('S'));
    }
    assert_eq!(ErrorCode::from_num(0), None);
    assert_eq!(ErrorCode::from_num(42), None);
    assert_eq!(ErrorCode::from_name("invalid_argument"), None);
}

#[test]
fn warning_codes_frozen() {
    let infos: Vec<CodeInfo> = WarningCode::ALL.iter().map(|c| c.info()).collect();
    assert_eq!(rows(&infos, &WarningCode::RESERVED), want_rows(&WARNINGS));
    for code in WarningCode::ALL {
        assert_eq!(code.num(), code.info().num, "{code:?}");
        assert_eq!(code as u16, code.num(), "{code:?}");
        assert_eq!(WarningCode::from_num(code.num()), Some(code));
        assert_eq!(WarningCode::from_name(code.name()), Some(code));
        assert_eq!(code.to_string(), code.name());
    }
    for reserved in WarningCode::RESERVED {
        assert_eq!(WarningCode::from_num(reserved.num), None);
        assert_eq!(WarningCode::from_name(reserved.name), None);
    }
    assert_eq!(WarningCode::from_num(21), None);
}

#[test]
fn diag_codes_frozen() {
    let got: Vec<(u16, &str)> = DiagCode::ALL
        .iter()
        .map(|c| (c.info().num, c.info().name))
        .collect();
    assert_eq!(got, DIAGS);
    for code in DiagCode::ALL {
        assert_eq!(code as u16, code.num());
        assert_eq!(DiagCode::from_num(code.num()), Some(code));
        assert_eq!(DiagCode::from_name(code.name()), Some(code));
        assert_eq!(code.to_string(), code.name());
        assert_eq!(code.info().class, RepairClass::None);
        assert!(!code.info().retry);
    }
    assert_eq!(DiagCode::from_num(16), None);
}

/// Checks the plain hint of one error code. A result with no repair call, no candidates or a
/// wide scope takes it, so it names none of them.
fn check_plain(info: &CodeInfo, failures: &mut Vec<String>) {
    for mark in ["next[0]", "candidate", "*"] {
        if info.plain.contains(mark) {
            failures.push(format!("{} plain hint names {mark}", info.name));
        }
    }
    let plain_needed =
        info.hint_names_next() || info.hint_names_candidates() || info.hint.contains('*');
    if !plain_needed && info.plain != info.hint {
        failures.push(format!("{} needs no plain hint", info.name));
    }
}

/// Checks the text fields of one code.
fn check_text(info: &CodeInfo, failures: &mut Vec<String>) {
    let texts = [
        ("message", info.message),
        ("hint", info.hint),
        ("plain hint", info.plain),
    ];
    for (what, text) in texts {
        if text.trim().is_empty() {
            failures.push(format!("{} has an empty {what}", info.name));
        }
        if !text.ends_with('.') {
            failures.push(format!(
                "{} {what} does not end with a period: {text}",
                info.name
            ));
        }
        for finding in ste::check_agent_text(text) {
            failures.push(format!("{} {what}: {finding}", info.name));
        }
        for bad in ["Some(", "Os {", "Error {", "panicked at"] {
            if text.contains(bad) {
                failures.push(format!("{} {what} holds debug text {bad}", info.name));
            }
        }
    }
}

#[test]
fn ac_141a_catalog_complete() {
    let mut failures = Vec::new();
    let mut names = BTreeSet::new();
    let infos = ErrorCode::ALL
        .iter()
        .map(|c| c.info())
        .chain(WarningCode::ALL.iter().map(|c| c.info()));
    for info in infos {
        assert!(info.num > 0, "{} has a frozen number", info.name);
        assert!(names.insert(info.name), "{} is unique", info.name);
        check_text(&info, &mut failures);
        // A message has the form "What failed. Why. Action.": at least two sentences.
        if info.message.matches(". ").count() < 1 {
            failures.push(format!("{} message has one sentence", info.name));
        }
    }
    for info in DiagCode::ALL.iter().map(|c| c.info()) {
        check_text(&info, &mut failures);
    }
    for code in ErrorCode::ALL {
        check_plain(&code.info(), &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        RepairClass::ALL.map(RepairClass::as_str),
        ["R", "R*", "C", "H", "N"]
    );
    assert_eq!(RepairClass::Choice.to_string(), "C");
}

#[test]
fn templates_render() {
    assert_eq!(placeholders("The {field} of {tool}."), ["field", "tool"]);
    assert_eq!(placeholders("No {} or {Bad} or {x"), Vec::<&str>::new());
    assert_eq!(
        render(
            "The {field} of {tool}.",
            &[("field", "target"), ("tool", "func_get")]
        ),
        "The target of func_get."
    );
    assert_eq!(render("The {field}.", &[]), "The {field}.");
    assert_eq!(render("{a}{a}", &[("a", "{a}")]), "{a}{a}");
    let message = ErrorCode::InvalidArgument.info().message;
    assert_eq!(placeholders(message), ["field"]);
    assert!(!render(message, &[("field", "target")]).contains('{'));
}

#[test]
fn ac_026_errors_doc_golden() {
    let body = errors_markdown();
    for code in ErrorCode::ALL {
        assert!(body.contains(&format!("`{}`", code.name())), "{code:?}");
    }
    for code in WarningCode::ALL {
        assert!(body.contains(&format!("`{}`", code.name())), "{code:?}");
    }
    for code in DiagCode::ALL {
        assert!(body.contains(&format!("`{}`", code.name())), "{code:?}");
    }
    for reserved in ErrorCode::RESERVED {
        assert!(body.contains(reserved.name), "{}", reserved.name);
    }
    let header = Header::new(
        "ghidorah-base::catalog::errors_markdown",
        ERRORS_DOC_VERSION,
    );
    golden::assert_text(&repo_root().join(ERRORS_DOC_PATH), &header, &body);
}

/// The hint of `FORMAT_MALFORMED` names the `binary_load` argument `file_format`. The global
/// argument `format` selects the output form, so `format raw` is not a valid repair.
#[test]
fn regress_format_malformed_hint_names_file_format() {
    let hint = ErrorCode::FormatMalformed.info().hint;
    assert!(hint.contains("file_format raw"), "{hint}");
}
