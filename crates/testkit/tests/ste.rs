//! Tests of the STE checker (AC-225 and the checker contract of ADR-0019).

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ghidorah_testkit::ste::{
    self, AllowEntry, Allowlist, Checker, Finding, Lexicon, Mode, Rule, TextKind,
};

const PASS: &str = include_str!("../../../tests/data/ste/pass.txt");
const FAIL: &str = include_str!("../../../tests/data/ste/fail.txt");

fn checker() -> Checker {
    Checker::new(Lexicon::builtin())
}

fn rules(findings: &[Finding]) -> BTreeSet<Rule> {
    findings.iter().map(|f| f.rule).collect()
}

/// Parses corpus lines into `(line number, expected rules, text)`.
fn corpus(text: &str) -> Vec<(usize, BTreeSet<Rule>, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((ids, body)) = line.split_once(" | ") else {
            panic!("corpus line {} has no ` | `: {line}", i + 1);
        };
        let expected: BTreeSet<Rule> = if ids.trim() == "-" {
            BTreeSet::new()
        } else {
            ids.split(',')
                .map(|id| {
                    Rule::from_id(id.trim())
                        .unwrap_or_else(|| panic!("unknown rule {id} on line {}", i + 1))
                })
                .collect()
        };
        out.push((i + 1, expected, body.to_string()));
    }
    out
}

#[test]
fn ac_225_ste_corpus() {
    let checker = checker();
    let pass = corpus(PASS);
    let fail = corpus(FAIL);
    assert!(pass.len() >= 20, "the pass corpus has at least 20 lines");
    assert!(fail.len() >= 20, "the fail corpus has at least 20 lines");
    assert!(pass.iter().all(|(_, want, _)| want.is_empty()));
    let covered: BTreeSet<Rule> = fail.iter().flat_map(|(_, want, _)| want.clone()).collect();
    assert_eq!(covered.len(), 8, "the fail corpus covers every rule");
    let mut errors = Vec::new();
    for (file, lines) in [("pass.txt", &pass), ("fail.txt", &fail)] {
        for (line, want, text) in lines {
            let findings = checker.check(text, TextKind::Plain);
            let got = rules(&findings);
            if &got != want {
                let detail: Vec<String> = findings.iter().map(ToString::to_string).collect();
                errors.push(format!(
                    "{file}:{line}: want {want:?}, got {got:?}: {text}\n    {}",
                    detail.join("\n    ")
                ));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "corpus mismatches:\n{}",
        errors.join("\n")
    );
}

#[test]
fn ste_rule_ids_roundtrip() {
    for rule in Rule::ALL {
        assert_eq!(Rule::from_id(rule.id()), Some(rule));
        assert_eq!(rule.to_string(), rule.id());
    }
    assert_eq!(Rule::from_id("STE-9"), None);
}

#[test]
fn ste_markdown_skips_headings_fences_and_mermaid() {
    let text = "# The file is read by the loader\n\
                \n\
                ```text\n\
                The file is read by the loader.\n\
                ```\n\
                \n\
                ```mermaid\n\
                graph TD\n\
                ```\n\
                \n\
                The value is checked here.\n";
    let findings = checker().check(text, TextKind::Markdown);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, Rule::Ste4);
    assert_eq!(findings[0].line, 11);
}

#[test]
fn ste_markdown_checks_table_cells_and_skips_the_header_row() {
    let text = "| The header cell is used | B |\n\
                |---|---|\n\
                | The cell is used by the loader. | ok |\n\
                | fine | The value is fine. |\n";
    let findings = checker().check(text, TextKind::Markdown);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].line, 3);
    assert_eq!(findings[0].rule, Rule::Ste4);
}

#[test]
fn ste_markdown_list_items_are_paragraphs() {
    let text = "- The reader starts. It reads a byte. It checks the byte.\n\
                - It moves on. It reads more. It stops at the end. It returns the count.\n";
    let findings = checker().check(text, TextKind::Markdown);
    assert!(
        findings.is_empty(),
        "two items with 3 and 4 sentences: {findings:?}"
    );
    let joined = "The reader starts. It reads a byte. It checks the byte.\n\
                  It moves on. It reads more. It stops at the end. It returns the count.\n";
    let findings = checker().check(joined, TextKind::Markdown);
    assert_eq!(rules(&findings), BTreeSet::from([Rule::Ste3]));
}

#[test]
fn ste_rust_comments_only() {
    let src = "//! The crate is used by tests.\n\
               \n\
               /// Reads the header.\n\
               ///\n\
               /// # Errors\n\
               ///\n\
               /// ```\n\
               /// let x = \"is read by\";\n\
               /// ```\n\
               fn f() -> &'static str {\n\
                   let s = \"// The value is read by the loader.\";\n\
                   let c = '\"';\n\
                   s // The value should change.\n\
               }\n\
               /* The block is ignored by nobody. */\n";
    let findings = checker().check(src, TextKind::RustComments);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(
        got,
        vec![(1, Rule::Ste4), (13, Rule::Ste6), (15, Rule::Ste4)],
        "{findings:?}"
    );
}

#[test]
fn ste_finding_has_line_detail_and_sentence() {
    let text = "First line is fine.\nThe file\nis read by the loader.\n";
    let findings = checker().check(text, TextKind::Plain);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.line, 2);
    assert_eq!(f.sentence, "The file is read by the loader.");
    assert!(f.detail.contains("is read"), "{}", f.detail);
    assert!(f.to_string().starts_with("STE-4 line 2"), "{f}");
}

#[test]
fn ste_plain_text_blank_line_ends_a_paragraph() {
    let text = "One. Two. Three. Four.\n\nFive. Six. Seven.\n";
    assert!(checker().check(text, TextKind::Plain).is_empty());
}

#[test]
fn ste_allowlist_parse_and_allow() {
    let text = "# reviewed entries\n\
                \n\
                docs/a.md STE-4 The file is read\n\
                crates/x/src/lib.rs STE-7 header field value\n";
    let allow = Allowlist::parse(text);
    let Ok(allow) = allow else {
        panic!("the allowlist parses: {allow:?}");
    };
    assert_eq!(allow.entries().len(), 2);
    let finding = Finding {
        line: 3,
        rule: Rule::Ste4,
        sentence: "The file is read by the loader.".to_string(),
        detail: "is read".to_string(),
    };
    assert!(allow.allows("docs/a.md", &finding));
    assert!(!allow.allows("docs/b.md", &finding));
    let other_rule = Finding {
        rule: Rule::Ste6,
        ..finding
    };
    assert!(!allow.allows("docs/a.md", &other_rule));
    assert!(Allowlist::parse("docs/a.md STE-9 x\n").is_err());
    assert!(Allowlist::parse("docs/a.md STE-4\n").is_err());
    let err = Allowlist::parse("ok.md STE-1 fine\nbad\n");
    assert_eq!(err.map_err(|e| e.line), Err(2));
}

#[test]
fn ste_allow_entry_for_finding_roundtrip() {
    let finding = Finding {
        line: 9,
        rule: Rule::Ste2,
        sentence: "one two three four five six seven eight nine ten".to_string(),
        detail: "26 words".to_string(),
    };
    let entry = AllowEntry::for_finding("docs/x.md", &finding);
    assert_eq!(entry.fragment, "one two three four five six seven eight");
    let line = entry.to_string();
    assert_eq!(
        line,
        "docs/x.md STE-2 one two three four five six seven eight"
    );
    let parsed = Allowlist::parse(&line);
    assert!(parsed.is_ok_and(|a| a.allows("docs/x.md", &finding)));
}

#[test]
fn ste_exempt_paths() {
    assert!(ste::is_exempt("docs/research.md"));
    assert!(ste::is_exempt("docs/planning/six-hats.md"));
    assert!(!ste::is_exempt("docs/design.md"));
    assert!(!ste::is_exempt("docs/research.md.bak"));
}

#[test]
fn ste_text_kind_of_path() {
    assert_eq!(
        TextKind::of_path("docs/design.md"),
        Some(TextKind::Markdown)
    );
    assert_eq!(
        TextKind::of_path("crates/a/src/lib.rs"),
        Some(TextKind::RustComments)
    );
    assert_eq!(TextKind::of_path("tests/data/ste/pass.txt"), None);
}

#[test]
fn ste_banlist_and_glossary_extend_lexicon() {
    let mut lexicon = Lexicon::builtin();
    assert!(lexicon.is_banned("would"));
    assert!(lexicon.is_banned("Ensures"));
    assert!(!lexicon.is_banned("frobnicate"));
    assert!(!lexicon.is_imperative("frobnicate"));
    lexicon.add_banlist("# extra words\nfrobnicate\n\n");
    lexicon.add_glossary("| Word | Kind | Meaning |\n|---|---|---|\n| zap | verb | Clear a value. |\n- bonk (verb): hit a key.\n");
    assert!(lexicon.is_banned("Frobnicate"));
    assert!(lexicon.is_imperative("Zap"));
    assert!(lexicon.is_imperative("bonk"));
    assert!(!lexicon.is_imperative("word"));
    let findings = Checker::new(lexicon).check("Zap the value and bonk the key.", TextKind::Plain);
    assert_eq!(rules(&findings), BTreeSet::from([Rule::Ste8]));
}

#[test]
fn ste_check_agent_text_is_deny_mode() {
    let findings = ste::check_agent_text("The file is read.");
    assert_eq!(rules(&findings), BTreeSet::from([Rule::Ste4]));
    assert!(ste::check_agent_text("Run `binary_load` first.").is_empty());
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("mkdir {}: {e}", parent.display()));
    }
    std::fs::write(&full, text).unwrap_or_else(|e| panic!("write {}: {e}", full.display()));
}

fn temp_tree() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ste_scan_tree");
    let _ = std::fs::remove_dir_all(&root);
    write(
        &root,
        "docs/a.md",
        "# Title\n\nThe file is read by the loader.\n",
    );
    write(
        &root,
        "docs/research.md",
        "The file is read by the loader.\n",
    );
    write(
        &root,
        "docs/planning/x.md",
        "The file is read by the loader.\n",
    );
    write(
        &root,
        "crates/x/src/lib.rs",
        "// The value should change.\nfn f() {}\n",
    );
    write(&root, "target/x.md", "The file is read by the loader.\n");
    write(&root, ".hidden/x.md", "The file is read by the loader.\n");
    write(&root, "docs/notes.txt", "The file is read by the loader.\n");
    write(&root, "docs/ste-banlist.txt", "frobnicate\n");
    write(
        &root,
        "docs/ste-allowlist.txt",
        "crates/x/src/lib.rs STE-6 The value should change\nREADME.md STE-4 unused entry\n",
    );
    write(&root, "README.md", "Frobnicate the value.\n");
    root
}

#[test]
fn ste_scan_repo_on_temp_tree() {
    let root = temp_tree();
    let files = ste::repo_files(&root).unwrap_or_default();
    assert_eq!(files, vec!["README.md", "crates/x/src/lib.rs", "docs/a.md"]);
    let lexicon = ste::repo_lexicon(&root);
    assert!(lexicon.is_banned("frobnicate"));
    let allow = ste::repo_allowlist(&root);
    let Ok(allow) = allow else {
        panic!("the allowlist parses: {allow:?}");
    };
    let checker = Checker::new(lexicon);
    let warn = ste::scan_repo(&root, &checker, Mode::Warn, &allow);
    let Ok(warn) = warn else {
        panic!("the scan runs: {warn:?}");
    };
    assert_eq!(warn.files, 3);
    let paths: Vec<&str> = warn.findings.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, vec!["README.md", "docs/a.md"], "{:?}", warn.findings);
    assert_eq!(warn.allowed, 1);
    assert_eq!(warn.unused.len(), 1);
    assert!(!warn.ok());
    let deny = ste::scan_repo(&root, &checker, Mode::Deny, &allow);
    assert_eq!(deny.map(|r| r.findings.len()).ok(), Some(3));
    let missing = ste::repo_allowlist(&root.join("docs"));
    assert_eq!(missing.map(|a| a.entries().len()), Ok(0));
}
