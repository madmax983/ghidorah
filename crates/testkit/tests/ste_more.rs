//! More tests of the STE checker: counting rules, inflections, Markdown and Rust edge cases.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidorah_testkit::pbt;
use ghidorah_testkit::ste::{self, Allowlist, Checker, Finding, Lexicon, Mode, Rule, TextKind};

fn plain(text: &str) -> Vec<Finding> {
    Checker::new(Lexicon::builtin()).check(text, TextKind::Plain)
}

fn rules_of(findings: &[Finding]) -> BTreeSet<Rule> {
    findings.iter().map(|f| f.rule).collect()
}

#[test]
fn ste_parenthetical_counts_as_one_word() {
    let text = "The scheduler runs each analyzer in a fixed order (by priority, then by name, \
                then by address, then by section, then by size, then by kind) so that runs give \
                equal output.";
    assert!(plain(text).is_empty(), "{:?}", plain(text));
    let open = "The scheduler runs each analyzer in a fixed order, by priority, then by name, \
                then by address, then by section, then by size, then by kind, so that runs give \
                equal output.";
    assert_eq!(rules_of(&plain(open)), BTreeSet::from([Rule::Ste2]));
}

#[test]
fn ste_comma_enumeration_of_code_spans_counts_as_one_word() {
    let spans: Vec<String> = ('A'..='Y').map(|c| format!("`{c}`")).collect();
    let text = format!(
        "The crate holds {} and `Z` for all tests.",
        spans.join(", ")
    );
    assert!(plain(&text).is_empty(), "{:?}", plain(&text));
}

#[test]
fn ste_label_list_counts_as_one_word() {
    let text = "Owns: the loader, the decoder, the lifter, the analyzer, the scheduler, the \
                types, the database, the tools, the server, the client, the harness, the kit.";
    assert!(plain(text).is_empty(), "{:?}", plain(text));
    let no_label = "The crate owns the loader, the decoder, the lifter, the analyzer, the \
                    scheduler, the types, the database, the tools, the server, the client, the \
                    harness, the kit.";
    assert_eq!(rules_of(&plain(no_label)), BTreeSet::from([Rule::Ste2]));
}

#[test]
fn ste_adjectival_participles_are_not_passive() {
    assert!(plain("The value is unused.").is_empty());
    assert!(plain("The loader has fixed limits.").is_empty());
    assert!(plain("The table is empty and the loader is ready.").is_empty());
    let by = plain("The value is fixed by the loader.");
    assert_eq!(rules_of(&by), BTreeSet::from([Rule::Ste4]));
}

#[test]
fn ste_inflected_banned_words() {
    for text in [
        "The step ensures the result.",
        "The loader ensured the range.",
        "The code utilized a map.",
        "The reader is utilizing a map.",
        "Never use would.",
    ] {
        assert!(
            rules_of(&plain(text)).contains(&Rule::Ste6),
            "{text}: {:?}",
            plain(text)
        );
    }
    assert!(plain("The loader ends the load.").is_empty());
}

#[test]
fn ste_finding_details() {
    let spans: Vec<String> = ('A'..='L').map(|c| format!("`{c}`")).collect();
    let long = format!("The crate holds {} today.", spans.join(" and "));
    let found = plain(&long);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].detail, "27 words");
    let many = plain("A b. C d. E f. G h. I j. K l. M n.");
    assert_eq!(many.len(), 1, "{many:?}");
    assert_eq!(many[0].rule, Rule::Ste3);
    assert_eq!(many[0].detail, "7 sentences");
    let should = plain("The loader should stop.");
    assert_eq!(should[0].detail, "should");
    let run = plain("The file header field value is wrong.");
    assert_eq!(run[0].detail, "file header field value");
    let and = plain("Read the file and write the output.");
    assert_eq!(and[0].rule, Rule::Ste8);
    assert!(and[0].detail.contains("write"), "{}", and[0].detail);
}

#[test]
fn ste_markdown_quotes_links_html_and_emphasis() {
    let text = "> The file is read by the loader.\n\
                \n\
                See [the guide](https://example.com/a_b/c_d.md) for details.\n\
                \n\
                <!-- The file is read by the loader. -->\n\
                \n\
                The **loader** reads the *file*.\n\
                \n\
                ![The file is read](image.png)\n";
    let findings = Checker::new(Lexicon::builtin()).check(text, TextKind::Markdown);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(got, vec![(1, Rule::Ste4), (9, Rule::Ste4)], "{findings:?}");
}

#[test]
fn ste_markdown_numbered_items_and_continuation_lines() {
    let text = "1. The reader starts. It reads a byte.\n\
                   It checks the byte. It moves on.\n\
                2. It stops. It returns.\n\
                \n\
                * Open the file.\n\
                * Read the file and write the output.\n";
    let findings = Checker::new(Lexicon::builtin()).check(text, TextKind::Markdown);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(got, vec![(6, Rule::Ste8)], "{findings:?}");
}

#[test]
fn ste_rust_block_comments_raw_strings_and_lifetimes() {
    let src = "fn f<'a>(x: &'a str) -> &'a str {\n\
               \x20   let r = r#\"// The value is read by the loader. \"quoted\" \"#;\n\
               \x20   /* outer /* inner */ The file is read. */\n\
               \x20   let b = b'/';\n\
               \x20   let t = \"a \\\" // The file is read.\";\n\
               \x20   x\n\
               }\n\
               /** The doc is read by nobody. */\n\
               struct S;\n";
    let findings = Checker::new(Lexicon::builtin()).check(src, TextKind::RustComments);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(got, vec![(3, Rule::Ste4), (8, Rule::Ste4)], "{findings:?}");
}

#[test]
fn ste_rust_comment_blocks_are_paragraphs() {
    let src = "// One. Two. Three.\n\
               // Four. Five. Six. Seven.\n\
               fn f() {}\n\
               // Eight. Nine.\n\
               fn g() {}\n";
    let findings = Checker::new(Lexicon::builtin()).check(src, TextKind::RustComments);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(got, vec![(1, Rule::Ste3)], "{findings:?}");
}

#[test]
fn ste_markdown_edge_blocks() {
    let text = "~~~\nThe file is read.\n~~~\n\
                <!-- start\n\
                The file is read.\n\
                end -->\n\
                [ref]: https://example.com/a.md\n\
                ---\n\
                > > Nested quote is read by nobody.\n\
                \n\
                | Name | Note |\n\
                |:--|--:|\n\
                | `a|b` | Use a pipe \\| here. |\n\
                \n\
                1) First item.\n\
                + Second item is checked by the tool.\n\
                text <b>bold</b> and < not a tag.\n";
    let findings = Checker::new(Lexicon::builtin()).check(text, TextKind::Markdown);
    let got: Vec<(usize, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
    assert_eq!(got, vec![(9, Rule::Ste4), (16, Rule::Ste4)], "{findings:?}");
}

fn repo_with_glossary() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ste_glossary_tree");
    let _ = std::fs::remove_dir_all(&root);
    let docs = root.join("docs");
    std::fs::create_dir_all(&docs).unwrap_or_else(|e| panic!("mkdir: {e}"));
    std::fs::write(
        docs.join("GLOSSARY.md"),
        "| Word | Kind | Meaning |\n|---|---|---|\n| frob | verb | Turn a part. |\n- zap (verb): clear a value.\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    root
}

#[test]
fn ste_repo_lexicon_reads_the_glossary() {
    let root = repo_with_glossary();
    let lexicon = ste::repo_lexicon(&root);
    assert!(lexicon.is_imperative("frob"));
    assert!(lexicon.is_imperative("Zap"));
    let findings = Checker::new(lexicon).check("Frob the part and zap the value.", TextKind::Plain);
    assert_eq!(rules_of(&findings), BTreeSet::from([Rule::Ste8]));
}

#[test]
fn ste_lexicon_reads_the_verb_section_of_the_glossary() {
    let text = "# Glossary\n\n## Technical verbs\n\n| Word | Meaning |\n|---|---|\n\
                | demangle | Change a name. |\n| `lift` | Change an instruction. |\n\
                | make sure | Check a result. |\n\n## Technical nouns\n\n\
                | Word | Meaning |\n|---|---|\n| thunk | A short jump. |\n";
    let mut lexicon = Lexicon::builtin();
    lexicon.add_glossary(text);
    assert!(lexicon.is_imperative("demangle"));
    assert!(lexicon.is_imperative("Lift"));
    assert!(!lexicon.is_imperative("word"));
    assert!(!lexicon.is_imperative("make sure"));
    assert!(!lexicon.is_imperative("thunk"));
    let findings =
        Checker::new(lexicon).check("Demangle the name and lift the code.", TextKind::Plain);
    assert_eq!(rules_of(&findings), BTreeSet::from([Rule::Ste8]));
}

#[test]
fn ste_repo_glossary_verbs_are_imperatives() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lexicon = ste::repo_lexicon(&root);
    for verb in [
        "demangle",
        "disassemble",
        "fuzz",
        "lift",
        "rebase",
        "verify",
    ] {
        assert!(lexicon.is_imperative(verb), "{verb}");
    }
    assert!(!lexicon.is_imperative("thunk"));
}

#[test]
fn ste_scan_of_a_missing_root_is_an_error() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ste_no_such_root");
    let _ = std::fs::remove_dir_all(&root);
    let checker = Checker::new(Lexicon::builtin());
    let scan = ste::scan_repo(&root, &checker, Mode::Warn, &Allowlist::default());
    assert!(scan.is_err());
    assert!(ste::repo_files(&root).is_err());
}

#[test]
fn ste_allowlist_entry_does_not_allow_another_rule_or_file() {
    let finding = plain("The loader should stop.").remove(0);
    let allow = Allowlist::parse("docs/a.md STE-6 The loader should\n");
    let Ok(allow) = allow else {
        panic!("the allowlist parses: {allow:?}");
    };
    assert!(allow.allows("docs/a.md", &finding));
    assert!(!allow.allows("docs/b.md", &finding));
    let other = Finding {
        sentence: "A different sentence.".to_string(),
        ..finding
    };
    assert!(!allow.allows("docs/a.md", &other));
}

const FRAGMENTS: [&str; 24] = [
    "The", "file", "is", "read", "by", "should", "`code`", "and", "write", ".", ",", ":", "|", "(",
    ")", "```", "#", "-", "1.", "e.g.", "\n", "\n\n", "'", "\"",
];

#[test]
fn ste_never_panics_and_reports_in_line_order() {
    pbt::check("ste_random_text", 200, |g| {
        let n = g.draw(60);
        let mut text = String::new();
        for _ in 0..n {
            let i = g.draw(u64::try_from(FRAGMENTS.len()).unwrap_or(1));
            text.push_str(FRAGMENTS[usize::try_from(i).unwrap_or(0)]);
            text.push(' ');
        }
        let lines = text.lines().count() + 1;
        let checker = Checker::new(Lexicon::builtin());
        for kind in [TextKind::Plain, TextKind::Markdown, TextKind::RustComments] {
            let findings = checker.check(&text, kind);
            let mut last = 0;
            for f in &findings {
                if f.line == 0 || f.line > lines {
                    return Err(format!("line {} outside 1..={lines}: {text:?}", f.line));
                }
                if f.line < last {
                    return Err(format!("findings are not in line order: {text:?}"));
                }
                last = f.line;
            }
        }
        Ok(())
    });
}
