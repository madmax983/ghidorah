use super::matches;

#[test]
fn star_and_question_mark_match() {
    assert!(matches("mov*eax*0x1337", "mov eax, 0x1337", false));
    assert!(matches("*", "", false));
    assert!(matches("a?c", "abc", false));
    assert!(!matches("a?c", "ac", false));
    assert!(matches("*break;*", "7:\n    break;\n", false));
    assert!(!matches("abc", "abcd", false));
    assert!(matches("ab*", "abcd", false));
}

#[test]
fn icase_folds_ascii_letters() {
    assert!(matches("*process*", "ExitProcess", true));
    assert!(!matches("*process*", "ExitProcess", false));
}
