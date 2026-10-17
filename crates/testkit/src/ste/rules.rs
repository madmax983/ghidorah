//! The rules STE-1 to STE-8 on sentences and paragraphs.

use super::lex::{Kind, Sentence, Tok};
use super::lexicon::Lexicon;
use super::words::{
    ADJECTIVAL, ADJECTIVES, ADVERBS, BE_FORMS, FUNCTION, HAVE_FORMS, IRREGULAR_PARTICIPLES,
    IRREGULAR_PAST, NOT_PARTICIPLES, VERBS,
};
use super::{
    Finding, MAX_DESCRIPTIVE_WORDS, MAX_NOUN_RUN, MAX_PARAGRAPH_SENTENCES, MAX_PROCEDURAL_WORDS,
    Rule,
};

/// The class of a word for the noun cluster rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Function,
    Adjective,
    Verb,
    Noun,
}

fn listed(list: &[&str], word: &str) -> bool {
    list.contains(&word)
}

/// Returns `true` when `word` is a participle.
fn is_participle(word: &str) -> bool {
    if listed(IRREGULAR_PARTICIPLES, word) {
        return true;
    }
    word.len() >= 4
        && word.ends_with("ed")
        && word.is_ascii()
        && !word.contains('-')
        && !listed(NOT_PARTICIPLES, word)
}

/// Returns `true` when the participle `word` names a state, as in "is unused".
fn is_adjectival(word: &str) -> bool {
    listed(ADJECTIVAL, word) || (word.starts_with("un") && word.len() > 5 && word.ends_with("ed"))
}

fn is_adverb(tok: &Tok) -> bool {
    tok.is_plain_word() && (listed(ADVERBS, &tok.norm) || tok.norm.ends_with("ly"))
}

/// Returns `true` when `word` or its stem is a verb.
fn is_verb_like(word: &str) -> bool {
    if listed(VERBS, word) {
        return true;
    }
    for suffix in ["s", "es", "ed", "d", "ing"] {
        let Some(stem) = word.strip_suffix(suffix) else {
            continue;
        };
        let last_two: Vec<char> = stem.chars().rev().take(2).collect();
        let undoubled = match last_two.as_slice() {
            [a, b] if a == b => Some(&stem[..stem.len() - a.len_utf8()]),
            _ => None,
        };
        let with_e = format!("{stem}e");
        if listed(VERBS, stem)
            || listed(VERBS, &with_e)
            || undoubled.is_some_and(|u| listed(VERBS, u))
        {
            return true;
        }
    }
    word.strip_suffix("ies")
        .is_some_and(|stem| listed(VERBS, &format!("{stem}y")))
}

fn classify(word: &str) -> Class {
    if listed(FUNCTION, word)
        || listed(BE_FORMS, word)
        || listed(HAVE_FORMS, word)
        || listed(ADVERBS, word)
    {
        Class::Function
    } else if listed(ADJECTIVES, word)
        || word.contains('-')
        || ["ous", "ful", "less", "ly"]
            .iter()
            .any(|e| word.ends_with(e))
        || (word.len() > 6 && word.ends_with("ive"))
    {
        Class::Adjective
    } else if is_verb_like(word)
        || listed(IRREGULAR_PARTICIPLES, word)
        || listed(IRREGULAR_PAST, word)
        || (word.len() > 4 && (word.ends_with("ed") || word.ends_with("ing")))
    {
        Class::Verb
    } else {
        Class::Noun
    }
}

fn join(toks: &[Tok]) -> String {
    toks.iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Finds a passive: a form of "be", up to two adverbs and a participle.
fn passive(toks: &[Tok]) -> Option<String> {
    for (i, tok) in toks.iter().enumerate() {
        if !tok.is_plain_word() || !listed(BE_FORMS, &tok.norm) {
            continue;
        }
        let mut j = i + 1;
        while j < i + 3 && toks.get(j).is_some_and(is_adverb) {
            j += 1;
        }
        let Some(part) = toks
            .get(j)
            .filter(|p| p.is_plain_word() && is_participle(&p.norm))
        else {
            continue;
        };
        let by = toks.iter().skip(j + 1).take(3).any(|t| t.norm == "by");
        let regular = !listed(IRREGULAR_PARTICIPLES, &part.norm);
        if !by && (is_adjectival(&part.norm) || (regular && adjective_follows(toks.get(j + 1)))) {
            continue;
        }
        return Some(join(&toks[i..=j]));
    }
    None
}

/// Returns `true` when the token after a regular participle makes the participle an adjective.
fn adjective_follows(next: Option<&Tok>) -> bool {
    next.is_some_and(|n| n.is_plain_word() && !is_adverb(n) && classify(&n.norm) != Class::Function)
}

/// Finds a present perfect: "have" or "has", up to two adverbs and a participle.
fn perfect(toks: &[Tok]) -> Option<String> {
    for (i, tok) in toks.iter().enumerate() {
        if !tok.is_plain_word() || !listed(HAVE_FORMS, &tok.norm) {
            continue;
        }
        let mut j = i + 1;
        while j < i + 3 && toks.get(j).is_some_and(is_adverb) {
            j += 1;
        }
        let Some(part) = toks
            .get(j)
            .filter(|p| p.is_plain_word() && is_participle(&p.norm))
        else {
            continue;
        };
        let regular = !listed(IRREGULAR_PARTICIPLES, &part.norm);
        if regular && (is_adjectival(&part.norm) || adjective_follows(toks.get(j + 1))) {
            continue;
        }
        return Some(join(&toks[i..=j]));
    }
    None
}

/// Finds the first run of more than [`MAX_NOUN_RUN`] nouns.
fn noun_run(toks: &[Tok]) -> Option<String> {
    let mut run: Vec<&Tok> = Vec::new();
    for tok in toks.iter().map(Some).chain([None]) {
        match tok {
            Some(t) if t.is_plain_word() && classify(&t.norm) == Class::Noun => run.push(t),
            _ => {
                if run.len() > MAX_NOUN_RUN {
                    return Some(
                        run.iter()
                            .map(|t| t.text.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
                run.clear();
            }
        }
    }
    None
}

/// Finds "and" followed by an imperative.
fn joined_imperatives(lexicon: &Lexicon, toks: &[Tok]) -> Option<String> {
    toks.windows(2).find_map(|pair| {
        let (and, next) = (&pair[0], &pair[1]);
        (and.is_plain_word()
            && and.norm == "and"
            && next.is_plain_word()
            && lexicon.is_imperative(&next.norm))
        .then(|| format!("and {}", next.text))
    })
}

/// Finds the first banned word, also inside a parenthetical.
fn banned(lexicon: &Lexicon, toks: &[Tok]) -> Option<String> {
    for tok in toks {
        if tok.kind == Kind::Word && lexicon.is_banned(&tok.norm) {
            return Some(tok.text.clone());
        }
        if let Some(word) = tok.inner.iter().find(|w| lexicon.is_banned(w)) {
            return Some(word.clone());
        }
    }
    None
}

/// Returns the findings of one sentence, in rule order.
pub(crate) fn check_sentence(lexicon: &Lexicon, sentence: &Sentence) -> Vec<Finding> {
    let toks = &sentence.toks;
    let words = toks.iter().filter(|t| t.counts()).count();
    let procedural = toks
        .first()
        .is_some_and(|t| t.is_plain_word() && lexicon.is_imperative(&t.norm));
    let mut out = Vec::new();
    let mut add = |rule: Rule, detail: String| {
        out.push(Finding {
            line: sentence.line,
            rule,
            sentence: sentence.text.clone(),
            detail,
        });
    };
    if procedural && words > MAX_PROCEDURAL_WORDS {
        add(Rule::Ste1, format!("{words} words"));
    } else if !procedural && words > MAX_DESCRIPTIVE_WORDS {
        add(Rule::Ste2, format!("{words} words"));
    }
    if let Some(detail) = passive(toks) {
        add(Rule::Ste4, detail);
    }
    if let Some(detail) = perfect(toks) {
        add(Rule::Ste5, detail);
    }
    if let Some(detail) = banned(lexicon, toks) {
        add(Rule::Ste6, detail);
    }
    if let Some(detail) = noun_run(toks) {
        add(Rule::Ste7, detail);
    }
    if procedural && let Some(detail) = joined_imperatives(lexicon, toks) {
        add(Rule::Ste8, detail);
    }
    out
}

/// Returns the findings of one paragraph, in sentence order.
pub(crate) fn check_paragraph(lexicon: &Lexicon, sentences: &[Sentence]) -> Vec<Finding> {
    let mut out = Vec::new();
    if sentences.len() > MAX_PARAGRAPH_SENTENCES
        && let Some(first) = sentences.first()
    {
        out.push(Finding {
            line: first.line,
            rule: Rule::Ste3,
            sentence: first.text.clone(),
            detail: format!("{} sentences", sentences.len()),
        });
    }
    for sentence in sentences {
        out.extend(check_sentence(lexicon, sentence));
    }
    out
}
