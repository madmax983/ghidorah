//! The budget writer: K6 trim, copies and section weights.

use ghidorah_json::Value;
use ghidorah_testkit::pbt;
use ghidorah_tools::ContentMode;
use ghidorah_tools::budget::{
    Budget, PROTOCOL_RESERVE, fit_items, section_weight, split_by_weight, split_even,
};
use ghidorah_tools::content::{cost, result_chars};

use crate::common::{chars, run_mode, text};
use crate::test_registry::TestHost;

fn items(envelope: &Value) -> &[Value] {
    envelope
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
}

fn list_args(max_chars: u64) -> String {
    format!(r#"{{"count":300,"limit":300,"max_chars":{max_chars}}}"#)
}

#[test]
fn budget_trim_at_item_boundary() {
    let mut host = TestHost::default();
    let full = run_mode(
        &mut host,
        "item_list",
        &list_args(60_000),
        ContentMode::Plain,
    );
    let all = items(&full);
    assert_eq!(all.len(), 300, "{}", text(&full));
    for max in [1_000_u64, 2_500, 5_000, 9_000, 20_000] {
        let envelope = run_mode(&mut host, "item_list", &list_args(max), ContentMode::Plain);
        let limit = max - PROTOCOL_RESERVE;
        let size = chars(&text(&envelope)) as u64;
        assert!(size <= limit, "{size} > {limit}");
        let kept = items(&envelope);
        let k = kept.len();
        assert!(k > 0 && k < all.len(), "{k} items at {max}");
        assert_eq!(
            kept,
            &all[..k],
            "the kept items are a prefix of whole items"
        );
        assert_eq!(
            envelope.pointer("/page/truncated"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            envelope.pointer("/page/total").and_then(Value::as_u64),
            Some(300)
        );
        assert_eq!(
            envelope.pointer("/page/returned").and_then(Value::as_u64),
            Some(k as u64)
        );
        let cursor = envelope
            .pointer("/page/next_cursor")
            .and_then(Value::as_str);
        let last = kept[k - 1]
            .get("addr")
            .and_then(Value::as_str)
            .expect("an addr");
        assert_eq!(cursor, Some(format!("c:0:{last}").as_str()));
        // One more item does not fit (K6 gives the largest prefix).
        let mut bigger = envelope.clone();
        let next_addr = all[k].get("addr").and_then(Value::as_str).expect("an addr");
        if let Some(Value::Array(list)) = bigger
            .as_object_mut()
            .and_then(|o| o.get_mut("data"))
            .and_then(|d| d.as_object_mut())
            .and_then(|d| d.get_mut("items"))
        {
            list.push(all[k].clone());
        }
        if let Some(page) = bigger
            .as_object_mut()
            .and_then(|o| o.get_mut("page"))
            .and_then(Value::as_object_mut)
        {
            page.insert(
                "returned",
                Value::from(ghidorah_json::Number::parse(&(k + 1).to_string()).expect("n")),
            );
            page.insert("next_cursor", Value::from(format!("c:0:{next_addr}")));
        }
        assert!(
            chars(&text(&bigger)) as u64 > limit,
            "one more item fits at {max}"
        );
    }
    let tiny = run_mode(&mut host, "item_list", &list_args(200), ContentMode::Plain);
    assert!(chars(&text(&tiny)) as u64 <= 200, "{}", text(&tiny));
}

#[test]
fn envelope_budget_halves_in_both_mode() {
    let max = 12_000;
    let mut host = TestHost::default();
    let structured = run_mode(
        &mut host,
        "item_list",
        &list_args(max),
        ContentMode::Structured,
    );
    let both = run_mode(&mut host, "item_list", &list_args(max), ContentMode::Both);
    let (one, two) = (items(&structured).len(), items(&both).len());
    assert!(
        two * 2 <= one + 2,
        "{two} items in both mode, {one} in structured mode"
    );
    assert!(
        two * 5 >= one * 2,
        "{two} items in both mode, {one} in structured mode"
    );
    assert!(chars(&text(&both)) as u64 * 2 <= max);
    assert!(result_chars(&both, false, ContentMode::Both) <= max - PROTOCOL_RESERVE);
    assert!(result_chars(&structured, false, ContentMode::Structured) <= max - PROTOCOL_RESERVE);
    for mode in ContentMode::ALL {
        let envelope = run_mode(&mut host, "item_list", &list_args(max), mode);
        assert!(
            result_chars(&envelope, false, mode) <= max - PROTOCOL_RESERVE,
            "{mode:?}"
        );
        assert!(!items(&envelope).is_empty());
    }
    assert_eq!(
        Budget::new(max, ContentMode::Both).envelope_chars(),
        (max - PROTOCOL_RESERVE) / 2
    );
    assert_eq!(
        Budget::new(max, ContentMode::Text).envelope_chars(),
        max - PROTOCOL_RESERVE
    );
    assert_eq!(Budget::new(100, ContentMode::Plain).limit(), 0);
}

#[test]
fn fit_items_matches_brute_force() {
    pbt::check("fit_items_matches_brute_force", 200, |g| {
        let n = usize::try_from(g.range(0, 12)).expect("small");
        let items: Vec<String> = (0..n)
            .map(|_| {
                let len = usize::try_from(g.range(0, 30)).expect("small");
                let quotes = usize::try_from(g.range(0, 4)).expect("small");
                format!("{}{}", "a".repeat(len), "\"".repeat(quotes))
            })
            .collect();
        let overhead = g.range(0, 50);
        let limit = g.range(0, 400);
        let mode = *g.pick(&ContentMode::ALL).expect("a mode");
        let got = fit_items(&items, overhead, limit, mode);
        let sep = mode.copies();
        let mut want = 0;
        for k in 1..=n {
            let sum: u64 = items[..k].iter().map(|i| cost(i, mode)).sum();
            if overhead + sum + sep * (k as u64 - 1) <= limit {
                want = k;
            }
        }
        if got == want {
            Ok(())
        } else {
            Err(format!("got {got}, want {want}"))
        }
    });
}

#[test]
fn section_split_by_weight() {
    assert_eq!(section_weight("decomp"), 6);
    assert_eq!(section_weight("disasm"), 3);
    assert_eq!(section_weight("ir"), 3);
    assert_eq!(section_weight("callers"), 1);
    assert_eq!(
        split_by_weight(1_200, &[6, 3, 3], &[10_000, 10_000, 10_000]),
        vec![600, 300, 300]
    );
    assert_eq!(
        split_by_weight(1_200, &[6, 3, 3], &[100, 10_000, 10_000]),
        vec![100, 550, 550]
    );
    assert_eq!(split_by_weight(1_000, &[1, 1], &[10, 20]), vec![10, 20]);
    assert_eq!(split_by_weight(1_000, &[0, 0], &[10, 20]), vec![0, 0]);
    assert_eq!(split_by_weight(1_000, &[1], &[]), Vec::<u64>::new());
    assert_eq!(split_even(10, 3), vec![4, 3, 3]);
    assert_eq!(split_even(0, 2), vec![0, 0]);
    assert_eq!(split_even(5, 0), Vec::<u64>::new());
}
