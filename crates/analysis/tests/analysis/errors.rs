//! The error enum of the publish step.

use ghidorah_analysis::AnalysisError;
use ghidorah_db::codec::tables_from_json;
use ghidorah_db::{EditError, Invalid, TxError};
use ghidorah_json::Value;

#[test]
fn analysis_errors_convert_and_show() {
    let codec = tables_from_json(&Value::Null).expect_err("null is not a set");
    let all = [
        AnalysisError::from(codec),
        AnalysisError::from(TxError::Poisoned),
        AnalysisError::from(EditError::Poisoned),
        AnalysisError::from(Invalid::EmptyName),
    ];
    let prefixes = [
        "The analysis set does not decode",
        "The publish transaction fails",
        "The analysis edit fails",
        "A value of the analysis set is not valid",
    ];
    for (e, prefix) in all.iter().zip(prefixes) {
        let text = e.to_string();
        assert!(text.starts_with(prefix), "{text}");
        let _: &dyn std::error::Error = e;
    }
    assert!(matches!(all[1], AnalysisError::Tx(TxError::Poisoned)));
}
