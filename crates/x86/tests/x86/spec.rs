//! AC-061: the spec vectors of `tests/data/x86_spec.txt`.

use ghidorah_x86::{DecodeError, length};

use crate::common::{SPEC_ADDR, SpecLine, dec, ops_text, spec_lines};

fn error_len(e: DecodeError) -> u8 {
    match e {
        DecodeError::Truncated { need_at_least, .. } => need_at_least,
        DecodeError::Invalid { len_consumed, .. } => len_consumed,
        DecodeError::InvalidInMode { len } | DecodeError::Unsupported { len, .. } => len,
    }
}

fn check(v: &SpecLine) -> Result<(), String> {
    let got = dec(&v.bytes, SPEC_ADDR);
    if v.is_error() {
        let e = match got {
            Ok(insn) => return Err(format!("decodes as {:?}", insn.mnem())),
            Err(e) => e,
        };
        let kind = format!("!{}", e.kind());
        if kind != v.mnem || error_len(e) != v.len {
            return Err(format!("gives {e:?}"));
        }
        return Ok(());
    }
    let insn = got.map_err(|e| format!("fails: {e:?}"))?;
    let found = format!(
        "{}|{}|{}|{}",
        insn.mnem().name(),
        ops_text(&insn),
        insn.len(),
        insn.flow().name()
    );
    let want = format!("{}|{}|{}|{}", v.mnem, v.ops, v.len, v.flow);
    if found != want {
        return Err(format!("gives {found}, wants {want}"));
    }
    if length(&v.bytes) != Ok(insn.len()) {
        return Err(format!("length gives {:?}", length(&v.bytes)));
    }
    Ok(())
}

#[test]
fn ac_061_decoder_spec_vectors() {
    let lines = spec_lines();
    assert!(lines.len() >= 400, "the spec has {} vectors", lines.len());
    let failures: Vec<String> = lines
        .iter()
        .filter_map(|v| {
            check(v).err().map(|e| {
                let bytes: Vec<String> = v.bytes.iter().map(|b| format!("{b:02x}")).collect();
                format!("line {} ({}): {e}", v.line, bytes.join(" "))
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} spec vectors fail:\n{}",
        failures.len(),
        lines.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn spec_covers_every_flow_kind() {
    let lines = spec_lines();
    for flow in ["seq", "jmp", "jcc", "call", "icall", "ijmp", "ret", "trap"] {
        assert!(
            lines.iter().any(|v| v.flow == flow),
            "no spec vector has the flow {flow}"
        );
    }
    for kind in ["!truncated", "!invalid", "!invalid_in_mode", "!unsupported"] {
        assert!(
            lines.iter().any(|v| v.mnem == kind),
            "no spec vector has the error {kind}"
        );
    }
}
