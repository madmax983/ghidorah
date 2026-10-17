//! The native semantic vectors of `tests/golden/semantics/x86` (AC-069a, AC-069b, AC-208).
//!
//! Each form lifts once. Each vector sets the registers, the flags and the buffer, runs the
//! L0 interpreter and compares the registers, the defined flags and the buffer with the
//! host CPU result.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ghidorah_base::Fuel;
use ghidorah_ir::{Arena, Builder, Config, FlatImage, Interp, Loc, Opc, StopReason};
use ghidorah_x86::lift::{self, ROWS, Template};
use ghidorah_x86::{Insn, Mnem, Operand, lift as lift_insn};

use crate::common::{dec, hex, root};
use crate::json::{self, Json};

/// The status flags of the flags word.
const STATUS: u128 = 0x8d5;

/// One vector.
#[derive(Debug, Clone)]
pub struct Vector {
    pub inputs: Vec<u128>,
    pub outputs: Vec<u128>,
    pub mem_in: Vec<u8>,
    pub mem_out: Vec<u8>,
}

/// One form of a vector file with its vectors.
#[derive(Debug, Clone)]
pub struct Form {
    pub file: String,
    pub name: String,
    pub row: String,
    pub w: u64,
    pub bytes: Vec<u8>,
    pub kind: String,
    pub regs: Vec<String>,
    pub mem: usize,
    pub ip: u64,
    pub base: u64,
    pub fill: u64,
    pub vectors: Vec<Vector>,
}

fn dir() -> PathBuf {
    root().join("tests/golden/semantics/x86")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    if text.is_empty() {
        Vec::new()
    } else {
        hex(text)
    }
}

fn parse_file(file: &str, text: &str) -> Vec<Form> {
    let mut out: Vec<Form> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            assert!(line.starts_with("{\"golden\":"), "{file}: the header line");
            continue;
        }
        let v = json::parse(line);
        if let Some(name) = v.opt("form") {
            out.push(Form {
                file: file.to_owned(),
                name: name.str().to_owned(),
                row: v.get("row").str().to_owned(),
                w: v.get("w").u64(),
                bytes: hex_bytes(v.get("bytes").str()),
                kind: v.get("kind").str().to_owned(),
                regs: v
                    .get("regs")
                    .arr()
                    .iter()
                    .map(|r| r.str().to_owned())
                    .collect(),
                mem: usize::try_from(v.get("mem").u64()).expect("size"),
                ip: u64::try_from(v.get("ip").hex()).expect("ip"),
                base: u64::try_from(v.get("base").hex()).expect("base"),
                fill: u64::try_from(v.get("fill").hex()).expect("fill"),
                vectors: Vec::new(),
            });
            continue;
        }
        let form = out
            .last_mut()
            .unwrap_or_else(|| panic!("{file}:{}: a vector before a form", i + 1));
        let values = |key: &str| v.get(key).arr().iter().map(Json::hex).collect::<Vec<_>>();
        form.vectors.push(Vector {
            inputs: values("in"),
            outputs: values("out"),
            mem_in: v
                .opt("mem_in")
                .map(|m| hex_bytes(m.str()))
                .unwrap_or_default(),
            mem_out: v
                .opt("mem_out")
                .map(|m| hex_bytes(m.str()))
                .unwrap_or_default(),
        });
    }
    out
}

/// Reads every vector file, sorted by file name.
pub fn forms() -> &'static [Form] {
    ghidorah_testkit::fixture::cached("x86_semantic_vectors", || {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir())
            .map(|d| d.map(|e| e.expect("directory entry").path()).collect())
            .unwrap_or_default();
        paths.retain(|p| p.extension().is_some_and(|x| x == "jsonl"));
        paths.sort();
        paths
            .iter()
            .flat_map(|p| {
                let file = p.file_stem().expect("stem").to_string_lossy().into_owned();
                parse_file(
                    &file,
                    &std::fs::read_to_string(p).expect("read a vector file"),
                )
            })
            .collect::<Vec<_>>()
    })
}

/// Gives the location of a vector register, or `None` for `pc`.
fn loc_of(name: &str) -> Option<Loc> {
    const GPR: [&str; 15] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14",
    ];
    if name == "flags" {
        return Some(Loc::Flags);
    }
    if let Some(n) = GPR.iter().position(|g| *g == name) {
        return Loc::gpr(u8::try_from(n).expect("number"));
    }
    let n: u8 = name.strip_prefix("xmm")?.parse().ok()?;
    Loc::xmm(n)
}

/// Gives the count of a shift or a double shift, from an immediate or from `cl`.
fn shift_count(insn: &Insn, form: &Form, v: &Vector) -> Option<u64> {
    let slot = if matches!(insn.mnem(), Mnem::Shld | Mnem::Shrd) {
        2
    } else {
        1
    };
    match insn.op(slot)? {
        Operand::Imm { value, .. } => Some(value.cast_unsigned()),
        Operand::Reg { .. } => {
            let i = form.regs.iter().position(|r| r == "rcx")?;
            Some(u64::try_from(v.inputs[i] & 0xff).expect("byte"))
        }
        _ => None,
    }
}

/// Gives the status flags that the hardware leaves undefined for one vector.
fn undefined(insn: &Insn, form: &Form, v: &Vector) -> u128 {
    let mut mask = u128::from(insn.flags_undefined().to_eflags());
    if matches!(insn.mnem(), Mnem::Shl | Mnem::Shr)
        && let Some(n) = shift_count(insn, form, v)
    {
        // A count of the operand width or more leaves CF undefined.
        let masked = n & if form.w == 64 { 63 } else { 31 };
        if masked >= form.w {
            mask |= 1;
        }
    }
    mask
}

/// Lifts the instruction of a form at its address.
pub fn lift_form(form: &Form) -> (Insn, Arena) {
    let insn = dec(&form.bytes, form.ip).unwrap_or_else(|e| panic!("{}: decode: {e}", form.name));
    assert_eq!(
        insn.mnem().name(),
        form.row,
        "{}: the decoded mnemonic",
        form.name
    );
    let mut b = Builder::new();
    lift_insn(&insn, &mut b).unwrap_or_else(|e| panic!("{}: lift: {e}", form.name));
    (insn, b.finish())
}

/// Runs one vector. Gives a mismatch message or `None`.
fn replay_one(form: &Form, insn: &Insn, arena: &Arena, v: &Vector) -> Option<String> {
    if v.mem_in.len() != form.mem || v.mem_out.len() != form.mem {
        return Some(format!(
            "a buffer of {} bytes, not {}",
            v.mem_in.len(),
            form.mem
        ));
    }
    let image = FlatImage::new(form.base, v.mem_in.clone(), true);
    let mut interp = Interp::new(arena, &image, Config::default());
    for n in 0u8..16 {
        interp.set_loc(Loc::Reg(u16::from(n)), u128::from(form.fill + u64::from(n)));
    }
    for (reg, value) in form.regs.iter().zip(&v.inputs) {
        if let Some(loc) = loc_of(reg) {
            let value = if loc == Loc::Flags {
                value & STATUS
            } else {
                *value
            };
            interp.set_loc(loc, value);
        }
    }
    let stop = interp.run(form.ip, &mut Fuel::new(10_000));
    let pc = form
        .regs
        .iter()
        .position(|r| r == "pc")
        .map(|i| u64::try_from(v.outputs[i]).expect("pc"));
    let next = insn.next_addr();
    let expected = match form.kind.as_str() {
        "plain" => StopReason::NoCode(next),
        "branch" => StopReason::NoCode(pc.unwrap_or(next)),
        "call" => StopReason::CallUnresolved(pc.unwrap_or(next)),
        _ => StopReason::Returned,
    };
    if stop.reason != expected {
        return Some(format!("stop {:?}, expected {expected:?}", stop.reason));
    }
    let undef = undefined(insn, form, v);
    for (i, reg) in form.regs.iter().enumerate() {
        let Some(loc) = loc_of(reg) else { continue };
        let (got, want) = (interp.loc(loc), v.outputs[i]);
        let ok = if loc == Loc::Flags {
            (got ^ want) & STATUS & !undef == 0
        } else {
            got == want
        };
        if !ok {
            return Some(format!(
                "{reg}: got {got:#x}, want {want:#x}, in {:x?}",
                v.inputs
            ));
        }
    }
    for n in 0u8..15 {
        let name = loc_name(n);
        if !form.regs.iter().any(|r| r == name) {
            let got = interp.loc(Loc::Reg(u16::from(n)));
            if got != u128::from(form.fill + u64::from(n)) {
                return Some(format!("{name} changes to {got:#x}"));
            }
        }
    }
    for (i, want) in v.mem_out.iter().enumerate() {
        let at = form.base + u64::try_from(i).expect("offset");
        if interp.read(at) != Some(*want) {
            return Some(format!(
                "byte {i}: got {:?}, want {want:#x}",
                interp.read(at)
            ));
        }
    }
    None
}

fn loc_name(n: u8) -> &'static str {
    [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14",
    ][usize::from(n)]
}

/// Replays every vector of a form. Gives the failure messages.
pub fn replay(form: &Form) -> Vec<String> {
    let (insn, arena) = lift_form(form);
    form.vectors
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            replay_one(form, &insn, &arena, v).map(|m| format!("{} #{i}: {m}", form.name))
        })
        .collect()
}

/// Gives the template of a form row.
fn template_of(row: &str) -> Option<Template> {
    lift::row(Mnem::from_name(row)?).map(|r| r.template)
}

#[test]
fn ac_069a_semantic_vectors() {
    let forms = forms();
    assert!(forms.len() >= 300, "only {} forms", forms.len());
    let mut failures = Vec::new();
    let mut counts: BTreeMap<(String, u64), usize> = BTreeMap::new();
    for form in forms {
        failures.extend(replay(form).into_iter().take(3));
        *counts.entry((form.row.clone(), form.w)).or_default() += form.vectors.len();
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let small: Vec<_> = counts.iter().filter(|(_, n)| **n < 64).collect();
    assert!(
        small.is_empty(),
        "rows with fewer than 64 vectors at a width: {small:?}"
    );
}

#[test]
fn ac_069b_every_row_has_vectors() {
    let rows_with_vectors: BTreeSet<&str> = forms().iter().map(|f| f.row.as_str()).collect();
    let missing: Vec<&str> = ROWS
        .iter()
        .map(|r| r.mnem.name())
        .filter(|m| !rows_with_vectors.contains(m))
        .collect();
    assert!(missing.is_empty(), "rows without vectors: {missing:?}");
    let orphans: Vec<&str> = rows_with_vectors
        .iter()
        .copied()
        .filter(|m| template_of(m).is_none())
        .collect();
    assert!(
        orphans.is_empty(),
        "vector rows outside the table: {orphans:?}"
    );
    for form in forms() {
        assert_eq!(
            Some(form.file.as_str()),
            template_of(&form.row).map(Template::name),
            "{}: the file of the template",
            form.name
        );
    }
}

#[test]
fn ac_208_sse_subset() {
    let sse: Vec<&Form> = forms()
        .iter()
        .filter(|f| {
            matches!(
                template_of(&f.row),
                Some(Template::SseMove | Template::SseZero)
            )
        })
        .collect();
    assert!(sse.len() >= 30, "only {} SSE forms", sse.len());
    let allowed = [
        Opc::Get,
        Opc::Put,
        Opc::Load,
        Opc::Store,
        Opc::Copy,
        Opc::ZExt,
        Opc::Trunc,
        Opc::Insert,
    ];
    for form in &sse {
        let (insn, arena) = lift_form(form);
        let opcs: BTreeSet<Opc> = arena.ops().iter().map(|op| op.opc).collect();
        assert!(
            opcs.iter().all(|o| allowed.contains(o)),
            "{}: {opcs:?}",
            form.name
        );
        let mem = insn.mem().map(|m| m.access);
        match mem {
            Some(a) if a.writes() => assert!(opcs.contains(&Opc::Store), "{}: a store", form.name),
            Some(_) => assert!(opcs.contains(&Opc::Load), "{}: a load", form.name),
            None if form.w == 128 && template_of(&form.row) == Some(Template::SseMove) => {
                assert!(opcs.contains(&Opc::Copy), "{}: a copy", form.name);
            }
            None => {}
        }
        let failures = replay(form);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
