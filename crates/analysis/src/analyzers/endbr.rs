//! `EndbrSeeds` (band 440): a function at each free `endbr64` head (design Section 7.3).
//!
//! The scan reads the executable sections named `.text`, or every executable region of a file
//! with no section headers. Each `f3 0f 1e fa` that no code unit holds gets the start reason
//! `Endbr` with confidence 85 and `R_ENDBR_HEAD`. A head after a call to a `setjmp`-like
//! function is in a code unit of its body. So is a jump target in a body. Neither head is a
//! seed. A head in the PLT area starts a stub, not a function.

use ghidorah_base::Limits;
use ghidorah_db::{Program, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Perms;

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The bytes of `endbr64`.
pub const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// The bytes of the scan that cost one work unit.
const BYTES_PER_UNIT: u64 = 64;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::EndbrSeeds,
    name: "EndbrSeeds",
    priority: 440,
    triggers: &[Trigger::Bytes, Trigger::Instructions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each endbr64 head that no body holds.",
};

/// Gives the ranges of the scan: the executable `.text` sections, or every executable region
/// when the file has no section headers.
fn scope(program: &Program) -> RangeSet {
    let mut out = RangeSet::new();
    let sections = &program.binary().sections;
    if sections.is_empty() {
        for r in program.mem().regions() {
            if r.perms.contains(Perms::EXECUTE) {
                out.insert(r.va);
            }
        }
        return out;
    }
    for s in sections {
        if let Some(va) = s.va
            && s.name.as_str() == Some(".text")
            && is_exec(program, va.first)
        {
            out.insert(va);
        }
    }
    out
}

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    let mut heads = Vec::new();
    for r in scope(program).intersect(ranges).ranges() {
        let Ok(len) = u64::try_from(r.len()) else {
            continue;
        };
        work = work.saturating_add(len / BYTES_PER_UNIT);
        let Ok(bytes) = program.mem().read(r.first, len, &Limits::DEFAULT) else {
            continue;
        };
        for (i, w) in bytes.windows(ENDBR64.len()).enumerate() {
            if w == ENDBR64
                && let Some(at) = u64::try_from(i).ok().and_then(|i| r.first.checked_add(i))
            {
                heads.push(at);
            }
        }
    }
    for at in heads {
        work = work.saturating_add(1);
        if ctx.is_entry(at) || ctx.owner(at).is_some() || ctx.in_plt(at) {
            continue;
        }
        let _ = ctx.add_reason(at, StartReason::Endbr, 85, Why::bare(Rule::EndbrHead));
    }
    Step { work }
}
