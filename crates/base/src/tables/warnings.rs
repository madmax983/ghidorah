//! The catalog data of `WarningCode` (design Section 10.8).

use crate::catalog::{CodeInfo, RepairClass, WarningCode};

use RepairClass::{Choice as C, Helper as H, None as N, Repair as R};

/// Makes one catalog row.
const fn row(
    code: WarningCode,
    name: &'static str,
    class: RepairClass,
    retry: bool,
    message: &'static str,
    hint: &'static str,
) -> CodeInfo {
    CodeInfo {
        num: code as u16,
        name,
        class,
        retry,
        message,
        hint,
    }
}

/// Gives the catalog data of `code`.
#[expect(clippy::too_many_lines, reason = "one arm per frozen code")]
pub(crate) const fn info(code: WarningCode) -> CodeInfo {
    use WarningCode as W;
    match code {
        W::Coerced => row(
            code,
            "W_COERCED",
            N,
            false,
            "The server changed an argument to the type of the schema. The call ran with the changed value.",
            "Send the value in the type of the schema.",
        ),
        W::ArchUnsupported => row(
            code,
            "W_ARCH_UNSUPPORTED",
            N,
            false,
            "The ELF machine is not x86-64. Only the survey tools work on this binary.",
            "The survey tools are binary_survey and search.",
        ),
        W::NotDemangled => row(
            code,
            "W_NOT_DEMANGLED",
            N,
            false,
            "The result holds a mangled name. This version shows mangled names in their raw form.",
            "Read the raw name as the symbol of the compiler.",
        ),
        W::JournalTailDiscarded => row(
            code,
            "W_JOURNAL_TAIL_DISCARDED",
            N,
            false,
            "The server dropped the last journal line. The line was not complete, because the process stopped during a commit.",
            "Do the last edit again when it is missing.",
        ),
        W::AgentOverrideConflict => row(
            code,
            "W_AGENT_OVERRIDE_CONFLICT",
            C,
            false,
            "The analysis disagrees with an agent override. The override stays, and the details hold the analysis value.",
            "Call history_undo or func_edit to change the override.",
        ),
        W::FactOrphaned => row(
            code,
            "W_FACT_ORPHANED",
            H,
            false,
            "An agent fact lost its function. The fact stays at its address as a label or a comment.",
            "Call func_edit with the action create to make the function again.",
        ),
        W::StaleOpId => row(
            code,
            "W_STALE_OP_ID",
            N,
            false,
            "The op ID comes from another lifter version. The op at this ID can be different now.",
            "Get the IR again for the current op IDs.",
        ),
        W::UngroundedFinding => row(
            code,
            "W_UNGROUNDED_FINDING",
            H,
            false,
            "The finding has no evidence and no claim. Other agents cannot check it.",
            "Call note_write with evidence for the finding.",
        ),
        W::NoreturnSuspect => row(
            code,
            "W_NORETURN_SUSPECT",
            H,
            false,
            "A call has an unsafe fall-through. The callee can be a function that does not return.",
            "Call func_edit with the action set_noreturn when the callee does not return.",
        ),
        W::NoreturnAssumed => row(
            code,
            "W_NORETURN_ASSUMED",
            N,
            false,
            "Only the known list marks the callee as noreturn. The analysis found no other evidence.",
            "Check the callee with func_get.",
        ),
        W::JumptableUnresolved => row(
            code,
            "W_JUMPTABLE_UNRESOLVED",
            H,
            false,
            "The jump table has no targets. Method A did not find the bounds of the table.",
            "Call func_edit with the action set_jumptable and the case addresses.",
        ),
        W::IndirectCallUnresolved => row(
            code,
            "W_INDIRECT_CALL_UNRESOLVED",
            H,
            false,
            "An indirect call or jump has no targets. The analysis cannot find the target.",
            "Call func_edit with the action set_call_targets.",
        ),
        W::LiftUnsupported => row(
            code,
            "W_LIFT_UNSUPPORTED",
            N,
            false,
            "An instruction lifts to an intrinsic op. The lifter has no template for it, so the view shows only its def and use sets.",
            "Read the disassembly row of the instruction.",
        ),
        W::SpMismatch => row(
            code,
            "W_SP_MISMATCH",
            N,
            false,
            "The tracked stack pointer differs from the CFA. The stack depth at this point can be wrong.",
            "Check the frame in the disassembly of func_get.",
        ),
        W::BudgetFlat => row(
            code,
            "W_BUDGET_FLAT",
            N,
            false,
            "The decompiler used the FLAT form. The structurer ran out of fuel.",
            "Send the call again with a higher max_steps.",
        ),
        W::StructureSelfcheck => row(
            code,
            "W_STRUCTURE_SELFCHECK",
            N,
            false,
            "The decompiler self-check failed. The structured text can differ from the control flow.",
            "Read the disassembly to check the control flow.",
        ),
        W::AnalysisStale => row(
            code,
            "W_ANALYSIS_STALE",
            R,
            false,
            "The read used the committed analysis set. A shadow analysis runs, so the result can change.",
            "Call analysis_run to complete the analysis.",
        ),
        W::TimeStop => row(
            code,
            "W_TIME_STOP",
            R,
            true,
            "A max_ms guard stopped the work. The result depends on the time, so it is not deterministic.",
            "Send the same call again.",
        ),
    }
}
