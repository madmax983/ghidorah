//! The catalog data of `ErrorCode` (design Section 10.8).
//!
//! Each message has the form "What failed. Why. Action." in STE (AC-024).
//!
//! The server drops each hint sentence that names a tool outside the active profile. So a
//! hint with a sentence that names a tool also has a sentence that names no tool.

use crate::catalog::{CodeInfo, ErrorCode, RepairClass};

use RepairClass::{Choice as C, Helper as H, None as N, Repair as R, RepairWhen as RW};

/// Makes one catalog row.
const fn row(
    code: ErrorCode,
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
        plain: hint,
    }
}

/// Gives the catalog data of `code`.
#[expect(clippy::too_many_lines, reason = "one arm per frozen code")]
pub(crate) const fn info(code: ErrorCode) -> CodeInfo {
    use ErrorCode as E;
    match code {
        E::InvalidArgument => row(
            code,
            "INVALID_ARGUMENT",
            N,
            false,
            "The argument {field} has a value that is not valid. The value has the wrong type or is out of range. Send a value that matches details.expected.",
            "Read details.expected for the type and the range.",
        ),
        E::UnknownArgument => row(
            code,
            "UNKNOWN_ARGUMENT",
            R,
            false,
            "The argument {field} is not in the schema of the tool. The tool accepts only the arguments of its schema. Rename or remove the argument.",
            "Send next[0]. It renames or removes the argument, or it gets the schema of the tool.",
        )
        .with_plain("The schema of the tool in tools/list holds the argument names."),
        E::MissingArgument => row(
            code,
            "MISSING_ARGUMENT",
            H,
            false,
            "The required argument {field} is missing. The tool cannot run without it. Add the argument to the call.",
            "Call next[0] to get the schema and an example.",
        )
        .with_plain("The schema of the tool in tools/list holds the required arguments."),
        E::UnknownTool => row(
            code,
            "UNKNOWN_TOOL",
            H,
            false,
            "The tool {tool} does not exist. No tool in the registry has this name. Use a name from the candidates.",
            "Call next[0] to search the tools.",
        )
        .with_plain("Use a tool name from tools/list."),
        E::ToolNotInProfile => row(
            code,
            "TOOL_NOT_IN_PROFILE",
            H,
            false,
            "The tool {tool} is not available here. The tool is outside the active profile, or the batch step is destructive. Read details.reason.",
            "Send next[0]. For not_in_profile, the server runs {profile}. Start it again with --profile full or a wider --tools list.",
        )
        .with_plain("The server runs {profile}. Start it again with --profile full or a wider --tools list."),
        E::AddressInvalid => row(
            code,
            "ADDRESS_INVALID",
            RW,
            false,
            "The address text does not parse. It does not match the address grammar, or the integer is 2^53 or more. Send the address as a 0x hex string.",
            "Send next[0] when it exists.",
        )
        .with_plain("An address is a 0x hex string, a symbol or an ID."),
        E::AddressUnmapped => row(
            code,
            "ADDRESS_UNMAPPED",
            C,
            false,
            "The address is not in a memory region of the binary. The binary has no bytes at this address. Use an address from the candidates.",
            "The candidates hold the nearest addresses in a region.",
        )
        .with_plain("Call binary_survey to see the memory regions of the binary."),
        E::AddressBaseAmbiguous => row(
            code,
            "ADDRESS_BASE_AMBIGUOUS",
            C,
            false,
            "The address text has only digits. It can be a decimal value or a hex value, and the server does not guess. Use a candidate value.",
            "Send a 0x hex string or a JSON integer.",
        ),
        E::AmbiguousName => row(
            code,
            "AMBIGUOUS_NAME",
            C,
            false,
            "The name matches more than one entity. The server does not pick a match. Use a candidate value.",
            "Each candidate value is a sym: form or a name@0x form.",
        )
        .with_plain("Send the name as a sym: form or a name@0x form."),
        E::NotFound => row(
            code,
            "NOT_FOUND",
            C,
            false,
            "The {kind} does not exist. No entity of this kind has this ID or name. Use a candidate value or search for the entity.",
            "The candidates hold the closest names.",
        )
        .with_plain("Call search to find the entity by name or by kind."),
        E::UnknownBinary => row(
            code,
            "UNKNOWN_BINARY",
            RW,
            false,
            "The binary_id is not open in this session. The session has no binary with this ID. Use a candidate binary_id.",
            "Send next[0] when it exists. It opens the project of the binary.",
        )
        .with_plain(
            "Use the binary_id of an open binary. Load the binary again with binary_load.",
        ),
        E::BinaryRequired => row(
            code,
            "BINARY_REQUIRED",
            R,
            false,
            "The call names no binary, and more than one binary is open. The server cannot select a binary for the call. Add binary_id to the call.",
            "Send next[0]. It uses the most recent binary_id.",
        )
        .with_plain("Add the binary_id of an open binary to the call."),
        E::PathOutsideRoot => row(
            code,
            "PATH_OUTSIDE_ROOT",
            N,
            false,
            "The path is outside the roots of the server. The server reads files only under its roots. Use a path under a root of details.roots.",
            "Start the server with a root option for the directory.",
        ),
        E::FileUnreadable => row(
            code,
            "FILE_UNREADABLE",
            N,
            false,
            "The server cannot read the file. The file does not exist, or the process has no read access. Make sure that the path is correct.",
            "Make sure that the file exists and that the process can read it.",
        ),
        E::UnsupportedFormat => row(
            code,
            "UNSUPPORTED_FORMAT",
            N,
            false,
            "The server does not support the file format. The probe found a format outside the MVP list. Read details.detected and details.supported.",
            "Load an ELF64 x86-64 file, a PE32+ AMD64 file or a raw blob.",
        ),
        E::UnsupportedArch => row(
            code,
            "UNSUPPORTED_ARCH",
            N,
            false,
            "The binary has no x86-64 code. Code features work only on x86-64 binaries. Use the survey tools for this binary.",
            "The tools binary_survey and search work on every binary.",
        ),
        E::FormatMalformed => row(
            code,
            "FORMAT_MALFORMED",
            N,
            false,
            "The parser cannot read the main header of the file. The magic value is wrong, or the header is not complete. Read details.diagnostic.",
            "Use file_format raw to load the file as a raw blob.",
        ),
        E::CursorInvalid => row(
            code,
            "CURSOR_INVALID",
            R,
            false,
            "The cursor is not valid. It does not decode, it fails its check or it belongs to another query. Send next[0] to start at the first page.",
            "Send next[0]. It is the call without the cursor.",
        )
        .with_plain("Send the call again without the cursor."),
        E::CursorStale => row(
            code,
            "CURSOR_STALE",
            R,
            false,
            "The cursor is stale. The sort key of its boundary item changed. Send next[0] to start at the first page.",
            "Send next[0]. It is the call without the cursor.",
        )
        .with_plain("Send the call again without the cursor."),
        E::Conflict => row(
            code,
            "CONFLICT",
            H,
            true,
            "The call conflicts with the current state. The expected_rev differs from the current rev, or a later transaction changed the same facts. Read the later edits before you send the call again.",
            "Send next[0] to read the later edits. The candidates hold the call with the current rev or the later transactions.",
        )
        .with_plain("Call history_list to read the later edits. Read rev in this result. Send the call again with that rev as expected_rev."),
        E::BlockedByHigherPrioritySource => row(
            code,
            "BLOCKED_BY_HIGHER_PRIORITY_SOURCE",
            N,
            false,
            "The write has a lower rank than the current fact. A source with a higher rank owns the fact. Read details.current and details.source.",
            "Add force true only when the change is correct.",
        ),
        E::BodyOverlap => row(
            code,
            "BODY_OVERLAP",
            N,
            false,
            "The new function body overlaps another function. Two function bodies cannot share an address. Change or delete the other function first.",
            "The candidates name the owner function.",
        )
        .with_plain(
            "Call addr_info to find the owner function. Change or delete the owner function first.",
        ),
        E::NotInFunction => row(
            code,
            "NOT_IN_FUNCTION",
            N,
            false,
            "The address is not in a function. The call needs an address inside a function body. Use an address in a function.",
            "Use an address inside a function body. Call func_edit with the action create to make a function.",
        ),
        E::CParseError => row(
            code,
            "C_PARSE_ERROR",
            N,
            false,
            "The C text does not parse. The parser found the errors in details.errors. Change the text at each error location.",
            "Each error gives the line, the column and the expected tokens.",
        ),
        E::NothingToUndo => row(
            code,
            "NOTHING_TO_UNDO",
            N,
            false,
            "The undo found no transaction. The scope has no transaction in the applied state. Call history_list to see the transactions.",
            "Use the session value * for a wider scope.",
        )
        .with_plain("The scope of every session has no applied transaction."),
        E::LimitExceeded => row(
            code,
            "LIMIT_EXCEEDED",
            R,
            false,
            "A list or a value is above its cap. The tool accepts at most the cap. Send next[0], which clamps the value to the cap.",
            "Split a long list into more calls.",
        ),
        E::BadReference => row(
            code,
            "BAD_REFERENCE",
            C,
            false,
            "A batch reference does not resolve. The path is missing, its type is wrong or its source page is not complete. Use a path from the candidates.",
            "Read details.source_truncated.",
        ),
        E::SkippedDependency => row(
            code,
            "SKIPPED_DEPENDENCY",
            N,
            false,
            "The batch skips this step. The step refers to a step that failed. Read details.failed_step.",
            "Correct the failed step first.",
        ),
        E::ExpectFailed => row(
            code,
            "EXPECT_FAILED",
            N,
            false,
            "A batch guard failed. The actual value does not match the guard. Read details.actual.",
            "Change the guard or the steps before it.",
        ),
        E::PluckTooLong => row(
            code,
            "PLUCK_TOO_LONG",
            R,
            false,
            "A star reference gives too many values. The target list has a lower cap. Send next[0], which adds a limit to the source step.",
            "Use a lower limit on the source step.",
        ),
        E::BudgetExceeded => row(
            code,
            "BUDGET_EXCEEDED",
            R,
            true,
            "The call used all of its fuel. The work needs more fuel than max_steps gives. Send next[0] to resume the work.",
            "Add a higher max_steps to the next call.",
        ),
        E::ProjectLocked => row(
            code,
            "PROJECT_LOCKED",
            N,
            true,
            "Another writer holds the project lock. Only one writer can open a project. Open the project in read-only mode.",
            "Read details.owner for the process that holds the lock.",
        ),
        E::JournalCorrupt => row(
            code,
            "JOURNAL_CORRUPT",
            N,
            false,
            "A journal line fails its checksum. The line is not at the end of the journal, so the server cannot skip it. Read details.line.",
            "Restore the project directory from a backup.",
        ),
        E::ReadOnlyProject => row(
            code,
            "READ_ONLY_PROJECT",
            N,
            false,
            "The project is open in read-only mode. A read-only project accepts no edits. Open the project again for writes.",
            "Stop the other writer first.",
        ),
        E::OutputBudgetExceeded => row(
            code,
            "OUTPUT_BUDGET_EXCEEDED",
            N,
            false,
            "The result is larger than the output budget. The call changed no fact, and an internal guard stopped it. Read details.chars and details.limit.",
            "A committed edit never gives this error. Its result drops data members until it fits.",
        ),
        E::InternalError => row(
            code,
            "INTERNAL_ERROR",
            N,
            false,
            "The tool failed with an internal error. The handler stopped on a fault. Report the crash_id.",
            "The crash file holds the tool, the arguments and the rev.",
        ),
        E::NoBinaryOpen => row(
            code,
            "NO_BINARY_OPEN",
            H,
            false,
            "No binary is open. The call needs an open binary. Load a binary with binary_load.",
            "Send next[0]. It lists the projects or opens the newest project.",
        )
        .with_plain("Send binary_load with a path under a root of the server."),
        E::NothingToRedo => row(
            code,
            "NOTHING_TO_REDO",
            N,
            false,
            "The redo found no transaction. The scope has no transaction in the undone state, or a later edit ended the redo chain. Call history_list to see the transactions.",
            "A new edit after an undo ends the redo chain.",
        ),
    }
}
