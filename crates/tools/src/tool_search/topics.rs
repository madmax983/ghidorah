//! The topic texts of `tool_search` (design Section 10.4). Each text is STE for agents.

use super::Topic;

/// The topics in the order of [`super::TOPIC_NAMES`].
pub const TOPICS: &[Topic] = &[
    Topic {
        name: "addresses",
        text: "Send an address as a 0x hex string such as 0x401000. A JSON integer below 2^53 is a decimal value. A string of digits only is an error, because the server does not guess the base.\n\n\
               The server reads an address text by the first rule that matches. Rule order: JSON integer, 0x hex, ID, exact symbol name, section name, default name, name@0x<hex>, term with a 0x offset. Use sym:<exact name> for a symbol name that looks like another form.\n\n\
               A name with more than one match gives AMBIGUOUS_NAME. Each candidate value resolves to one match. An unknown name gives NOT_FOUND with the closest names. An address outside the memory regions gives ADDRESS_UNMAPPED with the nearest mapped addresses.\n\n\
               Output addresses are lower case 0x hex strings. The result field resolved_from tells the rule and the matched text.",
    },
    Topic {
        name: "ids",
        text: "An ID names one entity, and a rename never changes it. Use IDs, not names, in later calls.\n\n\
               ID forms: fn:0x401130 (function), bb:0x401145 (basic block), op:0x401a2c:3 (IR op), imp:puts (import), exp:main (export), sys:openat (syscall), sec:14:.text (section), seg:2 (segment), str:0x402010 (string), jt:0x401200 (jump table), ext:0x3 (EXTERNAL address), file:0x1040 (file offset), sym:<name> (exact symbol name), var:0x401130/stack:-0x14 (variable), note:7 (note), set:parsers (named set), t:sockaddr_in (type), tx:42 (transaction), ref:0x401136>0x402010:read (xref).\n\n\
               A binary_id has 16 hex digits. The 64 digits of the SHA-256 also work as input.",
    },
    Topic {
        name: "budgets",
        text: "The global max_chars sets the largest result in characters. The count includes every copy of the result. The hard cap is 60,000 characters.\n\n\
               A list result has a page member. When page.truncated is true, send page.next_cursor as cursor to get the next page. The limit argument sets the page size, and count_only gives only the count.\n\n\
               A cursor stays valid after an edit. CURSOR_STALE comes only when the sort key of the boundary item changed. Then send the call again without the cursor.\n\n\
               The global max_steps sets the fuel of the analysis and of long calls. The work stops at the same point on each host.",
    },
    Topic {
        name: "batch",
        text: "The tool batch_run runs up to 32 steps in one call. Each step has an id, a tool and args.\n\n\
               A step refers to an earlier step with {\"$ref\":\"s1\",\"ptr\":\"/data/items/*/id\"}. The star segment maps over each item of a list. The executor checks the types of all references before a step runs.\n\n\
               A batch with edits is one transaction with one rev. A failed step rolls back the edits. Send dry_run true to see the planned edits first. A batch rejects destructive steps.\n\n\
               The return member names the steps whose data the result holds.",
    },
    Topic {
        name: "errors",
        text: "A failed call has ok false and an error object: code, num, message, hint, retryable, field_path, candidates and details.\n\n\
               Each code has a repair class. Class R: next[0] is the complete corrected call. Class C: the candidates hold the choices. Class H: next[0] is a helper call such as tool_search. Class N: no mechanical repair exists.\n\n\
               When a call fails, send next[0] if it exists. Else read error.hint and error.details. A warning has a code and a message, and a remedy when a call fixes the cause.",
    },
    Topic {
        name: "rules",
        text: "Each fact has a source with a rank. Rank order: default, analysis, agent, imported, user. A write with a lower rank than the current fact gives BLOCKED_BY_HIGHER_PRIORITY_SOURCE.\n\n\
               An agent write over an imported fact needs force true. The journal records the force. Analysis never replaces a fact of an agent, an import or a user.\n\n\
               Each edit increases rev by 1. An edit with no change gives noop true and keeps the rev. Send expected_rev to make sure that no other edit came first.",
    },
    Topic {
        name: "relations",
        text: "A claim is one relation atom with ID arguments. The verdict is supported, refuted or unknown.\n\n\
               Relations: calls(f, g), reaches(f, g, d), uses_import(f, i), refs_string(f, glob), refs_addr(f, a), xref(from, to, kind), const_arg(callee, index, value), has_syscall(f, name), noreturn(f), in_func(a, f).\n\n\
               The server gives refuted only when the evidence is complete. An unresolved indirect call gives unknown and lists the gap in basis.gaps. Each verdict lists the IDs of its evidence.",
    },
    Topic {
        name: "profiles",
        text: "A profile is a set of tools. The full profile holds all tools. The readonly profile holds the tools that change no fact. The mini profile holds 10 core tools.\n\n\
               In the readonly profile, batch_run rejects the steps that edit. A tool outside the active profile gives TOOL_NOT_IN_PROFILE.\n\n\
               The server option --tools gives an allowlist on top of the profile. Every profile keeps the order of the full tool list.",
    },
    Topic {
        name: "resume",
        text: "After a context reset or a server restart, call session_brief first. With no open binary, it lists the projects on disk. Then send binary_load with the binary_id of a project to open it again.\n\n\
               The project keeps every edit, note and name. Use the IDs of the brief in later calls.\n\n\
               When partial is true, the analysis is not complete. Call analysis_run to resume it.",
    },
];
