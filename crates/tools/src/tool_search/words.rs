//! The word tables of `tool_search`: stop words, synonyms and the keywords of each tool.

/// Words that do not count in a query.
pub const STOP_WORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "do", "for", "from", "how", "i", "in", "is",
    "it", "me", "my", "of", "on", "or", "the", "this", "to", "what", "with",
];

/// Query synonyms: a token and the token or tool name that it stands for.
pub const SYNONYMS: &[(&str, &str)] = &[
    ("fn", "func"),
    ("function", "func"),
    ("functions", "func"),
    ("sub", "func"),
    ("subroutine", "func"),
    ("routine", "func"),
    ("procedure", "func"),
    ("disassemble", "func_get"),
    ("disassembly", "func_get"),
    ("decompile", "func_get"),
    ("pseudocode", "func_get"),
    ("callers", "xref"),
    ("callees", "xref"),
    ("references", "xref"),
    ("refs", "xref"),
    ("calculate", "calc"),
    ("arithmetic", "calc"),
    ("open", "binary_load"),
    ("rename", "symbol_rename"),
    ("undo", "history_undo"),
    ("redo", "history_undo"),
    ("similar", "func_similar"),
    ("clone", "func_similar"),
    ("bsim", "func_similar"),
    ("bookmark", "note_write"),
    ("find", "search"),
    ("hexdump", "mem_read"),
    ("checksec", "binary_survey"),
    ("overview", "binary_survey"),
    ("claim", "fact_check"),
    ("struct", "type_get"),
];

/// Search keywords of each tool of the catalog, in catalog order.
pub const KEYWORDS: &[(&str, &[&str])] = &[
    (
        "binary_load",
        &["file", "elf", "raw", "blob", "demo", "project", "path"],
    ),
    (
        "binary_survey",
        &[
            "triage",
            "protections",
            "sections",
            "imports",
            "exports",
            "strings",
            "entry",
        ],
    ),
    (
        "analysis_run",
        &[
            "analyze", "analysis", "resume", "fuel", "progress", "partial",
        ],
    ),
    ("func_list", &["list", "priority", "filter", "sort"]),
    (
        "func_get",
        &["ir", "cfg", "variables", "summary", "jumptables"],
    ),
    ("xref_list", &["uses", "graph", "arguments", "calls"]),
    (
        "search",
        &[
            "strings", "bytes", "pattern", "names", "imports", "exports", "symbols",
        ],
    ),
    (
        "mem_read",
        &["memory", "bytes", "hex", "dump", "integers", "instructions"],
    ),
    ("addr_info", &["address", "region", "section", "owner"]),
    (
        "calc",
        &[
            "hex", "decimal", "offset", "signed", "convert", "base", "address",
        ],
    ),
    (
        "fact_check",
        &["verdict", "explain", "why", "proof", "check"],
    ),
    ("type_get", &["layout", "sizeof", "fields"]),
    ("history_list", &["edits", "changes", "revisions", "log"]),
    (
        "session_brief",
        &["resume", "context", "projects", "progress", "notes"],
    ),
    (
        "tool_search",
        &["tools", "help", "schema", "topics", "discover"],
    ),
    ("symbol_rename", &["name", "label", "symbol"]),
    ("comment_set", &["annotate", "remark"]),
    (
        "note_write",
        &["todo", "hypothesis", "finding", "set", "notes"],
    ),
    (
        "func_edit",
        &[
            "create",
            "delete",
            "noreturn",
            "jumptable",
            "override",
            "flow",
        ],
    ),
    ("type_edit", &["apply", "prototype", "signature", "declare"]),
    ("history_undo", &["revert", "rollback"]),
    ("batch_run", &["steps", "pipeline", "chain", "compose"]),
    ("func_similar", &["clone", "match", "compare", "propose"]),
];
