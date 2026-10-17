//! `search`: search the items of a binary by kind, or read records by ID (design Section
//! 10.4, tool 7).
//!
//! Exactly one of `kind` and `ids` is in a call. Each item is `{ kind, id, addr?, text?,
//! func?, extra }`. `kind` is the entity kind. Items sort by the kind order of [`ORDER`],
//! then by address, then by ID. An empty `query` lists every item of the kind.
//!
//! | `kind` | Items |
//! |---|---|
//! | `name` | functions, imports, exports and symbols whose name matches |
//! | `string` | referenced strings. `include_unreferenced` adds the others. |
//! | `bytes` | the starts of the byte pattern in mapped memory |
//! | `comment` | comments whose text matches |
//! | `note` | notes, with `note_filter` |
//! | `type` | named types and typedefs |
//! | `import`, `export`, `section`, `segment`, `library`, `symbol` | the items of the loader model (AC-217) |
//! | `set` | named sets |
//! | `jumptable` | jump tables |
//!
//! `match` is `substr` (ASCII case-insensitive, the default), `glob` (linear time) or
//! `exact`. `scope` keeps the items whose address is in a section, a function, a range or a
//! region with the given permissions. A byte pattern is a list of hex bytes: `??` matches any
//! byte, and `4?` matches a nibble.
//!
//! With `ids`, each `note:`, `set:` or `jt:` ID gives its full record. A set record is
//! followed by one item per member, so the cursor pages the members. String items carry
//! `ref_count`, at most 3 `funcs` and a `next` call to `xref_list`. Name and byte searches
//! use fuel. When the fuel runs out, `page.total_lower_bound` replaces `page.total`.

mod filter;
mod kinds;
mod tables;

use ghidorah_json::Object;

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, ListPayload, Payload, Total};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{
    ActionSpec, ArgKind, ArgSpec, Example, Group, GroupRule, ListSpec, Profile, Role, ToolSpec,
};

/// The default page size of `search`.
pub const DEFAULT_LIMIT: u32 = 50;

/// The search kinds in schema order.
pub const KINDS: [&str; 14] = [
    "name",
    "string",
    "bytes",
    "comment",
    "note",
    "type",
    "import",
    "export",
    "section",
    "segment",
    "library",
    "symbol",
    "set",
    "jumptable",
];

/// The item kinds in item order. `bytes` items sort with `data`.
pub const ORDER: [&str; 15] = [
    "function",
    "import",
    "export",
    "symbol",
    "data",
    "bytes",
    "string",
    "section",
    "segment",
    "library",
    "comment",
    "note",
    "set",
    "jumptable",
    "type",
];

/// The largest number of IDs in `ids`.
pub const MAX_IDS: usize = 50;

/// The largest number of referencing functions of a string item.
pub const STRING_FUNCS: usize = 3;

/// The page hint of a long result.
pub const HINT_NARROW: &str = "Add query or scope to narrow the list.";

/// The `why` of the `next` call of a string item.
pub const WHY_STRING_REFS: &str = "List the references to the string.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW, WHY_STRING_REFS];

/// The kinds other than `bytes`, for the rules of `pattern`.
const NOT_BYTES: &[(&str, &str)] = &[
    ("kind", "name"),
    ("kind", "string"),
    ("kind", "comment"),
    ("kind", "note"),
    ("kind", "type"),
    ("kind", "import"),
    ("kind", "export"),
    ("kind", "section"),
    ("kind", "segment"),
    ("kind", "library"),
    ("kind", "symbol"),
    ("kind", "set"),
    ("kind", "jumptable"),
];

/// The kinds other than `string`, for the rule of `include_unreferenced`.
const NOT_STRING: &[(&str, &str)] = &[
    ("kind", "name"),
    ("kind", "bytes"),
    ("kind", "comment"),
    ("kind", "note"),
    ("kind", "type"),
    ("kind", "import"),
    ("kind", "export"),
    ("kind", "section"),
    ("kind", "segment"),
    ("kind", "library"),
    ("kind", "symbol"),
    ("kind", "set"),
    ("kind", "jumptable"),
];

/// The kinds other than `note`, for the rule of `note_filter`.
const NOT_NOTE: &[(&str, &str)] = &[
    ("kind", "name"),
    ("kind", "string"),
    ("kind", "bytes"),
    ("kind", "comment"),
    ("kind", "type"),
    ("kind", "import"),
    ("kind", "export"),
    ("kind", "section"),
    ("kind", "segment"),
    ("kind", "library"),
    ("kind", "symbol"),
    ("kind", "set"),
    ("kind", "jumptable"),
];

const ID_ITEM: ArgSpec = ArgSpec::new(
    "id",
    Role::Param,
    ArgKind::Id(&[
        ghidorah_base::IdKind::Note,
        ghidorah_base::IdKind::Set,
        ghidorah_base::IdKind::JumpTable,
    ]),
    "A note:, set: or jt: ID.",
);

const TAG_ITEM: ArgSpec = ArgSpec::new("tag", Role::Param, ArgKind::Str(64), "One tag.");

const NOTE_FILTER: &[ArgSpec] = &[
    ArgSpec::new(
        "kind",
        Role::Param,
        ArgKind::Enum(&["note", "todo", "hypothesis", "finding", "error", "set"]),
        "Keep the notes of this kind.",
    ),
    ArgSpec::new(
        "status",
        Role::Param,
        ArgKind::Enum(&["open", "confirmed", "refuted", "done"]),
        "Keep the notes with this status.",
    ),
    ArgSpec::new(
        "tags",
        Role::Param,
        ArgKind::List(&TAG_ITEM, 16),
        "Keep the notes with all of these tags.",
    ),
];

const SCOPE: &[ArgSpec] = &[
    ArgSpec::new(
        "section",
        Role::Param,
        ArgKind::Str(256),
        "Keep the items in the section with this name.",
    ),
    ArgSpec::new(
        "perms",
        Role::Param,
        ArgKind::Str(3),
        "Keep the items in regions with all of these permissions, for example rx.",
    ),
    ArgSpec::new(
        "start",
        Role::Param,
        ArgKind::Addr,
        "The start of an address range.",
    ),
    ArgSpec::new(
        "size",
        Role::Param,
        ArgKind::Addr,
        "The size of the address range, as a 0x hex string.",
    ),
    ArgSpec::new(
        "func",
        Role::Param,
        ArgKind::Addr,
        "Keep the items in the body of this function.",
    ),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "kind",
        Role::Selector,
        ArgKind::Enum(&KINDS),
        "The kind of the items to search.",
    ),
    ArgSpec::new(
        "ids",
        Role::Param,
        ArgKind::List(&ID_ITEM, MAX_IDS),
        "Read the full records of these IDs.",
    ),
    ArgSpec::new(
        "query",
        Role::Param,
        ArgKind::Str(256),
        "The text to find. An empty query lists every item of the kind.",
    )
    .forbidden_when(&[("kind", "bytes")]),
    ArgSpec::new(
        "match",
        Role::Param,
        ArgKind::Enum(&["substr", "glob", "exact"]),
        "How the query matches: a part of the text, a glob or the exact text.",
    )
    .default_json("\"substr\""),
    ArgSpec::new(
        "pattern",
        Role::Param,
        ArgKind::Str(512),
        "The byte pattern in hex, for example 48 8b ?? 4?. The mark ?? matches any byte.",
    )
    .required_when(&[("kind", "bytes")])
    .forbidden_when(NOT_BYTES),
    ArgSpec::new(
        "scope",
        Role::Param,
        ArgKind::Obj(SCOPE),
        "Keep only the items in this part of the binary.",
    ),
    ArgSpec::new(
        "include_unreferenced",
        Role::Param,
        ArgKind::Bool,
        "Add the strings that no reference points to.",
    )
    .forbidden_when(NOT_STRING),
    ArgSpec::new(
        "note_filter",
        Role::Param,
        ArgKind::Obj(NOTE_FILTER),
        "The filters of the note kind.",
    )
    .forbidden_when(NOT_NOTE),
];

const ACTIONS: &[ActionSpec] = &[
    action(
        "name",
        "Find functions, imports, exports and symbols by name.",
        r#"{"kind":"name","query":"pass"}"#,
    ),
    action(
        "string",
        "Find strings by text, the referenced strings first.",
        r#"{"kind":"string","query":"Access"}"#,
    ),
    action(
        "bytes",
        "Find a byte pattern with wildcards in mapped memory.",
        r#"{"kind":"bytes","pattern":"e8 ?? ?? ?? ??","limit":3}"#,
    ),
    action("comment", "Find comments by text.", r#"{"kind":"comment"}"#),
    action(
        "note",
        "Find notes by text, kind, status and tags.",
        r#"{"kind":"note"}"#,
    ),
    action(
        "type",
        "Find named types and typedefs.",
        r#"{"kind":"type","query":"sockaddr"}"#,
    ),
    action(
        "import",
        "List or find the imports.",
        r#"{"kind":"import"}"#,
    ),
    action(
        "export",
        "List or find the exports.",
        r#"{"kind":"export"}"#,
    ),
    action(
        "section",
        "List or find the sections.",
        r#"{"kind":"section","query":"text"}"#,
    ),
    action("segment", "List the segments.", r#"{"kind":"segment"}"#),
    action(
        "library",
        "List the libraries that the binary needs.",
        r#"{"kind":"library"}"#,
    ),
    action(
        "symbol",
        "List or find the symbols of the symbol tables.",
        r#"{"kind":"symbol","query":"main","match":"exact"}"#,
    ),
    action("set", "List the named sets.", r#"{"kind":"set"}"#),
    action(
        "jumptable",
        "List the jump tables.",
        r#"{"kind":"jumptable"}"#,
    ),
];

/// Makes one action that is not destructive.
const fn action(value: &'static str, line: &'static str, example: &'static str) -> ActionSpec {
    ActionSpec {
        value,
        line,
        example,
        destructive: false,
    }
}

/// Makes the executed example of an action: its example and its golden file.
const fn example(args: &'static str, golden: &'static str) -> Example {
    Example { args, golden }
}

const FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::Any),
    Field::opt("cols", OutputShape::List(&OutputShape::Str)),
    Field::opt(
        "rows",
        OutputShape::List(&OutputShape::List(&OutputShape::Any)),
    ),
    Field::opt("count", OutputShape::Int),
];

/// `search`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Search a binary",
    summary: "Search the items of a binary by kind: names, strings, bytes, comments, notes, types, imports, exports, sections, segments, libraries, symbols, sets and jump tables.",
    description: "Search the items of a binary by kind: names, strings, bytes, comments, notes, types, imports, exports, sections, segments, libraries, symbols, sets and jump tables. \
                  Send kind with a query, or ids with note:, set: or jt: IDs to read full records. \
                  An empty query lists every item of the kind. \
                  The match substr ignores the letter case. \
                  In a byte pattern, two question marks match any byte. \
                  String items give the reference count and a call that lists the references.",
    args: ARGS,
    groups: &[Group {
        members: &["kind", "ids"],
        rule: GroupRule::ExactlyOne,
    }],
    actions: ACTIONS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        example(
            r#"{"kind":"name","query":"pass"}"#,
            "tests/golden/tools/search.1.json",
        ),
        example(
            r#"{"kind":"string","query":"Access"}"#,
            "tests/golden/tools/search.2.json",
        ),
        example(
            r#"{"kind":"bytes","pattern":"e8 ?? ?? ?? ??","limit":3}"#,
            "tests/golden/tools/search.3.json",
        ),
        example(r#"{"kind":"comment"}"#, "tests/golden/tools/search.4.json"),
        example(r#"{"kind":"note"}"#, "tests/golden/tools/search.5.json"),
        example(
            r#"{"kind":"type","query":"sockaddr"}"#,
            "tests/golden/tools/search.6.json",
        ),
        example(r#"{"kind":"import"}"#, "tests/golden/tools/search.7.json"),
        example(r#"{"kind":"export"}"#, "tests/golden/tools/search.8.json"),
        example(
            r#"{"kind":"section","query":"text"}"#,
            "tests/golden/tools/search.9.json",
        ),
        example(r#"{"kind":"segment"}"#, "tests/golden/tools/search.10.json"),
        example(r#"{"kind":"library"}"#, "tests/golden/tools/search.11.json"),
        example(
            r#"{"kind":"symbol","query":"main","match":"exact"}"#,
            "tests/golden/tools/search.12.json",
        ),
        example(r#"{"kind":"set"}"#, "tests/golden/tools/search.13.json"),
        example(
            r#"{"kind":"jumptable"}"#,
            "tests/golden/tools/search.14.json",
        ),
    ],
    max_chars: crate::budget::LIST_MAX_CHARS,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("search", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let namer = Namer::new();
    let caps = fs::caps(ctx);
    let mut items = filter::Items {
        program: p,
        scope: filter::Scope::of(p, args)?,
        list: Vec::new(),
        cut: false,
    };
    if let Some(ids) = args.list("ids") {
        kinds::records(&mut items, ids)?;
    } else {
        let m = filter::Matcher::of(args)?;
        match args.str("kind").unwrap_or_default() {
            "name" => kinds::names(&mut items, &m, &namer, &mut ctx.fuel),
            "string" => {
                let all = args.bool("include_unreferenced").unwrap_or(false);
                kinds::strings(&mut items, &m, all, caps);
            }
            "bytes" => {
                let pat = kinds::pattern(args.str("pattern").unwrap_or_default())?;
                kinds::bytes(&mut items, &pat, &mut ctx.fuel);
            }
            "comment" => kinds::comments(&mut items, &m),
            "note" => kinds::notes(&mut items, &m, args.get("note_filter")),
            "type" => kinds::types(&mut items, &m),
            "import" => tables::imports(&mut items, &m, &namer),
            "export" => tables::exports(&mut items, &m, &namer),
            "section" => tables::sections(&mut items, &m),
            "segment" => tables::segments(&mut items, &m),
            "library" => tables::libraries(&mut items, &m),
            "symbol" => tables::symbols(&mut items, &m, &namer),
            "set" => kinds::sets(&mut items, &m),
            _ => kinds::jumptables(&mut items),
        }
    }
    namer.finish(ctx);
    let count = u64::try_from(items.list.len()).unwrap_or(u64::MAX);
    Ok(Payload::List(ListPayload {
        items: items.list,
        total: if items.cut {
            Total::AtLeast(count)
        } else {
            Total::Items
        },
        extra: Object::new(),
        narrow: Some(HINT_NARROW.to_owned()),
    }))
}
