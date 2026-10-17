//! The test registry of WP-13a and its host.
//!
//! The registry holds five test tools. Together they use every argument kind, every global
//! argument, a selector tool with actions, a list tool, a tool with fuel and a tool with no
//! binary. Registry-wide tests run over this registry and over the shipped registry.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{BinText, Caps, ErrorCode, IdKind, did_you_mean};
use ghidorah_db::Table;
use ghidorah_json::{Object, Value};
use ghidorah_tools::dispatch::{Crash, CursorCall};
use ghidorah_tools::outshape::Field;
use ghidorah_tools::{
    ActionSpec, AnalysisInfo, Annotations, ArgKind, ArgSpec, Args, BinaryArg, Call, Candidate, Ctx,
    Example, Frame, FuelSpec, Globals, Group, GroupRule, Host, Item, KeyPart, ListPayload,
    ListSpec, Members, OutputShape, Payload, Profile, Registry, Role, SortKey, ToolError, ToolSpec,
};

/// The binary of the test host.
pub const BINARY: &str = "b1";

/// The rev of a new test host.
pub const START_REV: u64 = 7;

/// The address of the first test item.
pub const BASE: u64 = 0x40_1000;

/// The address step between two test items.
pub const STEP: u64 = 0x10;

/// The host of the test registry.
#[derive(Debug)]
pub struct TestHost {
    /// The open binaries.
    pub binaries: Vec<String>,
    /// The rev of the binaries.
    pub rev: u64,
    /// The analysis state of the binaries.
    pub analysis: Option<AnalysisInfo>,
    /// The tools of the active profile, or `None` for all tools.
    pub profile: Option<BTreeSet<&'static str>>,
    /// The panics that the host saw.
    pub panics: Vec<Crash>,
    /// `true` when the host coerces numeric strings to integers.
    pub lenient: bool,
    /// The names of the test items that `item_edit` changed, by address.
    pub names: BTreeMap<u64, String>,
}

impl Default for TestHost {
    fn default() -> Self {
        Self {
            binaries: vec![BINARY.to_owned()],
            rev: START_REV,
            analysis: Some(AnalysisInfo {
                state: ghidorah_tools::AnalysisState::Complete,
                rev: START_REV,
            }),
            profile: None,
            panics: Vec::new(),
            lenient: false,
            names: BTreeMap::new(),
        }
    }
}

impl Host for TestHost {
    fn registry() -> Registry<Self> {
        registry()
    }

    fn in_profile(&self, name: &str) -> bool {
        self.profile.as_ref().is_none_or(|p| p.contains(name))
    }

    fn frame(
        &mut self,
        tool: &ToolSpec<Self>,
        globals: &Globals,
        request_session: Option<&str>,
    ) -> Result<Frame, ToolError> {
        let session = globals
            .session
            .clone()
            .or_else(|| request_session.map(str::to_owned))
            .unwrap_or_else(|| "test".to_owned());
        let bound = match (&globals.binary_id, tool.binary) {
            (_, BinaryArg::None) => None,
            (Some(id), _) if self.binaries.contains(id) => Some(id.clone()),
            (Some(_), _) => return Err(ToolError::new(ErrorCode::UnknownBinary)),
            (None, _) if self.binaries.len() == 1 => self.binaries.first().cloned(),
            (None, BinaryArg::Optional) => None,
            (None, _) if self.binaries.is_empty() => {
                return Err(ToolError::new(ErrorCode::NoBinaryOpen));
            }
            (None, _) => return Err(ToolError::new(ErrorCode::BinaryRequired)),
        };
        Ok(Frame {
            rev: if bound.is_some() { self.rev } else { 0 },
            analysis: bound.as_ref().and(self.analysis),
            binary_id: bound,
            session,
        })
    }

    fn coerce(&self, kind: &ArgKind, value: &Value) -> Option<Value> {
        match (kind, value) {
            (ArgKind::Int { .. }, Value::String(text)) if self.lenient => {
                ghidorah_json::Number::parse(text).ok().map(Value::Number)
            }
            _ => None,
        }
    }

    fn members(&self, _frame: &Frame, set: &str) -> Result<Members, ToolError> {
        if set == "set:small" {
            Ok(Members {
                ids: ["fn:0x401000", "fn:0x401020"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                ranges: vec![(0x40_1040, 0x40_1060)],
            })
        } else {
            Err(ToolError::new(ErrorCode::NotFound)
                .var("kind", "set")
                .detail("kind", Value::from("set")))
        }
    }

    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String {
        let parts: Vec<String> = key
            .0
            .iter()
            .map(|part| match part {
                KeyPart::Int(v) => format!("{v:#x}"),
                KeyPart::Text(t) => t.clone(),
            })
            .collect();
        format!("c:{}:{}", call.tool_index, parts.join(":"))
    }

    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError> {
        let invalid = || ToolError::new(ErrorCode::CursorInvalid);
        let rest = cursor
            .strip_prefix(&format!("c:{}:", call.tool_index))
            .ok_or_else(invalid)?;
        let parts = rest
            .split(':')
            .map(|p| {
                p.strip_prefix("0x").map_or_else(
                    || KeyPart::Text(p.to_owned()),
                    |hex| {
                        u64::from_str_radix(hex, 16)
                            .map_or_else(|_| KeyPart::Text(p.to_owned()), KeyPart::Int)
                    },
                )
            })
            .collect();
        Ok(SortKey(parts))
    }

    fn on_panic(&mut self, crash: &Crash) {
        self.panics.push(crash.clone());
    }
}

/// The test registry.
pub fn registry() -> Registry<TestHost> {
    Registry::new(TOOLS)
}

/// The tools of the test registry in registry order.
pub static TOOLS: &[&ToolSpec<TestHost>] =
    &[&ITEM_LIST, &ITEM_GET, &ITEM_EDIT, &ECHO_VALUE, &FUEL_RUN];

/// Extra requests of the argument coverage check (AC-132b): `(tool, args)`.
pub const REQUESTS: &[(&str, &str)] = &[
    ("item_list", r#"{"cursor":"c:0:0x401010","limit":2}"#),
    (
        "item_list",
        r#"{"binary_id":"b1","max_chars":2000,"sort":"size"}"#,
    ),
    (
        "item_list",
        r#"{"filter":{"size_min":150},"format":"detailed"}"#,
    ),
    ("item_get", r#"{"target":4198400,"session":"agent-1"}"#),
    (
        "item_list",
        r#"{"sort":"addr","shape":"objects","format":"concise"}"#,
    ),
];

fn item_addr(index: u64) -> u64 {
    BASE + index * STEP
}

fn item_name(host: &TestHost, addr: u64) -> String {
    host.names.get(&addr).cloned().unwrap_or_else(|| {
        let index = (addr - BASE) / STEP;
        format!("func_{index:04}")
    })
}

fn item_size(addr: u64) -> u64 {
    ((addr - BASE) / STEP * 37) % 200 + 1
}

fn item_object(host: &TestHost, addr: u64) -> Value {
    let name = item_name(host, addr);
    let label = ghidorah_json::parse(
        &BinText::new(name.as_bytes()).to_json(Caps::DEFAULT),
        &ghidorah_json::Limits::DEFAULT,
    )
    .unwrap_or_default();
    Value::object([
        ("id", Value::from(format!("fn:{addr:#x}"))),
        ("addr", Value::from(format!("{addr:#x}"))),
        ("name", Value::from(name)),
        ("size", int(item_size(addr))),
        ("label", label),
    ])
}

fn int(value: u64) -> Value {
    Value::Number(ghidorah_json::Number::parse(&value.to_string()).expect("an integer"))
}

// item_list ------------------------------------------------------------------------------

const NAME_FILTER: ArgSpec = ArgSpec::new(
    "name",
    Role::Param,
    ArgKind::Str(64),
    "Keep the items whose name holds this text.",
);
const SIZE_FILTER: ArgSpec = ArgSpec::new(
    "size_min",
    Role::Param,
    ArgKind::Int { min: 0, max: 1_000 },
    "Keep the items with at least this size.",
);
const FILTERS: &[ArgSpec] = &[NAME_FILTER, SIZE_FILTER];

const LIST_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int {
            min: 0,
            max: 20_000,
        },
        "The number of test items in the binary.",
    )
    .default_json("40"),
    ArgSpec::new(
        "filter",
        Role::Param,
        ArgKind::Obj(FILTERS),
        "Filters that narrow the list.",
    ),
    ArgSpec::new(
        "sort",
        Role::Param,
        ArgKind::Enum(&["addr", "name", "size"]),
        "The sort order of the items.",
    )
    .default_json("\"addr\""),
];

const ITEM_FIELDS: &[Field] = &[
    Field::req("id", OutputShape::Id(IdKind::Func)),
    Field::req("addr", OutputShape::Addr),
    Field::req("name", OutputShape::Str),
    Field::req("size", OutputShape::Int),
    Field::req("label", OutputShape::Text),
];
const ITEM: OutputShape = OutputShape::Obj(ITEM_FIELDS);
const LIST_FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::List(&ITEM)),
    Field::opt("cols", OutputShape::List(&OutputShape::Str)),
    Field::opt(
        "rows",
        OutputShape::List(&OutputShape::List(&OutputShape::Any)),
    ),
    Field::opt("count", OutputShape::Int),
    Field::opt("sorted_by", OutputShape::Str),
];

/// `item_list`: a list tool.
pub const ITEM_LIST: ToolSpec<TestHost> = ToolSpec {
    title: "List test items",
    summary: "List the test items of the open binary, sorted by address, name or size.",
    description: "List the test items of the open binary, sorted by address, name or size. \
                  Use filter.name and filter.size_min to narrow the list. \
                  The tool exists only in the test registry.",
    args: LIST_ARGS,
    output: OutputShape::Obj(LIST_FIELDS),
    reads_tables: &[Table::Functions],
    examples: &[
        Example {
            args: "{}",
            golden: "tests/golden/tools/test/item_list.1.json",
        },
        Example {
            args: r#"{"sort":"name","limit":5,"filter":{"name":"func_00"}}"#,
            golden: "tests/golden/tools/test/item_list.2.json",
        },
        Example {
            args: r#"{"count":3,"shape":"table","fields":["/items/*/id","/items/*/addr"]}"#,
            golden: "tests/golden/tools/test/item_list.3.json",
        },
        Example {
            args: r#"{"count_only":true}"#,
            golden: "tests/golden/tools/test/item_list.4.json",
        },
        Example {
            args: r#"{"in":"set:small","limit":3}"#,
            golden: "tests/golden/tools/test/item_list.5.json",
        },
    ],
    max_chars: 16_000,
    list: Some(ListSpec { default_limit: 20 }),
    ..ToolSpec::base("item_list", item_list)
};

fn item_list(host: &mut TestHost, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let count = u64::try_from(args.int("count").unwrap_or(40)).unwrap_or(0);
    let filter = args.get("filter").and_then(Value::as_object);
    let name_part = filter.and_then(|f| f.get("name")).and_then(Value::as_str);
    let size_min = filter
        .and_then(|f| f.get("size_min"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let sort = args.str("sort").unwrap_or("addr");
    let mut items = Vec::new();
    for index in 0..count {
        let addr = item_addr(index);
        let name = item_name(host, addr);
        if name_part.is_some_and(|p| !name.contains(p)) || item_size(addr) < size_min {
            continue;
        }
        let key = match sort {
            "name" => SortKey(vec![KeyPart::Text(name), KeyPart::Int(addr)]),
            "size" => SortKey(vec![KeyPart::Int(item_size(addr)), KeyPart::Int(addr)]),
            _ => SortKey(vec![KeyPart::Int(addr)]),
        };
        items.push(Item {
            key,
            value: item_object(host, addr),
        });
    }
    items.sort_by(|a, b| a.key.cmp(&b.key));
    if let Some(first) = items.first() {
        let id = first.value.get("id").cloned().unwrap_or_default();
        ctx.hint(Call::new(
            "item_get",
            Value::object([("target", id)]),
            "Read the first item.",
        ));
    }
    let mut list = ListPayload::new(items);
    list.extra.insert("sorted_by", Value::from(sort));
    list.narrow = Some("Add filter.name or filter.size_min to narrow the list.".to_owned());
    Ok(Payload::List(list))
}

// item_get -------------------------------------------------------------------------------

const SECTION: ArgSpec = ArgSpec::new(
    "section",
    Role::Param,
    ArgKind::Enum(&["summary", "body"]),
    "One section.",
);

const GET_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The address of one item.",
    )
    .aliases(&["id", "addr"]),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(50),
        "The addresses of up to 50 items.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&SECTION, 2),
        "The sections of each item.",
    )
    .default_json("[\"summary\"]"),
];

const GET_ONE: &[Field] = &[
    Field::req("id", OutputShape::Id(IdKind::Func)),
    Field::req("addr", OutputShape::Addr),
    Field::opt("summary", OutputShape::Str),
    Field::opt("body", OutputShape::Str),
];
const GET_ONE_SHAPE: OutputShape = OutputShape::Obj(GET_ONE);
const GET_FIELDS: &[Field] = &[
    Field::opt("id", OutputShape::Id(IdKind::Func)),
    Field::opt("addr", OutputShape::Addr),
    Field::opt("summary", OutputShape::Str),
    Field::opt("body", OutputShape::Str),
    Field::opt("items", OutputShape::List(&GET_ONE_SHAPE)),
];

/// `item_get`: a tool with a target group and aliases.
pub const ITEM_GET: ToolSpec<TestHost> = ToolSpec {
    title: "Get test items",
    summary: "Get one or more test items by address with the selected sections.",
    description: "Get one or more test items by address with the selected sections. \
                  Send target for one item or targets for up to 50 items.",
    args: GET_ARGS,
    groups: &[Group {
        members: &["target", "targets"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(GET_FIELDS),
    reads_tables: &[Table::Functions],
    examples: &[
        Example {
            args: r#"{"target":"0x401010","include":["summary","body"]}"#,
            golden: "tests/golden/tools/test/item_get.1.json",
        },
        Example {
            args: r#"{"targets":["0x401000",4198416]}"#,
            golden: "tests/golden/tools/test/item_get.2.json",
        },
        Example {
            args: r#"{"id":"0x401000","format":"detailed"}"#,
            golden: "tests/golden/tools/test/item_get.3.json",
        },
    ],
    ..ToolSpec::base("item_get", item_get)
};

fn resolve(value: &Value) -> Result<u64, ToolError> {
    let addr = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok()),
        _ => None,
    };
    match addr {
        Some(a) if a >= BASE && (a - BASE).is_multiple_of(STEP) => Ok(a),
        _ => {
            let query = value.as_str().unwrap_or_default();
            let names: Vec<String> = (0..40).map(|i| format!("func_{i:04}")).collect();
            let mut fuel = ghidorah_base::Fuel::new(100_000);
            let found = did_you_mean(query, names.iter().map(String::as_str), &mut fuel);
            Err(ToolError::new(ErrorCode::NotFound)
                .var("kind", "item")
                .detail("kind", Value::from("item"))
                .candidates(
                    found
                        .iter()
                        .map(|s| Candidate::text(&s.name, "item"))
                        .collect(),
                )
                .next(Call::new(
                    "item_list",
                    Value::object(Vec::<(&str, Value)>::new()),
                    "List the items to find the address.",
                )))
        }
    }
}

fn get_one(host: &TestHost, addr: u64, include: &[Value]) -> Value {
    let mut out = Object::new();
    out.push("id", Value::from(format!("fn:{addr:#x}")));
    out.push("addr", Value::from(format!("{addr:#x}")));
    for section in include.iter().filter_map(Value::as_str) {
        let text = match section {
            "summary" => format!("{} has {} bytes.", item_name(host, addr), item_size(addr)),
            _ => format!("The body of {} is empty.", item_name(host, addr)),
        };
        out.push(section, Value::from(text));
    }
    Value::Object(out)
}

fn item_get(host: &mut TestHost, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let include = args.list("include").unwrap_or_default();
    if let Some(target) = args.get("target") {
        let addr = resolve(target)?;
        let Value::Object(object) = get_one(host, addr, include) else {
            return Err(ToolError::new(ErrorCode::InternalError));
        };
        return Ok(Payload::Object(object));
    }
    let mut items = Vec::new();
    for target in args.list("targets").unwrap_or_default() {
        items.push(get_one(host, resolve(target)?, include));
    }
    Ok(Payload::Object(Object::from_iter([(
        "items",
        Value::Array(items),
    )])))
}

// item_edit ------------------------------------------------------------------------------

const EVIDENCE: ArgSpec = ArgSpec::new("evidence_item", Role::Param, ArgKind::Str(200), "One ID.");

const EDIT_ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "action",
        Role::Selector,
        ArgKind::Enum(&["create", "rename", "delete"]),
        "The edit action.",
    )
    .required(),
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The address of the item.",
    )
    .required_when(&[
        ("action", "create"),
        ("action", "rename"),
        ("action", "delete"),
    ]),
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(64),
        "The new name of the item.",
    )
    .required_when(&[("action", "create"), ("action", "rename")])
    .forbidden_when(&[("action", "delete")]),
    ArgSpec::new(
        "evidence",
        Role::Param,
        ArgKind::List(&EVIDENCE, 16),
        "IDs that support the name.",
    )
    .forbidden_when(&[("action", "delete")]),
];

const EDIT_FIELDS: &[Field] = &[
    Field::req("action", OutputShape::Str),
    Field::req("target", OutputShape::Addr),
    Field::opt("old", OutputShape::Str),
    Field::opt("new", OutputShape::Str),
];

/// `item_edit`: a selector tool that edits.
pub const ITEM_EDIT: ToolSpec<TestHost> = ToolSpec {
    title: "Edit test items",
    summary: "Edit the test items: create, rename or delete one item.",
    description: "Edit the test items: create, rename or delete one item. \
                  Each action has its own required arguments. The delete action is destructive.",
    args: EDIT_ARGS,
    actions: &[
        ActionSpec {
            value: "create",
            line: "Create an item at target with the name in name.",
            example: r#"{"action":"create","target":"0x402000","name":"main"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "rename",
            line: "Rename the item at target to name, with optional evidence.",
            example: r#"{"action":"rename","target":"0x401000","name":"init","evidence":["fn:0x401000"]}"#,
            destructive: false,
        },
        ActionSpec {
            value: "delete",
            line: "Delete the item at target. This action is destructive.",
            example: r#"{"action":"delete","target":"0x401000"}"#,
            destructive: true,
        },
    ],
    output: OutputShape::Obj(EDIT_FIELDS),
    annotations: Annotations {
        read_only: false,
        destructive: true,
        idempotent: true,
        open_world: false,
    },
    reads_tables: &[Table::Functions, Table::Symbols],
    mutating: true,
    analysis_affecting: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: r#"{"action":"create","target":"0x402000","name":"main"}"#,
            golden: "tests/golden/tools/test/item_edit.1.json",
        },
        Example {
            args: r#"{"action":"rename","target":"0x401000","name":"init","evidence":["fn:0x401000"]}"#,
            golden: "tests/golden/tools/test/item_edit.2.json",
        },
        Example {
            args: r#"{"action":"delete","target":"0x401000"}"#,
            golden: "tests/golden/tools/test/item_edit.3.json",
        },
        Example {
            args: r#"{"action":"rename","target":"0x401010","name":"x","dry_run":true,"expected_rev":7,"force":true}"#,
            golden: "tests/golden/tools/test/item_edit.4.json",
        },
    ],
    force: true,
    ..ToolSpec::base("item_edit", item_edit)
};

fn item_edit(host: &mut TestHost, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let action = args.action().unwrap_or_default().to_owned();
    let addr = resolve(args.get("target").unwrap_or(&Value::Null))?;
    let old = item_name(host, addr);
    let new = args.str("name").unwrap_or_default().to_owned();
    let mut out = Object::new();
    out.push("action", Value::from(action.as_str()));
    out.push("target", Value::from(format!("{addr:#x}")));
    if action != "delete" {
        out.push("old", Value::from(old.as_str()));
        out.push("new", Value::from(new.as_str()));
    }
    let noop = action == "rename" && old == new;
    let dry = args.globals().dry_run;
    if !dry && !noop {
        host.rev += 1;
        host.names.insert(addr, new);
        ctx.frame.rev = host.rev;
    }
    ctx.mutation = Some(ghidorah_tools::envelope::Mutation {
        tx: (!dry && !noop).then(|| format!("tx:{}", host.rev)),
        noop,
        diff: dry.then(|| {
            Value::Array(vec![Value::object([
                ("op", Value::from("SetName")),
                ("key", Value::from(format!("fn:{addr:#x}"))),
                ("old", Value::from(old.as_str())),
                ("new", Value::from(args.str("name").unwrap_or_default())),
            ])])
        }),
    });
    Ok(Payload::Object(out))
}

// echo_value -----------------------------------------------------------------------------

const ECHO_ARGS: &[ArgSpec] = &[
    ArgSpec::new("value", Role::Param, ArgKind::Json, "Any JSON value.").required(),
    ArgSpec::new(
        "flag",
        Role::Param,
        ArgKind::Bool,
        "A flag that the tool gives back.",
    ),
    ArgSpec::new(
        "tag",
        Role::Param,
        ArgKind::Id(&[IdKind::Note, IdKind::Set]),
        "A note ID or a set ID.",
    ),
];

const ECHO_FIELDS: &[Field] = &[
    Field::req("value", OutputShape::Any),
    Field::opt("flag", OutputShape::Bool),
    Field::opt("tag", OutputShape::Nullable(&OutputShape::Str)),
];

/// `echo_value`: a tool with no binary.
pub const ECHO_VALUE: ToolSpec<TestHost> = ToolSpec {
    title: "Echo a value",
    summary: "Echo a JSON value with an optional flag and tag.",
    description: "Echo a JSON value with an optional flag and tag. The tool needs no binary.",
    args: ECHO_ARGS,
    output: OutputShape::Obj(ECHO_FIELDS),
    examples: &[Example {
        args: r#"{"value":{"a":[1,2]},"flag":true,"tag":"note:3"}"#,
        golden: "tests/golden/tools/test/echo_value.1.json",
    }],
    binary: BinaryArg::None,
    ..ToolSpec::base("echo_value", echo_value)
};

fn echo_value(_host: &mut TestHost, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let mut out = Object::new();
    out.push("value", args.get("value").cloned().unwrap_or_default());
    if let Some(flag) = args.bool("flag") {
        out.push("flag", Value::Bool(flag));
    }
    out.push("tag", args.str("tag").map(Value::from).unwrap_or_default());
    Ok(Payload::Object(out))
}

// fuel_run -------------------------------------------------------------------------------

const FUEL_ARGS: &[ArgSpec] = &[ArgSpec::new(
    "work",
    Role::Param,
    ArgKind::Int {
        min: 0,
        max: 1_000_000_000,
    },
    "The number of fuel units to use.",
)
.required()];

const FUEL_FIELDS: &[Field] = &[
    Field::req("used", OutputShape::Int),
    Field::req("cancelled", OutputShape::Bool),
];

/// `fuel_run`: a tool with fuel, progress and a cancel check.
pub const FUEL_RUN: ToolSpec<TestHost> = ToolSpec {
    title: "Run a fuel test",
    summary: "Run a fuel test: use a number of work units from the fuel of the call.",
    description: "Run a fuel test: use a number of work units from the fuel of the call. \
                  The tool sends a progress report for each 100 units.",
    args: FUEL_ARGS,
    output: OutputShape::Obj(FUEL_FIELDS),
    examples: &[Example {
        args: r#"{"work":10,"max_steps":100,"max_ms":1000}"#,
        golden: "tests/golden/tools/test/fuel_run.1.json",
    }],
    binary: BinaryArg::Optional,
    fuel: Some(FuelSpec {
        default: 1_000,
        cap: 100_000,
    }),
    ..ToolSpec::base("fuel_run", fuel_run)
};

fn fuel_run(_host: &mut TestHost, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let work = u64::try_from(args.int("work").unwrap_or(0)).unwrap_or(0);
    let mut used = 0;
    let mut cancelled = false;
    while used < work {
        if ctx.cancelled() {
            cancelled = true;
            break;
        }
        if ctx.fuel.tick().is_err() {
            return Err(ToolError::new(ErrorCode::BudgetExceeded).next(Call::new(
                "fuel_run",
                Value::object([("work", int(work)), ("max_steps", int(work))]),
                "Run the work again with enough fuel.",
            )));
        }
        used += 1;
        if used % 100 == 0 {
            ctx.progress(ghidorah_tools::Progress {
                progress: used,
                total: Some(work),
                message: "The test work runs.".to_owned(),
            });
        }
    }
    Ok(Payload::Object(Object::from_iter([
        ("used", int(used)),
        ("cancelled", Value::Bool(cancelled)),
    ])))
}
