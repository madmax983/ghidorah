//! The test registry of the cli tests and its backend [`TestHost`].
//!
//! | Tool | Kind | Profiles |
//! |---|---|---|
//! | `item_list` | A list tool on the open binary `b1` | all |
//! | `echo_text` | A tool with no binary and one required text | `full`, `mini` |
//! | `wait_cancel` | A tool that waits for the cancel flag and sends progress | `full` |

#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

use std::time::Duration;

use ghidorah_base::{ErrorCode, IdKind};
use ghidorah_cli::{Backend, OpenError, Options};
use ghidorah_json::{Number, Object, Value};
use ghidorah_tools::dispatch::{Crash, CursorCall};
use ghidorah_tools::outshape::Field;
use ghidorah_tools::{
    AnalysisInfo, AnalysisState, ArgKind, ArgSpec, Args, BinaryArg, Ctx, Example, Frame, Globals,
    Host, Item, KeyPart, ListPayload, ListSpec, Members, OutputShape, Payload, Profile, Progress,
    Registry, Role, SortKey, ToolError, ToolSpec,
};

/// The open binary of the test host.
pub const BINARY: &str = "b1";

/// The rev of the test binary.
pub const REV: u64 = 1;

/// The address of the first item.
pub const BASE: u64 = 0x40_1000;

/// The server instructions of the test host.
pub const INSTRUCTIONS: &str = "Test server. Call item_list first.";

/// The host of the test registry.
#[derive(Debug)]
pub struct TestHost {
    /// The options of the backend.
    pub options: Options,
}

impl Host for TestHost {
    fn registry() -> Registry<Self> {
        Registry::new(TOOLS)
    }

    fn in_profile(&self, name: &str) -> bool {
        Self::registry().get(name).is_some_and(|(_, tool)| {
            tool.profiles.contains(&self.options.profile)
                && self.options.tools.as_ref().is_none_or(|t| t.contains(name))
        })
    }

    fn frame(
        &mut self,
        tool: &ToolSpec<Self>,
        globals: &Globals,
        request_session: Option<&str>,
    ) -> Result<Frame, ToolError> {
        let session = globals
            .session
            .as_deref()
            .or(request_session)
            .unwrap_or(&self.options.session)
            .to_owned();
        let bound = match (&globals.binary_id, tool.binary) {
            (_, BinaryArg::None) => None,
            (Some(id), _) if id == BINARY => Some(id.clone()),
            (Some(_), _) => return Err(ToolError::new(ErrorCode::UnknownBinary)),
            (None, _) => Some(BINARY.to_owned()),
        };
        Ok(Frame {
            rev: if bound.is_some() { REV } else { 0 },
            analysis: bound.as_ref().map(|_| AnalysisInfo {
                state: AnalysisState::Complete,
                rev: REV,
            }),
            binary_id: bound,
            session,
        })
    }

    fn coerce(&self, _kind: &ArgKind, _value: &Value) -> Option<Value> {
        None
    }

    fn members(&self, _frame: &Frame, _set: &str) -> Result<Members, ToolError> {
        Err(ToolError::new(ErrorCode::NotFound)
            .var("kind", "set")
            .detail("kind", Value::from("set")))
    }

    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String {
        let addr = match key.0.first() {
            Some(KeyPart::Int(v)) => *v,
            _ => 0,
        };
        format!("c{}:{addr:x}", call.tool_index)
    }

    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError> {
        cursor
            .strip_prefix(&format!("c{}:", call.tool_index))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .map(|addr| SortKey(vec![KeyPart::Int(addr)]))
            .ok_or_else(|| ToolError::new(ErrorCode::CursorInvalid))
    }

    fn on_panic(&mut self, _crash: &Crash) {}
}

impl Backend for TestHost {
    fn open(options: &Options) -> Result<Self, OpenError> {
        if options.open.iter().any(|id| id != BINARY) {
            return Err(OpenError::new(
                "The project does not exist. Remove the --open flag.",
            ));
        }
        Ok(Self {
            options: options.clone(),
        })
    }

    fn instructions(&self) -> String {
        INSTRUCTIONS.to_owned()
    }
}

/// The tools of the test registry in registry order.
pub static TOOLS: &[&ToolSpec<TestHost>] = &[&ITEM_LIST, &ECHO_TEXT, &WAIT_CANCEL];

fn int(value: u64) -> Value {
    Number::parse(&value.to_string()).map_or(Value::Null, Value::Number)
}

// item_list ------------------------------------------------------------------------------

const ITEM_FIELDS: &[Field] = &[
    Field::req("id", OutputShape::Id(IdKind::Func)),
    Field::req("addr", OutputShape::Addr),
    Field::req("name", OutputShape::Str),
];
const ITEM: OutputShape = OutputShape::Obj(ITEM_FIELDS);
const LIST_FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::List(&ITEM)),
    Field::opt("count", OutputShape::Int),
];

/// `item_list`: a list tool.
pub const ITEM_LIST: ToolSpec<TestHost> = ToolSpec {
    title: "List test items",
    summary: "List the test items of the open binary in address order.",
    description: "List the test items of the open binary in address order. \
                  The tool exists only in the cli test registry.",
    args: &[ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int { min: 0, max: 200 },
        "The number of items.",
    )
    .default_json("5")],
    output: OutputShape::Obj(LIST_FIELDS),
    examples: &[
        Example {
            args: "{}",
            golden: "tests/golden/mcp/test/item_list.1.json",
        },
        Example {
            args: r#"{"count":3,"limit":2}"#,
            golden: "tests/golden/mcp/test/item_list.2.json",
        },
    ],
    max_chars: 16_000,
    list: Some(ListSpec { default_limit: 50 }),
    ..ToolSpec::base("item_list", item_list)
};

fn item_list(_host: &mut TestHost, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let count = args
        .int("count")
        .and_then(|c| u64::try_from(c).ok())
        .unwrap_or(5);
    let items = (0..count)
        .map(|i| {
            let addr = BASE + i * 0x10;
            Item {
                key: SortKey(vec![KeyPart::Int(addr)]),
                value: Value::object([
                    ("id", Value::from(format!("fn:{addr:#x}"))),
                    ("addr", Value::from(format!("{addr:#x}"))),
                    ("name", Value::from(format!("item_{i}"))),
                ]),
            }
        })
        .collect();
    Ok(Payload::List(ListPayload::new(items)))
}

// echo_text ------------------------------------------------------------------------------

/// `echo_text`: a tool with no binary.
pub const ECHO_TEXT: ToolSpec<TestHost> = ToolSpec {
    title: "Echo a text",
    summary: "Echo the text of the call back to the client.",
    description: "Echo the text of the call back to the client. \
                  The tool exists only in the cli test registry.",
    args: &[ArgSpec::new(
        "text",
        Role::Param,
        ArgKind::Str(200),
        "The text to send back.",
    )
    .required()],
    output: OutputShape::Obj(&[Field::req("text", OutputShape::Str)]),
    profiles: &[Profile::Full, Profile::Mini],
    examples: &[Example {
        args: r#"{"text":"hello"}"#,
        golden: "tests/golden/mcp/test/echo_text.1.json",
    }],
    binary: BinaryArg::None,
    ..ToolSpec::base("echo_text", echo_text)
};

fn echo_text(_host: &mut TestHost, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let text = args.str("text").unwrap_or_default();
    Ok(Payload::Object(Object::from_iter([(
        "text",
        Value::from(text),
    )])))
}

// wait_cancel ----------------------------------------------------------------------------

/// `wait_cancel`: a tool that waits until the client cancels the call.
pub const WAIT_CANCEL: ToolSpec<TestHost> = ToolSpec {
    title: "Wait for a cancel",
    summary: "Wait until the client cancels the call, for at most ms milliseconds.",
    description: "Wait until the client cancels the call, for at most ms milliseconds. \
                  The tool sends progress before the wait. \
                  The tool exists only in the cli test registry.",
    args: &[ArgSpec::new(
        "ms",
        Role::Param,
        ArgKind::Int {
            min: 0,
            max: 10_000,
        },
        "The longest wait in milliseconds.",
    )
    .default_json("0")],
    output: OutputShape::Obj(&[
        Field::req("cancelled", OutputShape::Bool),
        Field::req("waited_ms", OutputShape::Int),
    ]),
    profiles: &[Profile::Full],
    examples: &[Example {
        args: r#"{"ms":0}"#,
        golden: "tests/golden/mcp/test/wait_cancel.1.json",
    }],
    binary: BinaryArg::None,
    ..ToolSpec::base("wait_cancel", wait_cancel)
};

fn wait_cancel(_host: &mut TestHost, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let ms = args
        .int("ms")
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    let report = |progress| Progress {
        progress,
        total: Some(3),
        message: "The wait runs.".to_owned(),
    };
    ctx.progress(report(1));
    // The progress sender drops a report that does not increase.
    ctx.progress(report(1));
    ctx.progress(report(2));
    let mut waited = 0;
    while waited < ms && !ctx.cancelled() {
        std::thread::sleep(Duration::from_millis(1));
        waited += 1;
    }
    Ok(Payload::Object(Object::from_iter([
        ("cancelled", Value::Bool(ctx.cancelled())),
        ("waited_ms", int(waited)),
    ])))
}
