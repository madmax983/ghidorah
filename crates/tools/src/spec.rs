//! The tool table types (design Section 10.1, ADR-0005).
//!
//! Each handler file exports `pub const SPEC: ToolSpec<Session>`. All surfaces come from these
//! tables: the schema, the argument parser, `tools/list`, the lint and the examples.
//! The type parameter `S` is the session type of the host (see [`crate::api::Host`]).

use ghidorah_base::IdKind;
use ghidorah_db::Table;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::OutputShape;

/// The handler of a tool: a plain function, not a `dyn` object.
///
/// The handler gets the session, the parsed arguments and the call context.
/// It returns full typed data. The pipeline projects, pages, trims and wraps it.
pub type Handler<S> = fn(&mut S, &Args, &mut Ctx) -> Result<Payload, ToolError>;

/// The role of an argument in the shared vocabulary (design Section 10.2).
///
/// Each role except [`Role::Param`] and [`Role::Selector`] has one fixed name.
/// The registry lint checks the names (AC-222).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// One entity that the call acts on: `target`.
    Target,
    /// A list of entities: `targets`.
    Targets,
    /// A program point or an anchor: `at`.
    At,
    /// A set filter: `in`.
    In,
    /// Fuel: `max_steps`.
    Fuel,
    /// The output budget: `max_chars`.
    Budget,
    /// The page size: `limit`.
    PageSize,
    /// The page cursor: `cursor`.
    PageCursor,
    /// The action selector of a selector tool, for example `action`.
    Selector,
    /// Any other argument. Its name is free.
    Param,
}

impl Role {
    /// Gives the fixed name of the role, or `None` for a role with a free name.
    #[must_use]
    pub const fn fixed_name(self) -> Option<&'static str> {
        match self {
            Self::Target => Some("target"),
            Self::Targets => Some("targets"),
            Self::At => Some("at"),
            Self::In => Some("in"),
            Self::Fuel => Some("max_steps"),
            Self::Budget => Some("max_chars"),
            Self::PageSize => Some("limit"),
            Self::PageCursor => Some("cursor"),
            Self::Selector | Self::Param => None,
        }
    }
}

/// The kind of an argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// An address expression: a JSON integer below 2^53 or a string (ADR-0007).
    Addr,
    /// A list of address expressions with at most this many items.
    AddrList(usize),
    /// An ID of one of these kinds, for example `fn:0x401000`.
    Id(&'static [IdKind]),
    /// An integer in the closed range `min..=max`.
    Int {
        /// The smallest value.
        min: i64,
        /// The largest value. A larger value gives `LIMIT_EXCEEDED`.
        max: i64,
    },
    /// A string of at most this many characters.
    Str(usize),
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// `true` or `false`.
    Bool,
    /// An object with these members. Other keys give `UNKNOWN_ARGUMENT`.
    Obj(&'static [ArgSpec]),
    /// A list of items of the inner kind, with at most this many items.
    List(&'static ArgSpec, usize),
    /// Any JSON value.
    Json,
}

/// One argument of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgSpec {
    /// The name: `^[a-z][a-z0-9_]{0,40}$`.
    pub name: &'static str,
    /// The role in the vocabulary.
    pub role: Role,
    /// The kind of the value.
    pub kind: ArgKind,
    /// `true` when every call must give the argument.
    pub required: bool,
    /// The default value as JSON text, for example `"[\"summary\"]"`.
    pub default: Option<&'static str>,
    /// One STE sentence or two for the schema description.
    pub doc: &'static str,
    /// Other names that the parser accepts with `W_COERCED`. The schema shows none of them.
    pub aliases: &'static [&'static str],
    /// The call must give the argument when the selector argument has one of these values.
    ///
    /// Each pair is `(selector name, value)`.
    pub required_when: &'static [(&'static str, &'static str)],
    /// The argument is forbidden when the selector argument has one of these values.
    pub forbidden_when: &'static [(&'static str, &'static str)],
}

impl ArgSpec {
    /// Makes an optional argument with no default, no alias and no condition.
    #[must_use]
    pub const fn new(name: &'static str, role: Role, kind: ArgKind, doc: &'static str) -> Self {
        Self {
            name,
            role,
            kind,
            required: false,
            default: None,
            doc,
            aliases: &[],
            required_when: &[],
            forbidden_when: &[],
        }
    }

    /// Marks the argument as required.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Sets the default value as JSON text.
    #[must_use]
    pub const fn default_json(mut self, json: &'static str) -> Self {
        self.default = Some(json);
        self
    }

    /// Sets the aliases.
    #[must_use]
    pub const fn aliases(mut self, aliases: &'static [&'static str]) -> Self {
        self.aliases = aliases;
        self
    }

    /// Sets the selector values that make the argument required.
    #[must_use]
    pub const fn required_when(mut self, when: &'static [(&'static str, &'static str)]) -> Self {
        self.required_when = when;
        self
    }

    /// Sets the selector values that forbid the argument.
    #[must_use]
    pub const fn forbidden_when(mut self, when: &'static [(&'static str, &'static str)]) -> Self {
        self.forbidden_when = when;
        self
    }
}

/// The rule of an argument group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRule {
    /// Exactly one member must be present.
    ExactlyOne,
    /// At least one member must be present.
    AtLeastOne,
}

/// A group of arguments with a presence rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group {
    /// The argument names of the group.
    pub members: &'static [&'static str],
    /// The presence rule.
    pub rule: GroupRule,
}

/// One action of a selector tool (AC-129f, AC-221).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSpec {
    /// The selector value, for example `set_noreturn`.
    pub value: &'static str,
    /// One description line.
    pub line: &'static str,
    /// The JSON arguments of one example. The same text is an entry of [`ToolSpec::examples`].
    pub example: &'static str,
    /// `true` when the action destroys data, for example `delete`.
    pub destructive: bool,
}

/// One executed example of a tool (AC-132a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Example {
    /// The JSON arguments.
    pub args: &'static str,
    /// The golden file of the envelope, relative to the workspace root.
    pub golden: &'static str,
}

/// The four MCP annotations of a tool. `openWorldHint` is `false` for every tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the four MCP annotations are booleans"
)]
pub struct Annotations {
    /// `readOnlyHint`.
    pub read_only: bool,
    /// `destructiveHint`.
    pub destructive: bool,
    /// `idempotentHint`.
    pub idempotent: bool,
    /// `openWorldHint`.
    pub open_world: bool,
}

impl Annotations {
    /// The annotations of a read-only tool: read-only, not destructive, idempotent.
    pub const READ: Self = Self {
        read_only: true,
        destructive: false,
        idempotent: true,
        open_world: false,
    };

    /// The annotations of an idempotent edit tool.
    pub const EDIT: Self = Self {
        read_only: false,
        destructive: false,
        idempotent: true,
        open_world: false,
    };
}

/// A tool profile (design Section 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Profile {
    /// All tools.
    Full,
    /// The read-only tools.
    Readonly,
    /// The 10 core tools.
    Mini,
}

impl Profile {
    /// All profiles.
    pub const ALL: [Self; 3] = [Self::Full, Self::Readonly, Self::Mini];

    /// Gives the profile name: `full`, `readonly` or `mini`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Readonly => "readonly",
            Self::Mini => "mini",
        }
    }
}

/// How a tool takes the global `binary_id` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArg {
    /// The tool has no `binary_id`, for example `binary_load` and `tool_search`.
    None,
    /// The tool runs with or without an open binary, for example `session_brief`.
    Optional,
    /// The tool needs an open binary.
    Bound,
}

/// The list settings of a list tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListSpec {
    /// The page size when the call gives no `limit`.
    pub default_limit: u32,
}

/// The fuel settings of a tool with `max_steps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuelSpec {
    /// The fuel when the call gives no `max_steps`.
    pub default: u64,
    /// The largest `max_steps`.
    pub cap: u64,
}

/// One tool of the registry.
pub struct ToolSpec<S: 'static> {
    /// The name: `^[a-z][a-z0-9_]{0,40}$`.
    pub name: &'static str,
    /// The display title.
    pub title: &'static str,
    /// The first sentence of the description, keywords first.
    pub summary: &'static str,
    /// The description: at most 1,000 characters.
    pub description: &'static str,
    /// The arguments of the tool, without the global arguments.
    pub args: &'static [ArgSpec],
    /// The argument groups.
    pub groups: &'static [Group],
    /// The actions of a selector tool. Other tools have none.
    pub actions: &'static [ActionSpec],
    /// The shape of the envelope `data`.
    pub output: OutputShape,
    /// The MCP annotations.
    pub annotations: Annotations,
    /// The tables that the tool reads, for cursor checks.
    pub reads_tables: &'static [Table],
    /// `true` when the tool writes facts. It then takes `expected_rev` and `dry_run`.
    pub mutating: bool,
    /// `true` when the tool starts a re-analysis.
    pub analysis_affecting: bool,
    /// The profiles that hold the tool.
    pub profiles: &'static [Profile],
    /// The executed examples.
    pub examples: &'static [Example],
    /// How the tool takes `binary_id`.
    pub binary: BinaryArg,
    /// `true` when the tool takes `force`.
    pub force: bool,
    /// The default `max_chars` of the tool.
    pub max_chars: u32,
    /// The list settings. A list tool takes `limit`, `cursor`, `count_only`, `shape` and `in`.
    pub list: Option<ListSpec>,
    /// The fuel settings. A tool with fuel takes `max_steps` and `max_ms`.
    pub fuel: Option<FuelSpec>,
    /// The handler.
    pub handler: Handler<S>,
}

impl<S: 'static> ToolSpec<S> {
    /// Makes a read-only tool in every profile with no arguments, no examples and the
    /// default budget of 8,000 characters. Use struct update syntax for the other fields.
    #[must_use]
    pub const fn base(name: &'static str, handler: Handler<S>) -> Self {
        Self {
            name,
            title: "",
            summary: "",
            description: "",
            args: &[],
            groups: &[],
            actions: &[],
            output: OutputShape::Any,
            annotations: Annotations::READ,
            reads_tables: &[],
            mutating: false,
            analysis_affecting: false,
            profiles: &Profile::ALL,
            examples: &[],
            binary: BinaryArg::Bound,
            force: false,
            max_chars: crate::budget::OTHER_MAX_CHARS,
            list: None,
            fuel: None,
            handler,
        }
    }

    /// Gives the argument with `name`, or `None`.
    #[must_use]
    pub fn arg(&self, name: &str) -> Option<&'static ArgSpec> {
        self.args.iter().find(|a| a.name == name)
    }

    /// Gives the selector argument of a selector tool, or `None`.
    #[must_use]
    pub fn selector(&self) -> Option<&'static ArgSpec> {
        self.args.iter().find(|a| a.role == Role::Selector)
    }

    /// Gives the action with the selector value `value`, or `None`.
    #[must_use]
    pub fn action(&self, value: &str) -> Option<&'static ActionSpec> {
        self.actions.iter().find(|a| a.value == value)
    }
}
