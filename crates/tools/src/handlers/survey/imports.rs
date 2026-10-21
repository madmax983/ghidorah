//! The `imports` section of `binary_survey`: the libraries and the imports in groups by
//! Tier-0 category. PE imports group by DLL first (design Section 10.4).

use std::collections::BTreeMap;

use ghidorah_base::Caps;
use ghidorah_db::Types;
use ghidorah_json::{Object, Value};

use super::parts::{Ctx, Part};
use crate::handlers::func_sections as fs;

/// The libraries and the imports in groups by Tier-0 category. PE imports group by DLL in
/// library order first, and each item names its DLL. An import by ordinal shows `#<ordinal>`.
pub(super) fn part(c: &Ctx<'_>) -> Part {
    let p = c.program;
    let libraries: Vec<String> = (p.binary().libraries.iter())
        .map(|l| fs::safe(&l.render(Caps::DETAILED).text))
        .collect();
    let mut grouped: BTreeMap<(usize, usize, String), Value> = BTreeMap::new();
    for row in p.imports().values() {
        let name = match (row.id.name(), row.id.ordinal()) {
            (Some(n), _) => n.to_owned(),
            (None, Some(o)) => format!("#{o}"),
            (None, None) => row.id.to_string(),
        };
        let category = Types::prototype(&name).map(|proto| proto.category);
        let order = category.map_or(usize::MAX, |cat| {
            ghidorah_types::Category::ALL
                .iter()
                .position(|x| *x == cat)
                .unwrap_or(usize::MAX)
        });
        let dll = row.id.lib();
        let group = dll.map_or(0, |d| {
            (libraries.iter())
                .position(|x| x.eq_ignore_ascii_case(d))
                .unwrap_or(usize::MAX)
        });
        let mut out = Object::new();
        out.push("id", Value::from(row.id.to_string()));
        if let Some(d) = dll {
            out.push("dll", Value::from(fs::safe(d)));
        }
        out.push("name", Value::from(c.namer.text(&name)));
        out.push(
            "category",
            Value::from(category.map_or("other", |cat| cat.name())),
        );
        if row.delay {
            out.push("delay", Value::Bool(true));
        }
        grouped.insert((group, order, row.id.to_string()), Value::Object(out));
    }
    let mut head = Object::new();
    let libraries = libraries.into_iter().map(Value::from).collect();
    head.push("libraries", Value::Array(libraries));
    Part::listed(
        head,
        "items",
        grouped.into_values().collect(),
        Some("import"),
    )
}
