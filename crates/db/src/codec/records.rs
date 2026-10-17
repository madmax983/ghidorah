//! The [`Json`] forms of the records: functions, variables, why-records, fact keys and notes.

use ghidorah_base::{Address, FuncId};
use ghidorah_json::{DecodeKind, Value};

use super::values::{Json, Off, obj, text};
use super::{CodecError, Obj, Reason};
use crate::funcs::{Caveat, FuncFlags, Function, Part};
use crate::notes::{Claim, Note, NoteSet, SetMembers};
use crate::vars::VarFact;
use crate::why::{FactKey, Why};

impl Json for Part {
    fn enc(&self) -> Value {
        obj([("range", self.range.enc()), ("kind", self.kind.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["range", "kind"])?;
        Ok(Self {
            range: o.get("range")?,
            kind: o.get("kind")?,
        })
    }
}

impl Json for Caveat {
    fn enc(&self) -> Value {
        obj([
            ("code", self.code.enc()),
            ("at", self.at.enc()),
            ("remedy", self.remedy.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["code", "at", "remedy"])?;
        Ok(Self {
            code: o.get("code")?,
            at: o.get("at")?,
            remedy: o.get("remedy")?,
        })
    }
}

/// The member names of a function record.
const FUNC_NAMES: [&str; 11] = [
    "entry",
    "body",
    "parts",
    "sig",
    "noreturn",
    "thunk",
    "varargs",
    "start_reason",
    "confidence",
    "caveats",
    "source",
];

impl Json for Function {
    fn enc(&self) -> Value {
        obj([
            ("entry", self.entry.enc()),
            ("body", self.body.enc()),
            ("parts", self.parts.enc()),
            ("sig", self.sig.enc()),
            ("noreturn", self.flags.noreturn.enc()),
            ("thunk", self.flags.thunk.enc()),
            ("varargs", self.flags.varargs.enc()),
            ("start_reason", self.start_reason.enc()),
            ("confidence", self.confidence.enc()),
            ("caveats", self.caveats.enc()),
            ("source", self.source.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &FUNC_NAMES)?;
        let confidence: u8 = o.get("confidence")?;
        if confidence > 100 {
            return Err(CodecError::new(Reason::Json(DecodeKind::Range)).at("confidence"));
        }
        Ok(Self {
            entry: o.get("entry")?,
            body: o.get("body")?,
            parts: o.get("parts")?,
            sig: o.get("sig")?,
            flags: FuncFlags {
                noreturn: o.get("noreturn")?,
                thunk: o.get("thunk")?,
                varargs: o.get("varargs")?,
            },
            start_reason: o.get("start_reason")?,
            confidence,
            caveats: o.get("caveats")?,
            source: o.get("source")?,
        })
    }
}

impl Json for VarFact {
    fn enc(&self) -> Value {
        obj([("name", self.name.enc()), ("ty", self.ty.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["name", "ty"])?;
        Ok(Self {
            name: o.get("name")?,
            ty: o.get("ty")?,
        })
    }
}

impl Json for Why {
    fn enc(&self) -> Value {
        obj([("rule", self.rule.enc()), ("premises", self.premises.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["rule", "premises"])?;
        Ok(Self {
            rule: o.get("rule")?,
            premises: o.get("premises")?,
        })
    }
}

impl Json for FactKey {
    fn enc(&self) -> Value {
        let at = |k: &str, off: u64| obj([("k", Value::from(k)), ("at", Off(off).enc())]);
        let addr = |k: &str, a: &Address| obj([("k", Value::from(k)), ("at", a.enc())]);
        let func = |k: &str, f: &FuncId| obj([("k", Value::from(k)), ("func", f.enc())]);
        match self {
            Self::CodeUnit(o) => at("code_unit", *o),
            Self::Data(o) => at("data", *o),
            Self::Entry(o) => at("entry", *o),
            Self::Reloc(o) => at("reloc", *o),
            Self::Fde(o) => at("fde", *o),
            Self::Symbol(a, key) => obj([
                ("k", Value::from("symbol")),
                ("addr", a.enc()),
                ("key", key.enc()),
            ]),
            Self::Func(f) => func("func", f),
            Self::Signature(f) => func("signature", f),
            Self::Noreturn(f) => func("noreturn", f),
            Self::Ref(r) => obj([("k", Value::from("ref")), ("ref", r.enc())]),
            Self::Comment(a, kind) => obj([
                ("k", Value::from("comment")),
                ("addr", a.enc()),
                ("kind", kind.enc()),
            ]),
            Self::JumpTable(j) => addr("jump_table", &j.0),
            Self::FlowOverride(a) => addr("flow_override", a),
            Self::Str(s) => addr("string", &s.0),
            Self::Var(var) => obj([("k", Value::from("var")), ("var", var.enc())]),
            Self::Import(i) => obj([("k", Value::from("import")), ("id", i.enc())]),
            Self::Export(e) => obj([("k", Value::from("export")), ("id", e.enc())]),
            Self::Note(n) => obj([("k", Value::from("note")), ("note", n.enc())]),
        }
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let kind = v.get("k").ok_or_else(|| CodecError::kind("object", v))?;
        let kind = text(kind).map_err(|e| e.at("k"))?;
        let with = |name: &str| Obj::new(v, &["k", name]);
        let off = || -> Result<u64, CodecError> { Ok(with("at")?.get::<Off>("at")?.0) };
        Ok(match kind {
            "code_unit" => Self::CodeUnit(off()?),
            "data" => Self::Data(off()?),
            "entry" => Self::Entry(off()?),
            "reloc" => Self::Reloc(off()?),
            "fde" => Self::Fde(off()?),
            "symbol" => {
                let o = Obj::new(v, &["k", "addr", "key"])?;
                Self::Symbol(o.get("addr")?, o.get("key")?)
            }
            "func" => Self::Func(with("func")?.get("func")?),
            "signature" => Self::Signature(with("func")?.get("func")?),
            "noreturn" => Self::Noreturn(with("func")?.get("func")?),
            "ref" => Self::Ref(with("ref")?.get("ref")?),
            "comment" => {
                let o = Obj::new(v, &["k", "addr", "kind"])?;
                Self::Comment(o.get("addr")?, o.get("kind")?)
            }
            "jump_table" => Self::JumpTable(with("at")?.get("at")?),
            "flow_override" => Self::FlowOverride(with("at")?.get("at")?),
            "string" => Self::Str(with("at")?.get("at")?),
            "var" => Self::Var(with("var")?.get("var")?),
            "import" => Self::Import(with("id")?.get("id")?),
            "export" => Self::Export(with("id")?.get("id")?),
            "note" => Self::Note(with("note")?.get("note")?),
            _ => return Err(CodecError::text("fact key").at("k")),
        })
    }
}

impl Json for Claim {
    fn enc(&self) -> Value {
        obj([("rel", self.rel.enc()), ("args", self.args.enc())])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &["rel", "args"])?;
        Ok(Self {
            rel: o.get("rel")?,
            args: o.get("args")?,
        })
    }
}

impl Json for NoteSet {
    fn enc(&self) -> Value {
        let name = ("name", self.name.enc());
        match &self.members {
            SetMembers::Addrs(r) => obj([name, ("addrs", r.enc())]),
            SetMembers::Ids(ids) => obj([name, ("ids", ids.enc())]),
        }
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        if v.get("addrs").is_some() {
            let o = Obj::new(v, &["name", "addrs"])?;
            return Ok(Self {
                name: o.get("name")?,
                members: SetMembers::Addrs(o.get("addrs")?),
            });
        }
        let o = Obj::new(v, &["name", "ids"])?;
        Ok(Self {
            name: o.get("name")?,
            members: SetMembers::Ids(o.get("ids")?),
        })
    }
}

/// The member names of a note.
const NOTE_NAMES: [&str; 13] = [
    "id", "kind", "text", "at", "func", "status", "tags", "evidence", "claims", "set", "src",
    "session", "rev",
];

impl Json for Note {
    fn enc(&self) -> Value {
        obj([
            ("id", self.id.enc()),
            ("kind", self.kind.enc()),
            ("text", self.text.enc()),
            ("at", self.at.enc()),
            ("func", self.func.enc()),
            ("status", self.status.enc()),
            ("tags", self.tags.enc()),
            ("evidence", self.evidence.enc()),
            ("claims", self.claims.enc()),
            ("set", self.set.enc()),
            ("src", self.src.enc()),
            ("session", self.session.enc()),
            ("rev", self.rev.enc()),
        ])
    }

    fn dec(v: &Value) -> Result<Self, CodecError> {
        let o = Obj::new(v, &NOTE_NAMES)?;
        Ok(Self {
            id: o.get("id")?,
            kind: o.get("kind")?,
            text: o.get("text")?,
            at: o.get("at")?,
            func: o.get("func")?,
            status: o.get("status")?,
            tags: o.get("tags")?,
            evidence: o.get("evidence")?,
            claims: o.get("claims")?,
            set: o.get("set")?,
            src: o.get("src")?,
            session: o.get("session")?,
            rev: o.get("rev")?,
        })
    }
}
