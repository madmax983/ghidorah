//! The IR text and JSON printers.

#![allow(
    clippy::expect_used,
    reason = "the sample builder fails the test with a message"
)]

use ghidorah_ir::arena::op_at;
use ghidorah_ir::print::{self, IntrinsicNames, NoNames};
use ghidorah_ir::{
    Arena, Arg, Builder, Cc, Effect, FlagOp, IntrinsicId, Loc, LocSet, MemEffect, OpId, Opc,
};

struct Names;

impl IntrinsicNames for Names {
    fn name(&self, id: IntrinsicId) -> Option<&'static str> {
        (id.0 == 7).then_some("cpuid")
    }
}

fn sample() -> Arena {
    let mut b = Builder::new();
    b.begin(0x1000, 3).expect("begin");
    let v0 = b.get(Loc::RAX).expect("get");
    let v1 = b.binary(Opc::Add, 64, Arg::V(v0), Arg::k(8)).expect("add");
    b.put(Loc::RAX, Arg::V(v1)).expect("put");
    b.begin(0x1003, 2).expect("begin");
    let v2 = b.get(Loc::Flags).expect("get");
    let v3 = b
        .flags(FlagOp::X86Sub, 32, Arg::V(v0), Arg::V(v1), Arg::V(v2))
        .expect("flags");
    let v4 = b.cond(Cc::X86(5), Arg::V(v3)).expect("cond");
    b.flow(Opc::CJump, Arg::V(v4), Arg::k(0x1000))
        .expect("cjump");
    let v5 = b.extend(false, 64, 32, Arg::V(v1)).expect("zext");
    let effect = Effect {
        name: IntrinsicId(7),
        defs: [Loc::RAX, Loc::RBX].into_iter().collect::<LocSet>(),
        uses: [Loc::RAX, Loc::Flags].into_iter().collect::<LocSet>(),
        mem: MemEffect::Read { size: 8 },
    };
    b.effect_op(Opc::Intrinsic, effect, Arg::V(v0))
        .expect("intrinsic");
    let mut arena = b.finish();
    let list = arena
        .push_phi_args(vec![Arg::V(v1), Arg::V(v5)])
        .expect("phi list");
    let phi = op_at(
        OpId {
            addr: 0x1003,
            seq: 0x8000,
        },
        Opc::Phi,
        64,
        0,
        [Arg::k(u64::from(list)), Arg::Nil, Arg::Nil],
    );
    arena.push_op(phi).expect("phi");
    arena
}

const TEXT: &str = "\
0x1000 len=3
  op:0x1000:0 v0 = Get.64 rax
  op:0x1000:1 v1 = Add.64 v0 0x8
  op:0x1000:2 Put.64 rax v1
0x1003 len=2
  op:0x1003:0 v2 = Get.16 flags
  op:0x1003:1 v3 = Flags.32 X86Sub v0 v1 v2
  op:0x1003:2 v4 = Cond.1 ne v3
  op:0x1003:3 CJump.64 v4 0x1000
  op:0x1003:4 v5 = ZExt.64 #32 v1
  op:0x1003:5 Intrinsic.64 name=cpuid defs=[rax,rbx] uses=[rax,flags] mem=read:8 v0
extra
  op:0x1003:32768 v6 = Phi.64 [v1, v5]
";

#[test]
fn text_form() {
    let arena = sample();
    assert_eq!(print::text(&arena, &Names), TEXT);
    assert_eq!(print::text(&arena, &Names), print::text(&sample(), &Names));
    let unnamed = print::text(&arena, &NoNames);
    assert!(unnamed.contains("Intrinsic.64 name=#7 "), "{unnamed}");
    let op = &arena.ops()[1];
    assert_eq!(print::op_text(&arena, op, &NoNames), "v1 = Add.64 v0 0x8");
}

#[test]
fn json_form() {
    let arena = sample();
    let json = print::json(&arena, &Names);
    let want = concat!(
        r#"{"insns":[{"addr":"0x1000","len":3,"ops":["#,
        r#"{"id":"op:0x1000:0","opc":"Get","w":64,"out":"v0","args":["rax"]},"#,
        r#"{"id":"op:0x1000:1","opc":"Add","w":64,"out":"v1","args":["v0","0x8"]},"#,
        r#"{"id":"op:0x1000:2","opc":"Put","w":64,"args":["rax","v1"]}]},"#,
        r#"{"addr":"0x1003","len":2,"ops":["#,
        r#"{"id":"op:0x1003:0","opc":"Get","w":16,"out":"v2","args":["flags"]},"#,
        r#"{"id":"op:0x1003:1","opc":"Flags","w":32,"out":"v3","sub":"X86Sub","args":["v0","v1","v2"]},"#,
        r#"{"id":"op:0x1003:2","opc":"Cond","w":1,"out":"v4","sub":"ne","args":["v3"]},"#,
        r#"{"id":"op:0x1003:3","opc":"CJump","w":64,"args":["v4","0x1000"]},"#,
        r#"{"id":"op:0x1003:4","opc":"ZExt","w":64,"out":"v5","sub":32,"args":["v1"]},"#,
        r#"{"id":"op:0x1003:5","opc":"Intrinsic","w":64,"args":["v0"],"#,
        r#""effect":{"name":"cpuid","defs":["rax","rbx"],"uses":["rax","flags"],"mem":"read:8"}}]}],"#,
        r#""extra":[{"id":"op:0x1003:32768","opc":"Phi","w":64,"out":"v6","args":[],"phi":["v1","v5"]}]}"#,
    );
    assert_eq!(json, want);
}

#[test]
fn empty_and_effect_forms() {
    let arena = Builder::new().finish();
    assert_eq!(print::text(&arena, &NoNames), "");
    assert_eq!(print::json(&arena, &NoNames), r#"{"insns":[],"extra":[]}"#);
    let mut b = Builder::new();
    b.begin(0x10, 2).expect("begin");
    let none = Effect {
        name: IntrinsicId(3),
        defs: LocSet::EMPTY,
        uses: LocSet::EMPTY,
        mem: MemEffect::None,
    };
    b.effect_op(Opc::Syscall, none, Arg::Nil).expect("syscall");
    for mem in [
        MemEffect::Write { size: 4 },
        MemEffect::ReadWrite { size: 0 },
    ] {
        b.effect_op(Opc::Intrinsic, Effect { mem, ..none }, Arg::Nil)
            .expect("intrinsic");
    }
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let text = print::text(&arena, &NoNames);
    assert!(
        text.contains("Syscall.64 name=#3 defs=[] uses=[] mem=none\n"),
        "{text}"
    );
    assert!(
        text.contains("mem=write:4\n") && text.contains("mem=readwrite:0\n"),
        "{text}"
    );
    assert!(text.ends_with("op:0x10:3 Ret.0\n"), "{text}");
    let json = print::json(&arena, &NoNames);
    assert!(
        json.contains(r##""effect":{"name":"#3","defs":[],"uses":[],"mem":"none"}"##),
        "{json}"
    );
}
