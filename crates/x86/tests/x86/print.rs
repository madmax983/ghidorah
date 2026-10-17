//! Printer tests: display rules of design Section 5.4.

use ghidorah_x86::{NoSymbols, Symbolizer, print};

use crate::common::{dec, hex};

fn text(bytes: &str, addr: u64) -> String {
    let insn = dec(&hex(bytes), addr).unwrap_or_else(|e| panic!("{bytes}: {e}"));
    print(&insn, &NoSymbols)
}

#[test]
fn display_texts() {
    let cases: &[(&str, &str)] = &[
        ("48 89 e5", "mov rbp, rsp"),
        ("48 83 ec 08", "sub rsp, 0x8"),
        (
            "48 8b 05 10 00 00 00",
            "mov rax, qword ptr [rip+0x10] ; 0x1017",
        ),
        (
            "48 8b 05 f0 ff ff ff",
            "mov rax, qword ptr [rip-0x10] ; 0xff7",
        ),
        ("e8 00 00 00 00", "call 0x1005"),
        ("f3 c3", "repz ret"),
        ("f2 c3", "bnd ret"),
        ("3e ff e0", "notrack jmp rax"),
        (
            "66 2e 0f 1f 84 00 00 00 00 00",
            "cs nop word ptr [rax+rax*1+0x0]",
        ),
        (
            "66 66 2e 0f 1f 84 00 00 00 00 00",
            "data16 cs nop word ptr [rax+rax*1+0x0]",
        ),
        ("66 90", "xchg ax, ax"),
        (
            "f3 48 a5",
            "rep movs qword ptr es:[rdi], qword ptr ds:[rsi]",
        ),
        ("f2 ae", "repnz scas al, byte ptr es:[rdi]"),
        ("f0 0f b1 0a", "lock cmpxchg dword ptr [rdx], ecx"),
        ("64 48 8b 04 25 28 00 00 00", "mov rax, qword ptr fs:[0x28]"),
        ("8b 04 25 00 10 00 00", "mov eax, dword ptr [0x1000]"),
        ("a1 00 10 00 00 00 00 00 00", "movabs eax, [0x1000]"),
        ("d1 e0", "shl eax, 1"),
        ("c1 e0 03", "shl eax, 0x3"),
        ("0f c2 c1 01", "cmpltps xmm0, xmm1"),
        ("f2 0f c2 c1 08", "cmpsd xmm0, xmm1, 0x8"),
        ("d8 c1", "fadd st, st(1)"),
        ("dc c1", "fadd st(1), st"),
        ("c5 f8 77", "(vector 0f 77)"),
        ("c4 e2 79 f7 c0", "(vector 0f38 f7)"),
        ("62 f1 6c 48 58 d9", "(vector 0f 58)"),
        ("d5 10 89 c0", "(vector map0 89)"),
        ("66 0f 3a 0f c1 04", "(vector 0f3a 0f)"),
        ("67 e8 00 00 00 00", "addr32 call 0x1006"),
        ("2e 74 00", "cs je 0x1003"),
        ("d7", "xlat byte ptr ds:[rbx]"),
        ("c8 10 00 00", "enter 0x10, 0x0"),
        ("6a ff", "push 0xffffffffffffffff"),
    ];
    for &(bytes, want) in cases {
        assert_eq!(text(bytes, 0x1000), want, "{bytes}");
    }
}

struct Names;

impl Symbolizer for Names {
    fn name(&self, addr: u64) -> Option<String> {
        (addr == 0x1030).then(|| "puts@plt".to_owned())
    }

    fn note(&self, addr: u64) -> Option<String> {
        (addr == 0x3fc0).then(|| "__libc_start_main".to_owned())
    }
}

#[test]
fn symbolizer_names() {
    let call = dec(&hex("e8 2b 00 00 00"), 0x1000).expect("call");
    assert_eq!(print(&call, &Names), "call puts@plt");
    let other = dec(&hex("e8 00 00 00 00"), 0x1000).expect("call");
    assert_eq!(print(&other, &Names), "call 0x1005");
    let got = dec(&hex("ff 15 ba 2f 00 00"), 0x1000).expect("call via the GOT");
    assert_eq!(
        print(&got, &Names),
        "call qword ptr [rip+0x2fba] ; __libc_start_main"
    );
}

#[test]
fn regress_bnd_only_on_near_branches() {
    // GNU objdump prints `bnd` for `F2` on `jcc`, `jmp`, `call` and `ret` only.
    let cases: &[(&str, &str)] = &[
        ("f2 cc", "repnz int3"),
        ("f2 e2 00", "repnz loop 0x1003"),
        ("f2 0f 0b", "repnz ud2"),
        ("f2 74 00", "bnd je 0x1003"),
        ("f2 ff 20", "bnd jmp qword ptr [rax]"),
        ("f2 e8 00 00 00 00", "bnd call 0x1006"),
        ("64 90", "fs nop"),
        ("2e aa", "cs stos byte ptr es:[rdi], al"),
    ];
    for &(bytes, want) in cases {
        assert_eq!(text(bytes, 0x1000), want, "{bytes}");
    }
}
