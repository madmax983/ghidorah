//! Noreturn lists, the syscall table, calling conventions and data models.

use ghidorah_base::SyscallId;
use ghidorah_types::noreturn::{self, NoreturnList, match_name};
use ghidorah_types::syscalls::{self, ARG_REGS, NUMBER_REG, SyscallTable};
use ghidorah_types::{
    CALL_CONVS, DataError, DataModel, NORETURN_BY_FORMAT, Prim, SizeAlign, call_conv, cc,
    noreturn_list,
};

#[test]
fn elf_noreturn_list() {
    let list = noreturn::elf().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(list.len(), 21, "the Ghidra ELF list has 21 names");
    assert!(!list.is_empty());
    for name in [
        "exit",
        "_exit",
        "abort",
        "__stack_chk_fail",
        "__assert_fail",
        "__longjmp_chk",
        "longjmp",
        "_Unwind_Resume",
        "__cxa_throw",
        "_ZSt9terminatev",
        "exit@GLIBC_2.2.5",
        "__fortify_fail@@GLIBC_PRIVATE",
        "pthread_exit",
    ] {
        assert!(list.contains(name), "{name}");
    }
    for name in ["printf", "", "_", "exit2", "Exit", "atexit"] {
        assert!(!list.contains(name), "{name}");
    }
    let names: Vec<&str> = list.names().collect();
    assert!(names.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(match_name("__stack_chk_fail@GLIBC_2.4"), "stack_chk_fail");
    assert_eq!(match_name("puts"), "puts");
    assert_eq!(match_name("___"), "");
}

#[test]
fn noreturn_list_by_format() {
    let elf = noreturn_list("elf64-le")
        .expect("elf list")
        .expect("parses");
    assert!(elf.contains("abort"));
    assert!(noreturn_list("raw").is_none());
    assert!(noreturn_list("").is_none());
    assert_eq!(NORETURN_BY_FORMAT.len(), 1);
}

#[test]
fn noreturn_list_errors() {
    let cases: &[(&'static str, u32)] = &[
        ("exit\n_exit\n", 2),
        ("# header\nexit\nbad-name\n", 3),
        ("exit\nabort\nexit\n", 3),
        ("ex it\n", 1),
    ];
    for (text, line) in cases {
        let err = NoreturnList::parse("t.txt", text).expect_err(text);
        assert_eq!((err.file, err.line), ("t.txt", *line), "{text:?}: {err}");
        assert!(err.to_string().starts_with(&format!("t.txt:{line}: ")));
    }
    let ok = NoreturnList::parse("t.txt", "# c\n\n  abort  \n").expect("ok");
    assert!(ok.contains("abort"));
    assert_eq!(ok.len(), 1);
}

#[test]
fn x86_64_syscall_table() {
    let table = syscalls::x86_64().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        table.len() >= 360 && table.len() <= 400,
        "{} syscalls",
        table.len()
    );
    assert!(!table.is_empty());
    for (number, name) in [
        (0u16, "read"),
        (1, "write"),
        (2, "open"),
        (9, "mmap"),
        (39, "getpid"),
        (59, "execve"),
        (60, "exit"),
        (101, "ptrace"),
        (231, "exit_group"),
        (257, "openat"),
        (318, "getrandom"),
        (435, "clone3"),
    ] {
        assert_eq!(table.name(u64::from(number)), Some(name), "{number}");
        assert_eq!(table.number(name), Some(number), "{name}");
    }
    assert_eq!(table.name(100_000), None);
    assert_eq!(table.name(u64::MAX), None);
    assert_eq!(table.number("no_such_call"), None);
    let mut last = None;
    for (number, name) in table.iter() {
        assert!(last < Some(number), "number order");
        last = Some(number);
        assert!(
            SyscallId::by_name(name).is_ok(),
            "{name} is a syscall ID name"
        );
    }
    assert_eq!(NUMBER_REG, "rax");
    assert_eq!(ARG_REGS, ["rdi", "rsi", "rdx", "r10", "r8", "r9"]);
}

#[test]
fn syscall_table_errors() {
    let cases: &[(&'static str, u32)] = &[
        ("0 read\nx write\n", 2),
        ("0 read\n70000 big\n", 2),
        ("0 read\n1\n", 2),
        ("0 read\n1 Write\n", 2),
        ("0 read\n0 write\n", 2),
        ("0 read\n1 read\n", 2),
        ("0 read extra\n", 1),
    ];
    for (text, line) in cases {
        let err: DataError = SyscallTable::parse("s.txt", text).expect_err(text);
        assert_eq!((err.file, err.line), ("s.txt", *line), "{text:?}: {err}");
    }
    let ok = SyscallTable::parse("s.txt", "# c\n7 poll\n").expect("ok");
    assert_eq!(ok.name(7), Some("poll"));
}

#[test]
fn sysv_calling_convention() {
    let c = &cc::SYSV_X86_64;
    assert_eq!(c.name, "sysv");
    assert_eq!(c.int_args, ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    assert_eq!(c.float_args.len(), 8);
    assert_eq!(c.int_ret, ["rax", "rdx"]);
    assert_eq!(c.float_ret, ["xmm0", "xmm1"]);
    assert_eq!(
        (c.stack_arg_offset, c.shadow_space, c.red_zone),
        (8, 0, 128)
    );
    assert_eq!((c.stack_align, c.return_pop), (16, 8));
    assert_eq!(c.varargs_reg, Some("al"));
    assert!(!c.positional);
    for reg in ["rbx", "rbp", "rsp", "r12", "r13", "r14", "r15"] {
        assert!(c.is_callee_saved(reg), "{reg}");
    }
    for reg in ["rax", "rdi", "r11", "xmm0"] {
        assert!(!c.is_callee_saved(reg), "{reg}");
    }
    assert_eq!(c.int_arg_index("rcx"), Some(3));
    assert_eq!(c.int_arg_index("rax"), None);
    assert_eq!(c.float_arg_index("xmm7"), Some(7));
    assert_eq!(c.float_arg_index("xmm8"), None);
    assert_eq!(call_conv("sysv"), Some(&cc::SYSV_X86_64));
    assert_eq!(call_conv("pascal"), None);
    assert_eq!(CALL_CONVS.len(), 1);
}

#[test]
fn sysv_data_model() {
    let m = DataModel::X86_64_SYSV;
    assert_eq!(m.name, "x86_64-sysv");
    let cases = [
        (Prim::Bool, 1),
        (Prim::Char, 1),
        (Prim::SChar, 1),
        (Prim::UChar, 1),
        (Prim::Short, 2),
        (Prim::UShort, 2),
        (Prim::Int, 4),
        (Prim::UInt, 4),
        (Prim::Long, 8),
        (Prim::ULong, 8),
        (Prim::LongLong, 8),
        (Prim::ULongLong, 8),
        (Prim::Int128, 16),
        (Prim::UInt128, 16),
        (Prim::Float, 4),
        (Prim::Double, 8),
        (Prim::LongDouble, 16),
        (Prim::WChar, 4),
    ];
    for (prim, bytes) in cases {
        assert_eq!(m.prim(prim), Some(SizeAlign::same(bytes)), "{prim:?}");
    }
    assert_eq!(m.prim(Prim::Void), None);
    assert!(m.is_signed(Prim::Char));
    assert!(m.is_signed(Prim::WChar));
    assert!(m.is_signed(Prim::Int128));
    assert!(!m.is_signed(Prim::UInt));
    assert!(!m.is_signed(Prim::Bool));
    assert!(!m.is_signed(Prim::Double));
    assert!(Prim::Double.is_float() && !Prim::Double.is_integer());
    assert!(Prim::WChar.is_integer() && !Prim::Void.is_integer());
}
