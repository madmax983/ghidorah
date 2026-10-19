//! The MS x64 calling convention, the `x86_64-win` data model and the PE noreturn list (WP-30,
//! design Sections 7.7, 7.10 and 9.1).

use ghidorah_types::{DataModel, Prim, SizeAlign, call_conv, cc, noreturn_list};

#[test]
fn ms_x64_calling_convention() {
    let c = &cc::MS_X64;
    assert_eq!(c.name, "ms_x64");
    assert_eq!(c.int_args, ["rcx", "rdx", "r8", "r9"]);
    assert_eq!(c.float_args, ["xmm0", "xmm1", "xmm2", "xmm3"]);
    assert_eq!(c.int_ret, ["rax"]);
    assert_eq!(c.float_ret, ["xmm0"]);
    assert!(c.positional);
    assert_eq!(
        (c.stack_arg_offset, c.shadow_space, c.red_zone),
        (0x28, 32, 0)
    );
    assert_eq!((c.stack_align, c.return_pop), (16, 8));
    assert_eq!(c.varargs_reg, None);
    for reg in [
        "rbx", "rbp", "rdi", "rsi", "rsp", "r12", "r13", "r14", "r15", "xmm6", "xmm15",
    ] {
        assert!(c.is_callee_saved(reg), "{reg}");
    }
    for reg in [
        "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm5",
    ] {
        assert!(!c.is_callee_saved(reg), "{reg}");
    }
    assert_eq!(c.int_arg_index("r9"), Some(3));
    assert_eq!(c.float_arg_index("xmm2"), Some(2));
    assert_eq!(call_conv("ms_x64"), Some(&cc::MS_X64));
    assert_eq!(call_conv("sysv"), Some(&cc::SYSV_X86_64));
}

#[test]
fn win_data_model() {
    let m = DataModel::X86_64_WIN;
    assert_eq!(m.name, "x86_64-win");
    for (prim, bytes) in [
        (Prim::Int, 4),
        (Prim::Long, 4),
        (Prim::ULong, 4),
        (Prim::LongLong, 8),
        (Prim::LongDouble, 8),
        (Prim::WChar, 2),
        (Prim::Double, 8),
        (Prim::Bool, 1),
        (Prim::Int128, 16),
    ] {
        assert_eq!(m.prim(prim), Some(SizeAlign::same(bytes)), "{prim:?}");
    }
    assert_eq!(m.pointer, SizeAlign::same(8));
    assert!(!m.is_signed(Prim::WChar), "wchar_t is unsigned on Windows");
    assert_ne!(m, DataModel::X86_64_SYSV);
}

#[test]
fn pe_noreturn_list() {
    let pe = noreturn_list("pe32+-x86_64")
        .expect("a PE list")
        .expect("the PE list parses");
    for name in [
        "ExitProcess",
        "_exit",
        "abort",
        "__raise_securityfailure",
        "longjmp",
    ] {
        assert!(pe.contains(name), "{name}");
    }
    assert!(pe.contains("ExitThread") && pe.contains("FreeLibraryAndExitThread"));
    assert!(!pe.contains("Sleep"));
    assert_eq!(pe.len(), 21);
}
