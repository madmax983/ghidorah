//! The const table of the prelude types (design Section 9.2).
//!
//! The items install in table order. So an item can use the items above it.
//! The type text of an item uses the `type` mode of the C parser.
//! The values follow glibc on x86-64 Linux.

use crate::ty::RecordKind::{Struct, Union};

use super::Item::{self, Opaque, Record, Typedef};

/// The prelude items in install order.
pub(crate) const PRELUDE: &[Item] = &[
    // stdint.h
    Typedef("int8_t", "signed char"),
    Typedef("int16_t", "short"),
    Typedef("int32_t", "int"),
    Typedef("int64_t", "long"),
    Typedef("uint8_t", "unsigned char"),
    Typedef("uint16_t", "unsigned short"),
    Typedef("uint32_t", "unsigned int"),
    Typedef("uint64_t", "unsigned long"),
    Typedef("int_least8_t", "signed char"),
    Typedef("int_least16_t", "short"),
    Typedef("int_least32_t", "int"),
    Typedef("int_least64_t", "long"),
    Typedef("uint_least8_t", "unsigned char"),
    Typedef("uint_least16_t", "unsigned short"),
    Typedef("uint_least32_t", "unsigned int"),
    Typedef("uint_least64_t", "unsigned long"),
    Typedef("int_fast8_t", "signed char"),
    Typedef("int_fast16_t", "long"),
    Typedef("int_fast32_t", "long"),
    Typedef("int_fast64_t", "long"),
    Typedef("uint_fast8_t", "unsigned char"),
    Typedef("uint_fast16_t", "unsigned long"),
    Typedef("uint_fast32_t", "unsigned long"),
    Typedef("uint_fast64_t", "unsigned long"),
    Typedef("intptr_t", "long"),
    Typedef("uintptr_t", "unsigned long"),
    Typedef("intmax_t", "long"),
    Typedef("uintmax_t", "unsigned long"),
    Typedef("__int128_t", "__int128"),
    Typedef("__uint128_t", "unsigned __int128"),
    // stddef.h and POSIX types
    Typedef("size_t", "unsigned long"),
    Typedef("ssize_t", "long"),
    Typedef("ptrdiff_t", "long"),
    Typedef("off_t", "long"),
    Typedef("off64_t", "long"),
    Typedef("pid_t", "int"),
    Typedef("uid_t", "unsigned int"),
    Typedef("gid_t", "unsigned int"),
    Typedef("mode_t", "unsigned int"),
    Typedef("dev_t", "unsigned long"),
    Typedef("ino_t", "unsigned long"),
    Typedef("time_t", "long"),
    Typedef("clock_t", "long"),
    Typedef("clockid_t", "int"),
    Typedef("useconds_t", "unsigned int"),
    Typedef("suseconds_t", "long"),
    Typedef("wint_t", "unsigned int"),
    Typedef("socklen_t", "unsigned int"),
    Typedef("sa_family_t", "unsigned short"),
    Typedef("in_addr_t", "uint32_t"),
    Typedef("in_port_t", "uint16_t"),
    Typedef("nfds_t", "unsigned long"),
    Typedef("pthread_t", "unsigned long"),
    // Opaque types
    Opaque(Struct, "_IO_FILE"),
    Typedef("FILE", "struct _IO_FILE"),
    Opaque(Struct, "__dirstream"),
    Typedef("DIR", "struct __dirstream"),
    Opaque(Union, "pthread_attr_t"),
    Typedef("pthread_attr_t", "union pthread_attr_t"),
    Opaque(Union, "pthread_mutex_t"),
    Typedef("pthread_mutex_t", "union pthread_mutex_t"),
    Record(
        Struct,
        "__jmp_buf_tag",
        &[
            ("__jmpbuf", "long[8]"),
            ("__mask_was_saved", "int"),
            ("__saved_mask", "struct { unsigned long __val[16]; }"),
        ],
    ),
    Typedef("jmp_buf", "struct __jmp_buf_tag[1]"),
    Typedef("sigjmp_buf", "struct __jmp_buf_tag[1]"),
    Typedef("fd_set", "struct { long fds_bits[16]; }"),
    Opaque(Struct, "stat"),
    Opaque(Struct, "tm"),
    Opaque(Struct, "timeval"),
    Opaque(Struct, "dirent"),
    Opaque(Struct, "utsname"),
    Opaque(Struct, "passwd"),
    Opaque(Struct, "addrinfo"),
    Opaque(Struct, "hostent"),
    Opaque(Struct, "pollfd"),
    Opaque(Struct, "sigaction"),
    Opaque(Struct, "epoll_event"),
    // The va_list of the System V ABI
    Record(
        Struct,
        "__va_list_tag",
        &[
            ("gp_offset", "unsigned int"),
            ("fp_offset", "unsigned int"),
            ("overflow_arg_area", "void *"),
            ("reg_save_area", "void *"),
        ],
    ),
    Typedef("__builtin_va_list", "struct __va_list_tag[1]"),
    Typedef("__gnuc_va_list", "__builtin_va_list"),
    Typedef("va_list", "__builtin_va_list"),
    // Signal handlers
    Typedef("__sighandler_t", "void (*)(int)"),
    Typedef("sighandler_t", "__sighandler_t"),
    // The records that Tier-0 uses
    Record(Struct, "in_addr", &[("s_addr", "in_addr_t")]),
    Record(
        Struct,
        "sockaddr",
        &[("sa_family", "sa_family_t"), ("sa_data", "char[14]")],
    ),
    Record(
        Struct,
        "sockaddr_in",
        &[
            ("sin_family", "sa_family_t"),
            ("sin_port", "in_port_t"),
            ("sin_addr", "struct in_addr"),
            ("sin_zero", "unsigned char[8]"),
        ],
    ),
    Record(
        Struct,
        "timespec",
        &[("tv_sec", "time_t"), ("tv_nsec", "long")],
    ),
];
