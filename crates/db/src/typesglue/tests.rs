use ghidorah_base::TypeRef;
use ghidorah_loader::Format;
use ghidorah_types::{DataModel, Prim, parse_sig};

use super::{Types, model_for};

#[test]
fn types_start_with_the_prelude() {
    let types = Types::for_format(Format::Elf64Le).unwrap();
    assert!(types.store().lookup_typedef("size_t").is_some());
    assert!(types.store().lookup_tag("sockaddr_in").is_some());
    assert_eq!(*types.model(), DataModel::X86_64_SYSV);
    for format in [Format::Elf64Le, Format::Raw, Format::Pe32Plus] {
        assert_eq!(model_for(format), DataModel::X86_64_SYSV);
    }
    let size_t = types.store().lookup_typedef("size_t").unwrap();
    let r = types.type_ref(size_t).unwrap();
    assert_eq!(r, TypeRef::named("size_t").unwrap());
    assert_eq!(types.by_ref(&r), Some(size_t));
}

#[test]
fn sig_gives_function_types_only() {
    let mut types = Types::for_format(Format::Raw).unwrap();
    let parsed = parse_sig(types.store_mut(), "int f(char *s, ...)").unwrap();
    let sig = types.sig(parsed.ty).unwrap();
    assert!(sig.variadic);
    assert_eq!(sig.params.len(), 1);
    let int = types.store().prim(Prim::Int);
    assert_eq!(types.sig(int), None);
}

#[test]
fn prototypes_by_linked_name() {
    assert!(Types::prototype("puts").is_some());
    assert!(Types::prototype("puts@GLIBC_2.2.5").is_some());
    assert!(Types::prototype("no_such_function_xyz").is_none());
}
