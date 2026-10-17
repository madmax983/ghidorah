use ghidorah_base::{Address, FuncId, Storage, TxId, VarId};
use ghidorah_types::TypeId;

use super::Vars;
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn agent() -> Origin {
    Origin::new(
        Source::Agent,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    )
}

fn var(func: u64, storage: Storage) -> VarId {
    VarId {
        func: FuncId(Address::ram(func)),
        storage,
    }
}

#[test]
fn name_and_type_facts() {
    let mut v = Vars::default();
    let x = var(0x1000, Storage::Stack(-0x14));
    assert_eq!(
        v.set_name(&x, Some("count".to_string()), &agent()).unwrap(),
        None
    );
    assert_eq!(
        v.set_type(&x, Some(TypeId::from_index(5)), &Origin::analysis())
            .unwrap(),
        None
    );
    let facts = v.get(&x).unwrap();
    assert_eq!(facts.name.as_ref().unwrap().value, "count");
    assert_eq!(facts.ty.as_ref().unwrap().source, Source::Analysis);
    assert!(matches!(
        v.set_name(&x, None, &Origin::analysis()),
        Err(WriteError::Blocked(_))
    ));
    assert_eq!(
        v.set_name(&x, Some(String::new()), &agent()),
        Err(WriteError::Invalid(Invalid::EmptyName))
    );
    let long = "n".repeat(ghidorah_base::id::MAX_NAME_LEN + 1);
    assert!(matches!(
        v.set_name(&x, Some(long), &agent()),
        Err(WriteError::Invalid(Invalid::TooLong { .. }))
    ));

    assert!(v.set_name(&x, None, &agent()).unwrap().is_some());
    assert_eq!(v.len(), 1, "the type fact keeps the entry");
    assert!(v.set_type(&x, None, &agent()).unwrap().is_some());
    assert!(v.is_empty(), "a variable with no fact has no entry");
    assert_eq!(v.set_type(&x, None, &agent()).unwrap(), None);
    assert!(v.is_empty());
}

#[test]
fn of_func_gives_the_variables_of_one_function() {
    let mut v = Vars::default();
    let ids = [
        var(0x1000, Storage::Param(0)),
        var(0x1000, Storage::Stack(-8)),
        var(0x1000, Storage::Ret),
        var(0x2000, Storage::Param(0)),
        var(0x0fff, Storage::Ret),
    ];
    for id in &ids {
        v.set_name(id, Some("v".to_string()), &agent()).unwrap();
    }
    let got: Vec<&VarId> = v
        .of_func(FuncId(Address::ram(0x1000)))
        .map(|(id, _)| id)
        .collect();
    assert_eq!(got, [&ids[0], &ids[1], &ids[2]]);
    assert_eq!(v.of_func(FuncId(Address::ram(0x3000))).count(), 0);
    assert_eq!(v.iter().count(), 5);
}
