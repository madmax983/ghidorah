use super::{MemStore, PageError, PageStore};

#[test]
fn a_mem_store_keeps_the_last_bytes_of_each_page() {
    let mut store = MemStore::new();
    let count = store.clone();
    assert_eq!(store.read(3), Ok(None));
    store.write(3, b"one").unwrap();
    store.write(3, b"two").unwrap();
    assert_eq!(store.read(3), Ok(Some(b"two".to_vec())));
    assert_eq!(count.writes(), 2, "a clone shares the write count");
    store.clear().unwrap();
    assert_eq!(store.read(3), Ok(None));
}

#[test]
fn page_errors_name_the_page() {
    let texts = [
        PageError::Io("disk full".to_owned()).to_string(),
        PageError::Corrupt { page: 7 }.to_string(),
        PageError::Missing { page: 9 }.to_string(),
    ];
    assert!(texts[0].contains("disk full"));
    assert!(texts[1].contains("Page 7"));
    assert!(texts[2].contains("page 9"));
}
