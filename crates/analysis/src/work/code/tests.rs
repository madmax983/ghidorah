use ghidorah_base::Address;
use ghidorah_db::{FlowKind, RefKey, RefType};

use super::{Code, FLOWS, Page, decode, encode};
use crate::pages::{MemStore, PageError, PageLimits, PageStore};
use crate::work::WUnit;

fn unit(len: u8, owner: u64) -> WUnit {
    WUnit {
        len,
        flow: FlowKind::Seq,
        flags: 0,
        owner,
    }
}

fn jump(from: u64, to: u64) -> RefKey {
    RefKey {
        from: Address::ram(from),
        op_index: 0,
        to: Address::ram(to),
        kind: RefType::UnconditionalJump,
    }
}

/// A store of 256-byte pages with room for one loaded page.
fn paged(store: impl PageStore + 'static) -> Code {
    let mut code = Code::default();
    let limits = PageLimits {
        loaded: 1,
        bits: PageLimits::MIN_BITS,
    };
    code.set_store(Box::new(store), limits);
    code
}

/// Puts a unit of 4 bytes at each of `starts`, owned by the first start, with a jump from
/// each unit to the next.
fn fill(code: &mut Code, starts: &[u64]) {
    for (i, at) in starts.iter().enumerate() {
        code.insert(*at, unit(4, starts[0]));
        if let Some(next) = starts.get(i + 1) {
            code.insert_ref(jump(*at, *next));
        }
    }
}

const STARTS: [u64; 5] = [0x10, 0xfe, 0x210, 0x300, 0x5f0];

#[test]
fn a_page_reads_back_from_its_bytes() {
    let mut page = Page::default();
    for (i, flow) in FLOWS.iter().enumerate() {
        let at = u64::try_from(i).unwrap() * 4;
        let u = WUnit {
            len: 4,
            flow: *flow,
            flags: 3,
            owner: 0x10,
        };
        page.units.insert(at, u);
    }
    page.refs.insert(jump(0, 8));
    page.refs.insert(RefKey {
        from: Address::ram(4),
        op_index: -1,
        to: Address::external(2),
        kind: RefType::UnconditionalCall,
    });
    assert_eq!(decode(&encode(&page)), Some(page));
}

#[test]
fn bytes_out_of_the_format_do_not_read() {
    let mut page = Page::default();
    page.units.insert(0, unit(4, 0));
    page.refs.insert(jump(0, 4));
    let good = encode(&page);
    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    let mut bad_flow = good.clone();
    bad_flow[4 + 4 + 8 + 1] = 99;
    let mut extra = good.clone();
    extra.push(0);
    let mut many = good.clone();
    many[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    for bytes in [
        bad_magic,
        bad_flow,
        extra,
        many,
        good[..good.len() - 1].to_vec(),
    ] {
        assert_eq!(decode(&bytes), None);
    }
}

#[test]
fn reads_load_the_pages_that_the_limit_stored() {
    let mut code = paged(MemStore::new());
    fill(&mut code, &STARTS);
    assert_eq!(code.loaded(), 1, "one page stays in memory");
    assert_eq!(code.len(), 5);
    for at in STARTS {
        assert_eq!(code.get(at), Some(unit(4, 0x10)), "{at:#x}");
    }
    assert_eq!(
        code.unit_at(0x101),
        Some((0xfe, unit(4, 0x10))),
        "the unit of the page before reaches over the page edge"
    );
    assert_eq!(code.unit_at(0x102), None);
    assert_eq!(code.unit_at(0x0f), None);
    let units: Vec<u64> = code.range(0x11, 0x300).map(|(at, _)| at).collect();
    assert_eq!(units, [0xfe, 0x210, 0x300]);
    let refs: Vec<u64> = code.refs().map(|k| k.from.off).collect();
    assert_eq!(refs, [0x10, 0xfe, 0x210, 0x300]);
    assert_eq!(code.refs_from(0x210), [jump(0x210, 0x300)]);
    assert!(code.has_ref(&jump(0x300, 0x5f0)));
    assert!(!code.has_ref(&jump(0x300, 0x10)));
    assert_eq!(code.error(), None);
}

#[test]
fn a_page_with_no_change_is_not_written_again() {
    let store = MemStore::new();
    let count = store.clone();
    let mut code = paged(store);
    fill(&mut code, &STARTS);
    let _ = code.iter().count();
    let writes = count.writes();
    assert_eq!(writes, 4, "each new page goes to the store once");
    let _ = code.iter().count();
    assert_eq!(count.writes(), writes, "a read changes no page");
}

#[test]
fn an_empty_page_goes() {
    let mut code = paged(MemStore::new());
    fill(&mut code, &[0x10, 0x210]);
    assert_eq!(code.remove(0x210), Some(unit(4, 0x10)));
    code.remove_ref(&jump(0x10, 0x210));
    assert_eq!(code.remove(0x10), Some(unit(4, 0x10)));
    assert_eq!(code.remove(0x10), None);
    assert_eq!(code.len(), 0);
    assert_eq!(code.loaded(), 0);
    assert_eq!(code.iter().count(), 0);
}

/// A store that fails each write and loses each page.
#[derive(Debug)]
struct Broken;

impl PageStore for Broken {
    fn read(&mut self, _: u64) -> Result<Option<Vec<u8>>, PageError> {
        Ok(None)
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), PageError> {
        Err(PageError::Io("disk full".to_owned()))
    }

    fn clear(&mut self) -> Result<(), PageError> {
        Ok(())
    }
}

#[test]
fn a_failed_write_keeps_the_page_in_memory() {
    let mut code = paged(Broken);
    fill(&mut code, &STARTS);
    assert_eq!(code.error(), Some(PageError::Io("disk full".to_owned())));
    assert_eq!(code.loaded(), 4, "no page of the four goes");
    assert_eq!(code.iter().count(), 5);
}

/// A store that keeps no page.
#[derive(Debug)]
struct Lossy;

impl PageStore for Lossy {
    fn read(&mut self, _: u64) -> Result<Option<Vec<u8>>, PageError> {
        Ok(None)
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), PageError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), PageError> {
        Err(PageError::Io("busy".to_owned()))
    }
}

#[test]
fn a_lost_page_is_an_error() {
    let mut code = paged(Lossy);
    fill(&mut code, &[0x10, 0x210]);
    assert_eq!(code.get(0x10), None);
    assert_eq!(code.error(), Some(PageError::Missing { page: 0 }));
    code.reset();
    assert_eq!(code.len(), 0);
    assert_eq!(
        code.error(),
        Some(PageError::Io("busy".to_owned())),
        "a reset keeps the error of the clear"
    );
}
