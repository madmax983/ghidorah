//! The code units and flow references of the work state, in pages (ADR-0031 stage 3).
//!
//! A page holds the code units and the flow references of one range of RAM offsets. A
//! reference goes in the page of its source. A page is in memory or in the store. With a
//! [`PageStore`], the number of loaded pages has a limit: a load above the limit stores a
//! random loaded page. A page goes to the store only when it changed after its load.
//! Without a store, each page stays loaded.
//!
//! The reads take `&self` and give values, so a read can load a page. The pages sit in a
//! `RefCell`, and no borrow lives past one call. A failed store operation keeps the page
//! loaded and records the error. The scheduler stops the run with the error after the step.
//!
//! Each flow reference starts at a RAM code unit. So the page order is the key order of the
//! references.

#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, SpaceId};
use ghidorah_db::{FlowKind, RefKey, RefType};

use super::WUnit;
use crate::pages::{PageError, PageLimits, PageStore};

/// The flow kinds by their page code.
const FLOWS: [FlowKind; 8] = [
    FlowKind::Seq,
    FlowKind::Jmp,
    FlowKind::Jcc,
    FlowKind::Call,
    FlowKind::ICall,
    FlowKind::IJmp,
    FlowKind::Ret,
    FlowKind::Trap,
];

/// The first bytes of a page.
const MAGIC: &[u8; 4] = b"GWP1";

/// The code units and flow references of a work state.
#[derive(Debug, Default)]
pub(crate) struct Code {
    state: RefCell<State>,
}

/// The pages and the store.
#[derive(Debug)]
struct State {
    /// The page size as a power of two.
    bits: u32,
    /// The pages by index: a loaded page, or `None` for a page in the store. A page with no
    /// unit and no reference is not in the map.
    pages: BTreeMap<u64, Option<Page>>,
    /// The number of code units.
    units: usize,
    /// The store of the pages that are not in memory.
    store: Option<Box<dyn PageStore>>,
    /// The number of loaded pages that a load can reach without a store operation.
    limit: usize,
    /// The number of loaded pages.
    loaded: usize,
    /// The counter of the random choices of [`State::make_room`].
    tick: u64,
    /// The first error of a store operation.
    error: Option<PageError>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            bits: PageLimits::DEFAULT_BITS,
            pages: BTreeMap::new(),
            units: 0,
            store: None,
            limit: usize::MAX,
            loaded: 0,
            tick: 0,
            error: None,
        }
    }
}

/// A loaded page.
#[derive(Debug, Default, PartialEq, Eq)]
struct Page {
    units: BTreeMap<u64, WUnit>,
    refs: BTreeSet<RefKey>,
    /// `true` when the store does not hold the current page.
    dirty: bool,
}

impl State {
    fn index(&self, off: u64) -> u64 {
        off.checked_shr(self.bits).unwrap_or(0)
    }

    /// Records `e` when the state has no error yet.
    fn fail(&mut self, e: PageError) {
        if self.error.is_none() {
            self.error = Some(e);
        }
    }

    /// Stores loaded pages until a load can add one page. `keep` stays.
    ///
    /// The page to store is a random page of the loaded pages. An analyzer reads the pages in
    /// address order. A store of the page of the oldest use then stores each page before its
    /// next read. A random choice keeps some pages of such a scan. The use counter seeds
    /// the choice, so a run makes the same choices each time.
    fn make_room(&mut self, keep: u64) {
        while self.loaded >= self.limit {
            let count = self
                .pages
                .iter()
                .filter(|(i, p)| **i != keep && p.is_some())
                .count();
            self.tick = self.tick.saturating_add(1);
            let pick = usize::try_from(mix(self.tick) % u64::try_from(count.max(1)).unwrap_or(1))
                .unwrap_or(0);
            let chosen = self
                .pages
                .iter()
                .filter(|(i, p)| **i != keep && p.is_some())
                .nth(pick)
                .map(|(i, _)| *i);
            let Some(index) = chosen else {
                return;
            };
            if !self.store_page(index) {
                return;
            }
        }
    }

    /// Puts the loaded page `index` in the store. Gives `false` when the store fails.
    fn store_page(&mut self, index: u64) -> bool {
        let Some(Some(page)) = self.pages.get(&index) else {
            return true;
        };
        if page.dirty {
            let bytes = encode(page);
            let done = match self.store.as_mut() {
                Some(store) => store.write(index, &bytes),
                None => Err(PageError::Io("no page store".to_owned())),
            };
            if let Err(e) = done {
                self.fail(e);
                // The page stays loaded, so no fact goes. Later loads store no page.
                self.limit = usize::MAX;
                return false;
            }
        }
        self.pages.insert(index, None);
        self.loaded = self.loaded.saturating_sub(1);
        true
    }

    /// Gives the page `index` when it exists. A stored page loads. A failed load records
    /// the error and gives an empty page.
    fn page(&mut self, index: u64) -> Option<&mut Page> {
        if self.pages.get(&index)?.is_none() {
            let read = match self.store.as_mut().map(|s| s.read(index)) {
                Some(Ok(Some(bytes))) => decode(&bytes).ok_or(PageError::Corrupt { page: index }),
                Some(Ok(None)) | None => Err(PageError::Missing { page: index }),
                Some(Err(e)) => Err(e),
            };
            let page = read.unwrap_or_else(|e| {
                self.fail(e);
                Page::default()
            });
            self.make_room(index);
            self.pages.insert(index, Some(page));
            self.loaded = self.loaded.saturating_add(1);
        }
        self.pages.get_mut(&index)?.as_mut()
    }

    /// Gives the page `index` for a change. A missing page starts empty.
    fn page_mut(&mut self, index: u64) -> &mut Page {
        if self.page(index).is_none() {
            self.make_room(index);
            self.loaded = self.loaded.saturating_add(1);
        }
        let page = self
            .pages
            .entry(index)
            .or_insert(None)
            .get_or_insert_with(Page::default);
        page.dirty = true;
        page
    }

    /// Removes the page `index` when it is in memory and empty.
    fn tidy(&mut self, index: u64) {
        let empty = matches!(
            self.pages.get(&index),
            Some(Some(p)) if p.units.is_empty() && p.refs.is_empty()
        );
        if empty {
            self.pages.remove(&index);
            self.loaded = self.loaded.saturating_sub(1);
        }
    }

    /// Gives the index of the first page from `from` to `last`.
    fn next_index(&self, from: u64, last: u64) -> Option<u64> {
        if from > last {
            return None;
        }
        self.pages.range(from..=last).next().map(|(i, _)| *i)
    }
}

impl Code {
    /// Sets the store and the limits. The loaded pages stay. A page size outside
    /// [`PageLimits::MIN_BITS`] to [`PageLimits::MAX_BITS`] takes the nearest size. A new
    /// page size applies only to an empty state.
    pub(crate) fn set_store(&mut self, store: Box<dyn PageStore>, limits: PageLimits) {
        let state = self.state.get_mut();
        if state.pages.is_empty() {
            state.bits = limits
                .bits
                .clamp(PageLimits::MIN_BITS, PageLimits::MAX_BITS);
        }
        state.limit = limits.loaded.max(1);
        state.store = Some(store);
    }

    /// Removes all code units and references. The store and the limits stay, and the pages
    /// of the store go.
    pub(crate) fn reset(&mut self) {
        let state = self.state.get_mut();
        let mut store = state.store.take();
        let cleared = store.as_mut().map_or(Ok(()), |s| s.clear());
        *state = State {
            bits: state.bits,
            limit: state.limit,
            store,
            error: cleared.err(),
            ..State::default()
        };
    }

    /// Gives the first error of a store operation. The error stays, because the work state
    /// lost the facts of a page.
    pub(crate) fn error(&self) -> Option<PageError> {
        self.state.try_borrow().ok()?.error.clone()
    }

    /// Gives the number of code units.
    pub(crate) fn len(&self) -> usize {
        self.state.try_borrow().map_or(0, |s| s.units)
    }

    /// Gives the number of loaded pages.
    #[cfg(test)]
    pub(crate) fn loaded(&self) -> usize {
        self.state.try_borrow().map_or(0, |s| s.loaded)
    }

    /// Runs `f` on the state. A borrowed state gives `None`, but no call holds a borrow
    /// past its end.
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Option<T>) -> Option<T> {
        f(&mut *self.state.try_borrow_mut().ok()?)
    }

    /// Gives the code unit at `at`.
    pub(crate) fn get(&self, at: u64) -> Option<WUnit> {
        self.with(|s| s.page(s.index(at))?.units.get(&at).copied())
    }

    /// Gives the start and the code unit that holds `at`.
    pub(crate) fn unit_at(&self, at: u64) -> Option<(u64, WUnit)> {
        let found = self.with(|s| {
            let index = s.index(at);
            let own = s.page(index).and_then(|p| {
                p.units
                    .range(..=at)
                    .next_back()
                    .map(|(start, u)| (*start, *u))
            });
            // A unit of this page at or below `at` ends before each unit of the page before.
            match (own, index.checked_sub(1)) {
                (Some(u), _) => Some(u),
                (None, Some(prev)) => s
                    .page(prev)?
                    .units
                    .last_key_value()
                    .map(|(start, u)| (*start, *u)),
                (None, None) => None,
            }
        })?;
        found.1.range(found.0)?.contains(at).then_some(found)
    }

    /// Gives the code units that start from `first` to `last`, in address order.
    pub(crate) fn range(&self, first: u64, last: u64) -> Chunks<'_, (u64, WUnit)> {
        Chunks::new(self, first, last, |page, first, last, out| {
            out.extend(page.units.range(first..=last).map(|(a, u)| (*a, *u)));
        })
    }

    /// Gives all code units in address order.
    pub(crate) fn iter(&self) -> Chunks<'_, (u64, WUnit)> {
        self.range(0, u64::MAX)
    }

    /// Puts the code unit `unit` at `at` in place of a unit at `at`.
    pub(crate) fn insert(&mut self, at: u64, unit: WUnit) {
        let state = self.state.get_mut();
        let index = state.index(at);
        if state.page_mut(index).units.insert(at, unit).is_none() {
            state.units = state.units.saturating_add(1);
        }
    }

    /// Removes and gives the code unit at `at`.
    pub(crate) fn remove(&mut self, at: u64) -> Option<WUnit> {
        let state = self.state.get_mut();
        let index = state.index(at);
        state.page(index)?.units.get(&at)?;
        let unit = state.page_mut(index).units.remove(&at);
        if unit.is_some() {
            state.units = state.units.saturating_sub(1);
        }
        state.tidy(index);
        unit
    }

    /// Tells if the reference `key` is in the state.
    pub(crate) fn has_ref(&self, key: &RefKey) -> bool {
        self.with(|s| Some(s.page(s.index(key.from.off))?.refs.contains(key)))
            .unwrap_or(false)
    }

    /// Gives the references from the code unit at `at` in key order.
    pub(crate) fn refs_from(&self, at: u64) -> Vec<RefKey> {
        let from = Address::ram(at);
        // RAM is the space of the lowest code, so this key is the first key from `at`.
        let first = RefKey {
            from,
            op_index: i8::MIN,
            to: Address::ram(0),
            kind: RefType::FallThrough,
        };
        self.with(|s| {
            let page = s.page(s.index(at))?;
            Some(
                page.refs
                    .range(first..)
                    .take_while(|k| k.from == from)
                    .copied()
                    .collect(),
            )
        })
        .unwrap_or_default()
    }

    /// Gives all references in key order.
    pub(crate) fn refs(&self) -> Chunks<'_, RefKey> {
        Chunks::new(self, 0, u64::MAX, |page, _, _, out| {
            out.extend(page.refs.iter().copied());
        })
    }

    /// Adds the reference `key`.
    pub(crate) fn insert_ref(&mut self, key: RefKey) {
        let state = self.state.get_mut();
        let index = state.index(key.from.off);
        state.page_mut(index).refs.insert(key);
    }

    /// Removes the reference `key`.
    pub(crate) fn remove_ref(&mut self, key: &RefKey) {
        let state = self.state.get_mut();
        let index = state.index(key.from.off);
        if state.page(index).is_some_and(|p| p.refs.contains(key)) {
            state.page_mut(index).refs.remove(key);
            state.tidy(index);
        }
    }
}

/// The function that copies the items of one page from `first` to `last`.
type Fill<T> = fn(&Page, u64, u64, &mut Vec<T>);

/// The items of the pages from `first` to `last`. The iterator copies one page at a time,
/// so it holds no borrow of the state between two calls.
pub(crate) struct Chunks<'a, T> {
    code: &'a Code,
    first: u64,
    last: u64,
    /// The index of the next page, or `None` after the last page.
    next: Option<u64>,
    buf: std::vec::IntoIter<T>,
    fill: Fill<T>,
}

impl<'a, T> Chunks<'a, T> {
    fn new(code: &'a Code, first: u64, last: u64, fill: Fill<T>) -> Self {
        let next = code.with(|s| Some(s.index(first)));
        Self {
            code,
            first,
            last,
            next,
            buf: Vec::new().into_iter(),
            fill,
        }
    }
}

impl<T> Iterator for Chunks<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        loop {
            if let Some(item) = self.buf.next() {
                return Some(item);
            }
            let from = self.next?;
            let (first, last, fill) = (self.first, self.last, self.fill);
            let (index, items) = self
                .code
                .with(|s| {
                    let index = s.next_index(from, s.index(last))?;
                    let mut out = Vec::new();
                    if let Some(page) = s.page(index) {
                        fill(page, first, last, &mut out);
                    }
                    Some((index, out))
                })
                .unzip();
            self.next = index.and_then(|i| i.checked_add(1));
            self.buf = items.unwrap_or_default().into_iter();
        }
    }
}

/// Gives a mix of the bits of `x` (the `SplitMix64` finalizer).
const fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Gives the bytes of `page`: the magic, the unit count, the units, the reference count and
/// the references. All numbers are little-endian.
fn encode(page: &Page) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        12usize
            .saturating_add(page.units.len().saturating_mul(19))
            .saturating_add(page.refs.len().saturating_mul(20)),
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(
        &u32::try_from(page.units.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for (at, u) in &page.units {
        out.extend_from_slice(&at.to_le_bytes());
        let flow = FLOWS.iter().position(|f| *f == u.flow).unwrap_or(0);
        out.extend_from_slice(&[u.len, u8::try_from(flow).unwrap_or(0), u.flags]);
        out.extend_from_slice(&u.owner.to_le_bytes());
    }
    out.extend_from_slice(
        &u32::try_from(page.refs.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for k in &page.refs {
        out.push(k.from.space.code());
        out.extend_from_slice(&k.from.off.to_le_bytes());
        out.extend_from_slice(&k.op_index.to_le_bytes());
        out.push(k.to.space.code());
        out.extend_from_slice(&k.to.off.to_le_bytes());
        out.push(k.kind.code());
    }
    out
}

/// A reader of the bytes of a page.
struct Reader<'a> {
    rest: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.rest.split_first_chunk::<N>()?;
        self.rest = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }

    fn addr(&mut self) -> Option<Address> {
        let space = SpaceId::from_code(self.u8()?)?;
        Some(Address::new(space, self.u64()?))
    }
}

/// Reads the bytes of a page. Bytes out of the format give `None`. The counts bound the
/// loops, and each item reads its bytes, so a count above the bytes stops at the end.
fn decode(bytes: &[u8]) -> Option<Page> {
    let mut r = Reader { rest: bytes };
    if &r.take::<4>()? != MAGIC {
        return None;
    }
    // The pages hold their items in key order, so each map takes a bulk build. A count above
    // the bytes gets no capacity above the bytes.
    let count = r.u32()?;
    let mut units = Vec::with_capacity(r.rest.len().min(usize::try_from(count).ok()?) / 19);
    for _ in 0..count {
        let at = r.u64()?;
        let [len, flow, flags] = r.take::<3>()?;
        let flow = *FLOWS.get(usize::from(flow))?;
        let owner = r.u64()?;
        units.push((
            at,
            WUnit {
                len,
                flow,
                flags,
                owner,
            },
        ));
    }
    let count = r.u32()?;
    let mut refs = Vec::with_capacity(r.rest.len().min(usize::try_from(count).ok()?) / 20);
    for _ in 0..count {
        let from = r.addr()?;
        let op_index = i8::from_le_bytes(r.take::<1>()?);
        let to = r.addr()?;
        let kind = RefType::from_code(r.u8()?)?;
        refs.push(RefKey {
            from,
            op_index,
            to,
            kind,
        });
    }
    r.rest.is_empty().then(|| Page {
        units: units.into_iter().collect(),
        refs: refs.into_iter().collect(),
        ..Page::default()
    })
}
