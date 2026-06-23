//! NTP source manager — a faithful port of chrony 4.5 `ntp_sources.c` (`NSR_*`).
//!
//! `ntp_sources.c` owns the table of configured NTP sources, keyed by remote address,
//! plus the source pools and the asynchronous name-resolving machinery. This module ports
//! the **source-table internals** — the addressing core that every `NSR_*` operation
//! sits on:
//!
//! * [`SourceTable`] — the open-addressing hash table of sources keyed by IP, with
//!   chrony's quadratic probing and power-of-two sizing ([`find_slot`](SourceTable::find_slot),
//!   [`find_slot2`](SourceTable::find_slot2), [`check_hashtable_size`]).
//! * [`ip_to_hash`] — chrony's `UTI_IPToHash` (the seeded address hash the table uses).
//! * [`status_to_string`] — `NSR_StatusToString`.
//! * [`ConfIdAllocator`] — `get_next_conf_id` (the monotonic configuration-id counter).
//!
//! The resolving, pool management, and per-source protocol wiring (which create
//! `NCR_Instance`s, open sockets, and schedule timeouts) are host-boundary / later
//! stages.
//!
//! # Adaptation (documented, not silent)
//!
//! `UTI_IPToHash` mixes in a process-random seed (drawn once from the CSPRNG) so that
//! collision order is unpredictable. Randomness is a host boundary here, so the seed is
//! an explicit input to [`ip_to_hash`] / [`SourceTable`]; chrony's hash is recovered for
//! any given seed. (The oracle pins the seed to `0x01010101`.)
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_sources.c`** via the `#include`
//! harness (real `array.c` linked, the random seed pinned): the hash, the slot probing on
//! an 8-slot table, the sizing rule, the status strings, and the id counter are captured
//! (`research/oracle/ntp_sources-table-c-vectors.txt`). See the tests.

/// chrony `NSR_Status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsrStatus {
    Success,
    NoSuchSource,
    AlreadyInUse,
    TooManySources,
    InvalidAf,
    InvalidName,
    UnresolvedName,
}

/// chrony `NSR_StatusToString`.
pub fn status_to_string(status: NsrStatus) -> &'static str {
    match status {
        NsrStatus::Success => "Success",
        NsrStatus::NoSuchSource => "No such source",
        NsrStatus::AlreadyInUse => "Already in use",
        NsrStatus::TooManySources => "Too many sources",
        NsrStatus::InvalidAf => "Invalid address",
        NsrStatus::InvalidName => "Invalid name",
        NsrStatus::UnresolvedName => "Unresolved name",
    }
}

/// chrony `check_hashtable_size`: whether a table of `size` slots can hold `sources`
/// (chrony keeps the load factor at or below one half).
pub fn check_hashtable_size(sources: u32, size: u32) -> bool {
    sources * 2 <= size
}

/// chrony `get_next_conf_id`: the monotonic configuration-id counter (shared by the
/// sources of a pool).
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfIdAllocator {
    last_conf_id: u32,
}

impl ConfIdAllocator {
    /// Allocate the next configuration id (chrony pre-increments `last_conf_id`).
    pub fn allocate(&mut self) -> u32 {
        self.last_conf_id = self.last_conf_id.wrapping_add(1);
        self.last_conf_id
    }
}

/// A source's IP key, matching the address families chrony's table accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpKey {
    V4(u32),
    V6([u8; 16]),
    /// chrony `IPADDR_ID` (an unresolved-source placeholder id).
    Id(u32),
    /// chrony `IPADDR_UNSPEC` / any unaccepted family — never stored; the table and
    /// `add_source` reject it.
    Unspec,
}

impl IpKey {
    /// The raw address bytes hashed by `UTI_IPToHash`, in host (little-endian on the
    /// oracle's platform) order — matching chrony hashing the in-memory representation.
    fn hash_bytes(&self) -> Vec<u8> {
        match self {
            IpKey::V4(v) => v.to_le_bytes().to_vec(),
            IpKey::V6(b) => b.to_vec(),
            IpKey::Id(v) => v.to_le_bytes().to_vec(),
            IpKey::Unspec => Vec::new(),
        }
    }

    /// Whether this is an address family chrony's table accepts (INET4/INET6/ID).
    fn is_valid_family(&self) -> bool {
        !matches!(self, IpKey::Unspec)
    }
}

/// chrony `UTI_CompareIPs(a, b, mask) == 0`: whether `a` and `b` are equal under `mask`
/// (a `None` mask compares the full addresses). Different families never match.
fn ip_equal_under_mask(a: IpKey, b: IpKey, mask: Option<IpKey>) -> bool {
    match (a, b) {
        (IpKey::V4(x), IpKey::V4(y)) => {
            let m = match mask {
                Some(IpKey::V4(m)) => m,
                _ => 0xffff_ffff,
            };
            x & m == y & m
        }
        (IpKey::V6(x), IpKey::V6(y)) => {
            let m = match mask {
                Some(IpKey::V6(m)) => m,
                _ => [0xff; 16],
            };
            (0..16).all(|i| x[i] & m[i] == y[i] & m[i])
        }
        (IpKey::Id(x), IpKey::Id(y)) => x == y,
        _ => false,
    }
}

/// chrony `UTI_IPToHash`: `hash = seed; for b in addr_bytes { hash = 71*hash + b }; hash +
/// seed` (all `u32` wrapping). `seed` is the process-random seed (host boundary). An
/// invalid family hashes to 0 (chrony's `default` case).
pub fn ip_to_hash(seed: u32, ip: IpKey) -> u32 {
    if !ip.is_valid_family() {
        return 0;
    }
    let mut hash = seed;
    for b in ip.hash_bytes() {
        hash = hash.wrapping_mul(71).wrapping_add(b as u32);
    }
    hash.wrapping_add(seed)
}

/// An entry in the source table (chrony `SourceRecord`, address fields only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteAddr {
    pub ip: IpKey,
    pub port: u16,
}

/// The result of [`SourceTable::find_slot2`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Find2 {
    /// IP not matched (an empty slot is returned for a valid address).
    NoMatch,
    /// IP matched but the port differs.
    IpOnly,
    /// Both IP and port matched.
    Both,
}

/// chrony `MAX_SOURCES`.
pub const MAX_SOURCES: u32 = 65536;

/// chrony's open-addressing source table: a power-of-two array of optional records,
/// probed quadratically by the seeded IP hash. `n_sources` is the logical source count
/// (chrony's `n_sources`) that drives growth — distinct from the slot count.
#[derive(Clone, Debug)]
pub struct SourceTable {
    seed: u32,
    slots: Vec<Option<RemoteAddr>>,
    n_sources: u32,
}

impl SourceTable {
    /// Create a table with `size` slots (chrony's size is always a power of two).
    pub fn with_size(seed: u32, size: usize) -> Self {
        SourceTable { seed, slots: vec![None; size], n_sources: 0 }
    }

    /// A freshly-initialised table (chrony `NSR_Initialise`: a 1-slot table, no sources).
    pub fn new(seed: u32) -> Self {
        SourceTable::with_size(seed, 1)
    }

    /// The logical source count (`n_sources`).
    pub fn n_sources(&self) -> u32 {
        self.n_sources
    }

    /// chrony `find_slot`: locate the slot matching `ip`. Returns `(matched, slot)`; when
    /// not matched, `slot` is the first empty slot found on the probe sequence (or 0 if
    /// the family is invalid or the probe gave up).
    pub fn find_slot(&self, ip: IpKey) -> (bool, usize) {
        // chrony rejects families other than INET4/INET6/ID up front (returns slot 0).
        if !ip.is_valid_family() {
            return (false, 0);
        }
        let size = self.slots.len();
        let hash = ip_to_hash(self.seed, ip) as usize;
        let mut slot = 0;
        for i in 0..size / 2 {
            // Quadratic probing: (hash + (i + i*i)/2) mod size.
            slot = (hash.wrapping_add((i + i * i) / 2)) % size;
            match self.slots[slot] {
                None => return (false, slot),
                Some(rec) if rec.ip == ip => return (true, slot),
                _ => {}
            }
        }
        (false, slot)
    }

    /// chrony `find_slot2`: match IP and port. `NoMatch` returns the empty slot for
    /// insertion; `IpOnly`/`Both` return the matching slot.
    pub fn find_slot2(&self, addr: RemoteAddr) -> (Find2, usize) {
        let (found, slot) = self.find_slot(addr.ip);
        if !found {
            return (Find2::NoMatch, slot);
        }
        let port_match = self.slots[slot].map(|r| r.port) == Some(addr.port);
        (if port_match { Find2::Both } else { Find2::IpOnly }, slot)
    }

    /// Insert `addr` (chrony's `add_source` core: find an empty slot, occupy it). Returns
    /// the slot used.
    pub fn insert(&mut self, addr: RemoteAddr) -> usize {
        let (_, slot) = self.find_slot(addr.ip);
        self.slots[slot] = Some(addr);
        slot
    }

    /// The current table size (number of slots).
    pub fn size(&self) -> usize {
        self.slots.len()
    }

    /// The record at `slot`, if occupied.
    pub fn get(&self, slot: usize) -> Option<RemoteAddr> {
        self.slots[slot]
    }

    /// chrony `rehash_records`: grow the table to the smallest power-of-two size that
    /// satisfies [`check_hashtable_size`] for `n_sources`, then re-insert every existing
    /// record (probing its new slot in the old-slot order). `n_sources` is the source
    /// count driving the resize (chrony increments it before rehashing on an add).
    pub fn rehash(&mut self, n_sources: u32) {
        let old = std::mem::take(&mut self.slots);

        // The size of the hash table is always a power of two.
        let mut new_size: u32 = 1;
        while !check_hashtable_size(n_sources, new_size) {
            new_size *= 2;
        }

        self.slots = vec![None; new_size as usize];
        for rec in old.into_iter().flatten() {
            let (r, slot) = self.find_slot2(rec);
            debug_assert_eq!(r, Find2::NoMatch, "rehash: address unexpectedly present");
            self.slots[slot] = Some(rec);
        }
    }

    /// chrony `add_source`: validate and insert a source keyed by `addr`. `has_name` is
    /// whether a source name was given; `ip_is_real` is `UTI_IsIPReal` (host/util). The
    /// checks run in chrony's order — already-present, name-required-for-unreal-address,
    /// too-many-sources, invalid-family — then the table grows if needed and the record is
    /// placed. The `NCR_Instance`/socket/pool/start side effects are host-boundary and not
    /// modeled here.
    pub fn add_source(&mut self, addr: RemoteAddr, has_name: bool, ip_is_real: bool) -> NsrStatus {
        if self.find_slot2(addr).0 != Find2::NoMatch {
            return NsrStatus::AlreadyInUse;
        }
        if !has_name && !ip_is_real {
            return NsrStatus::InvalidName;
        }
        if self.n_sources >= MAX_SOURCES {
            return NsrStatus::TooManySources;
        }
        if !addr.ip.is_valid_family() {
            return NsrStatus::InvalidAf;
        }

        self.n_sources += 1;
        if !check_hashtable_size(self.n_sources, self.slots.len() as u32) {
            self.rehash(self.n_sources);
        }
        let (r, slot) = self.find_slot2(addr);
        debug_assert_eq!(r, Find2::NoMatch, "add_source: address unexpectedly present");
        self.slots[slot] = Some(addr);
        NsrStatus::Success
    }

    /// chrony `NSR_Modify*` dispatch: look up the source by `address`; the closure applies
    /// the per-source change (the already-ported `NCR_Modify*`). Returns `true` if the
    /// source was found (chrony's `1`), `false` if not (`0`).
    pub fn modify_source<F: FnOnce(RemoteAddr)>(&self, address: IpKey, apply: F) -> bool {
        let (found, slot) = self.find_slot(address);
        if !found {
            return false;
        }
        apply(self.slots[slot].unwrap());
        true
    }

    /// Test/setup helper: set the logical source count (chrony's `n_sources`).
    #[cfg(test)]
    fn set_n_sources(&mut self, n: u32) {
        self.n_sources = n;
    }

    /// chrony `NSR_RemoveSource` (table part): remove the source at `address`. Returns
    /// `NoSuchSource` if absent; otherwise clears the slot, decrements `n_sources`, and
    /// rehashes (chrony rehashes after every removal to keep probe sequences unbroken).
    /// The pool-counter bookkeeping (`clean_source_record`'s pool branch) is
    /// [`SourcePool::on_remove`]; the `NCR_DestroyInstance`/name-free are host-boundary.
    pub fn remove_source(&mut self, address: IpKey) -> NsrStatus {
        let (found, slot) = self.find_slot(address);
        if !found {
            return NsrStatus::NoSuchSource;
        }
        self.slots[slot] = None;
        self.n_sources -= 1;
        self.rehash(self.n_sources);
        NsrStatus::Success
    }
}

impl SourceTable {
    /// chrony's source-iteration match (used by `NSR_InitiateSampleBurst`,
    /// `NSR_SetConnectivity`): the occupied slots whose address matches `address` under
    /// `mask`, in slot order. An `Unspec` address matches every source. Returns
    /// `(matched_slots, any)` where `any` is chrony's return flag.
    pub fn select_matching(&self, address: IpKey, mask: Option<IpKey>) -> (Vec<usize>, bool) {
        let mut matched = Vec::new();
        for (slot, rec) in self.slots.iter().enumerate() {
            if let Some(r) = rec {
                if matches!(address, IpKey::Unspec) || ip_equal_under_mask(r.ip, address, mask) {
                    matched.push(slot);
                }
            }
        }
        let any = !matched.is_empty();
        (matched, any)
    }

    /// chrony `NSR_RemoveAllSources`: clean every record and rehash back to the empty
    /// 1-slot table.
    pub fn remove_all(&mut self) {
        for s in self.slots.iter_mut() {
            *s = None;
        }
        self.n_sources = 0;
        self.rehash(0);
    }

    /// chrony `NSR_GetLocalRefid`: the local reference id for the source at `address`
    /// (via `refid_of`, the ported `NCR_GetLocalRefid`), or 0 when no such source.
    pub fn get_local_refid<F: Fn(RemoteAddr) -> u32>(&self, address: IpKey, refid_of: F) -> u32 {
        match self.find_slot(address) {
            (true, slot) => refid_of(self.slots[slot].unwrap()),
            _ => 0,
        }
    }
}

/// chrony `struct SourcePool`: per-pool source counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourcePool {
    pub sources: i32,
    pub unresolved_sources: i32,
    pub confirmed_sources: i32,
    pub max_sources: i32,
}

impl SourcePool {
    /// chrony `clean_source_record`'s pool branch: account for removing a source.
    /// `is_real` is `UTI_IsIPReal(addr)`; `tentative` is the record's tentative flag.
    pub fn on_remove(&mut self, is_real: bool, tentative: bool) {
        self.sources -= 1;
        if !is_real {
            self.unresolved_sources -= 1;
        }
        if !tentative {
            self.confirmed_sources -= 1;
        }
        if self.max_sources > self.sources {
            self.max_sources = self.sources;
        }
    }
}

#[cfg(test)]
mod tests;
