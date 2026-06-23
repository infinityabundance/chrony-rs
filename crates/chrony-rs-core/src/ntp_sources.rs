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
}

impl IpKey {
    /// The raw address bytes hashed by `UTI_IPToHash`, in host (little-endian on the
    /// oracle's platform) order — matching chrony hashing the in-memory representation.
    fn hash_bytes(&self) -> Vec<u8> {
        match self {
            IpKey::V4(v) => v.to_le_bytes().to_vec(),
            IpKey::V6(b) => b.to_vec(),
            IpKey::Id(v) => v.to_le_bytes().to_vec(),
        }
    }
}

/// chrony `UTI_IPToHash`: `hash = seed; for b in addr_bytes { hash = 71*hash + b }; hash +
/// seed` (all `u32` wrapping). `seed` is the process-random seed (host boundary).
pub fn ip_to_hash(seed: u32, ip: IpKey) -> u32 {
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

/// chrony's open-addressing source table: a power-of-two array of optional records,
/// probed quadratically by the seeded IP hash.
#[derive(Clone, Debug)]
pub struct SourceTable {
    seed: u32,
    slots: Vec<Option<RemoteAddr>>,
}

impl SourceTable {
    /// Create a table with `size` slots (chrony's size is always a power of two).
    pub fn with_size(seed: u32, size: usize) -> Self {
        SourceTable { seed, slots: vec![None; size] }
    }

    /// chrony `find_slot`: locate the slot matching `ip`. Returns `(matched, slot)`; when
    /// not matched, `slot` is the first empty slot found on the probe sequence (or 0 if
    /// the family is invalid or the probe gave up).
    pub fn find_slot(&self, ip: IpKey) -> (bool, usize) {
        let size = self.slots.len();
        // chrony rejects families other than INET4/INET6/ID up front.
        // (All IpKey variants are valid; an invalid family never reaches here.)
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
}

#[cfg(test)]
mod tests;
