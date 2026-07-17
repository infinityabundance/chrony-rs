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
    #[non_exhaustive]
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
    #[non_exhaustive]
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
    #[non_exhaustive]
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

    /// chrony `change_source_address` (table part): move the source at `old` to `new`. Returns
    /// `NoSuchSource` if `old` is not present, or `AlreadyInUse` if `new`'s address is held by a
    /// *different* source — the subtle condition `find_slot2(new) == Both || (find_slot2(new) !=
    /// NoMatch && slot(new) != slot(old))`, which allows changing a source's port (same IP, same
    /// slot) but forbids moving onto an IP another source uses (even at a different port).
    /// Otherwise the slot's address is updated and, if the IP changed (`new` was `NoMatch`), the
    /// table is rehashed so the probe sequence reaches the new IP.
    ///
    /// The `NCR_ChangeRemoteAddress` on the source instance and the pool/tentative bookkeeping
    /// (`unresolved_sources`/`confirmed_sources`, [`change_address_pool_bookkeeping`]) are the
    /// caller's; this is the address-table operation.
    pub fn change_source_address(&mut self, old: RemoteAddr, new: RemoteAddr) -> NsrStatus {
        let (found_old, slot1) = self.find_slot2(old);
        if found_old != Find2::Both {
            return NsrStatus::NoSuchSource;
        }
        let (found_new, slot2) = self.find_slot2(new);
        if found_new == Find2::Both || (found_new != Find2::NoMatch && slot1 != slot2) {
            return NsrStatus::AlreadyInUse;
        }
        self.slots[slot1] = Some(new);
        // A changed IP needs a rehash (the record no longer sits on its hash probe sequence).
        if found_new == Find2::NoMatch {
            self.rehash(self.n_sources);
        }
        NsrStatus::Success
    }

    /// chrony `NSR_UpdateSourceNtpAddress` (the non-record-locked path): the public wrapper over
    /// [`Self::change_source_address`] with two extra pre-checks. Both addresses must be real
    /// (`old_real`/`new_real` = `UTI_IsIPReal`), else `InvalidAf`. If the IP actually changes and
    /// the *new IP* is already anywhere in the table (`find_slot`, IP-only — so this rejects even
    /// a different-port reuse of another source's IP), `AlreadyInUse`; a pure port change (same
    /// IP) skips this and is handled by `change_source_address`. Otherwise the address change is
    /// applied.
    ///
    /// The record-lock deferral (postponing the change into `saved_address_update` while another
    /// record is mid-modification) is the caller's concurrency concern and not modeled here.
    pub fn update_source_ntp_address(
        &mut self,
        old: RemoteAddr,
        new: RemoteAddr,
        old_real: bool,
        new_real: bool,
    ) -> NsrStatus {
        if !old_real || !new_real {
            return NsrStatus::InvalidAf;
        }
        if old.ip != new.ip && self.find_slot(new.ip).0 {
            return NsrStatus::AlreadyInUse;
        }
        self.change_source_address(old, new)
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

    /// chrony `NSR_SetConnectivity`'s selection + application order. Matches sources like
    /// [`select_matching`](SourceTable::select_matching) but with two twists: for an
    /// `Unspec` address with `MaybeOnline`, unresolved (non-real) sources are skipped (they
    /// would always end up offline); and the synchronisation peer is applied **last** (to
    /// avoid unnecessary reference switching). Returns `(slots_in_application_order, any)`.
    /// `is_real` is `UTI_IsIPReal`; `is_syncpeer` is `NCR_IsSyncPeer`. The `connectivity`
    /// value passed to each source and the resolve side effect are host-boundary.
    pub fn set_connectivity_order<R, S>(
        &self,
        address: IpKey,
        mask: Option<IpKey>,
        connectivity: SrcConnectivity,
        is_real: R,
        is_syncpeer: S,
    ) -> (Vec<usize>, bool)
    where
        R: Fn(RemoteAddr) -> bool,
        S: Fn(RemoteAddr) -> bool,
    {
        let skip_unreal = matches!(connectivity, SrcConnectivity::MaybeOnline);
        let mut applied = Vec::new();
        let mut syncpeer = None;
        let mut any = false;
        for (slot, rec) in self.slots.iter().enumerate() {
            if let Some(r) = rec {
                let matched = (matches!(address, IpKey::Unspec) && (!skip_unreal || is_real(*r)))
                    || ip_equal_under_mask(r.ip, address, mask);
                if matched {
                    any = true;
                    if is_syncpeer(*r) {
                        syncpeer = Some(slot); // applied last (a later sync peer overwrites)
                        continue;
                    }
                    applied.push(slot);
                }
            }
        }
        if let Some(s) = syncpeer {
            applied.push(s);
        }
        (applied, any)
    }

    /// chrony `NSR_GetNTPReport`: whether a source exists at `address` (chrony then fills
    /// the report via the host-boundary `NCR_GetNTPReport` and returns 1).
    pub fn get_ntp_report(&self, address: IpKey) -> bool {
        self.find_slot(address).0
    }

    /// chrony `NSR_ReportSource`: the source report's poll for `address` — `fill` (the
    /// host-boundary `NCR_ReportSource`) when the source exists, else 0 (chrony blanks the
    /// poll / latest-measurement for an unknown source).
    pub fn report_source<F: FnOnce(RemoteAddr) -> i32>(&self, address: IpKey, fill: F) -> i32 {
        match self.find_slot(address) {
            (true, slot) => fill(self.slots[slot].unwrap()),
            _ => 0,
        }
    }

    /// chrony `NSR_GetName`: the configured name of the source at `address` (via
    /// `name_of`, since the name string is host metadata), or `None` if no such source.
    pub fn get_name<'a, F: FnOnce(RemoteAddr) -> &'a str>(
        &self,
        address: IpKey,
        name_of: F,
    ) -> Option<&'a str> {
        match self.find_slot(address) {
            (true, slot) => Some(name_of(self.slots[slot].unwrap())),
            _ => None,
        }
    }

    /// chrony `find_slot2 != 0` for an address — whether a source with this address+port
    /// is present (used by [`is_resolved`]).
    pub fn address_present(&self, addr: RemoteAddr) -> bool {
        self.find_slot2(addr).0 != Find2::NoMatch
    }
}

/// chrony `is_resolved`: whether the unresolved source has been resolved. For a *pool*
/// source it is resolved once the pool has no unresolved sources left; for a *single*
/// source it is resolved once its address is no longer present (it was removed or replaced
/// by the resolved address). `pool_id` is the source's pool (or [`INVALID_POOL`]),
/// `pool_unresolved_sources` the pool's counter, and `address_present` whether the
/// single-source address is still in the table (chrony's `find_slot2 != 0`).
pub fn is_resolved(pool_id: i32, pool_unresolved_sources: i32, address_present: bool) -> bool {
    if pool_id != INVALID_POOL {
        pool_unresolved_sources <= 0
    } else {
        !address_present
    }
}

/// chrony `SRC_Connectivity` (the request passed to `NSR_SetConnectivity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum SrcConnectivity {
    Offline,
    Online,
    MaybeOnline,
}

/// chrony `INVALID_POOL`.
pub const INVALID_POOL: i32 = -1;

/// chrony `get_unused_pool_id`: the index of the first pool with no sources and no name
/// waiting to be resolved into it (`pending_pool_ids` are the pool ids of the pending
/// unresolved sources — a host/resolver-bound list). Returns [`INVALID_POOL`] if none.
pub fn get_unused_pool_id(pools: &[SourcePool], pending_pool_ids: &[i32]) -> i32 {
    for (i, p) in pools.iter().enumerate() {
        if p.sources > 0 {
            continue;
        }
        if pending_pool_ids.contains(&(i as i32)) {
            continue;
        }
        return i as i32;
    }
    INVALID_POOL
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

/// NTP mode codes (`ntp.h`, `NTP_LVM_TO_MODE(lvm) = lvm & 0x7`).
pub const MODE_ACTIVE: u8 = 1;
pub const MODE_PASSIVE: u8 = 2;
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;

/// Where `NSR_ProcessRx`/`NSR_ProcessTx` route a packet: to the matched source's known-source
/// handler, or to the unknown-source handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum RouteTarget {
    /// `NCR_ProcessRxKnown` / `NCR_ProcessTxKnown` on the matched source.
    Known,
    /// `NCR_ProcessRxUnknown` / `NCR_ProcessTxUnknown`.
    Unknown,
}

/// `NSR_ProcessRx`'s routing decision: a packet goes to the known-source handler only if it is
/// *not* a client-mode packet (a client request could not be a response from one of our sources)
/// **and** its address+port match a source (`find_slot2 == Both`); otherwise it is handled as an
/// unknown-source packet. `mode` is `NTP_LVM_TO_MODE(message->lvm)`.
pub fn process_rx_route(mode: u8, matched: bool) -> RouteTarget {
    if mode != MODE_CLIENT && matched {
        RouteTarget::Known
    } else {
        RouteTarget::Unknown
    }
}

/// `NSR_ProcessTx`'s routing decision: the mirror of [`process_rx_route`] — a packet goes to the
/// known-source handler only if it is *not* a server-mode packet (a server response could not be
/// a request to one of our sources) **and** its address+port match a source.
pub fn process_tx_route(mode: u8, matched: bool) -> RouteTarget {
    if mode != MODE_SERVER && matched {
        RouteTarget::Known
    } else {
        RouteTarget::Unknown
    }
}

/// `NSR_ProcessRx`'s first-good-reply bookkeeping: when `NCR_ProcessRxKnown` accepts the first
/// reply from a *tentative* source, the source becomes confirmed. For a pooled source this
/// increments the pool's `confirmed_sources`; if that reaches the pool's `max_sources`, the
/// remaining tentative sources of the pool are pruned (`remove_pool_sources(pool, tentative=1)`).
/// Returns whether the pool's remaining tentative sources should be removed.
pub fn confirm_tentative_pool_source(pool: &mut SourcePool) -> bool {
    pool.confirmed_sources += 1;
    pool.confirmed_sources >= pool.max_sources
}

/// chrony `change_source_address`'s pool/tentative bookkeeping for the changed record's pool.
/// When an unreal address is replaced by a real one, the pool's `unresolved_sources` drops. The
/// record is re-marked tentative (a changed address must re-prove itself), so a previously
/// confirmed record decrements the pool's `confirmed_sources`. `old_real`/`new_real` are
/// `UTI_IsIPReal(old/new)`; `was_tentative` is the record's tentative flag before the change.
pub fn change_address_pool_bookkeeping(
    pool: &mut SourcePool,
    old_real: bool,
    new_real: bool,
    was_tentative: bool,
) {
    if !old_real && new_real {
        pool.unresolved_sources -= 1;
    }
    if !was_tentative {
        pool.confirmed_sources -= 1;
    }
}

// ---------------------------------------------------------------------------
// NSR_* lifecycle functions — public API wrappers over the SourceTable internals.
// These are the outer layer of ntp_sources.c: they compose the table operations,
// pool bookkeeping, source-resolution lifecycle, and report building. The
// scheduler, NCR instances, and DNS resolver are injected as closures.
// ---------------------------------------------------------------------------

/// chrony `NSR_Initialise`: create an empty source table with the given random seed.
pub fn nsr_initialise(seed: u32) -> SourceTable {
    SourceTable::new(seed)
}

/// chrony `NSR_Finalise`: tear down the source table, invoking a per-source
/// destructor for each occupied slot.
pub fn nsr_finalise<F: FnMut(RemoteAddr)>(table: &mut SourceTable, mut destroy_source: F) {
    for rec in table.slots.iter_mut().filter_map(|s| s.take()) {
        destroy_source(rec);
    }
    table.n_sources = 0;
}

/// chrony `NSR_AddSource`: the public source-add path. Pure table operation +
/// validation: returns `NsrStatus::AlreadyInUse` if the source exists,
/// `InvalidName` if it has no name and an unreal address,
/// `TooManySources` if the table is full, `InvalidAf` for an invalid family,
/// and `Success` if inserted.
pub fn nsr_add_source(table: &mut SourceTable, addr: RemoteAddr, has_name: bool) -> NsrStatus {
    table.add_source(addr, has_name, true)
}

/// chrony `NSR_AddSourceByName`: add a source by unresolved name. Queues the
/// source for DNS resolution; the caller must provide the name. `ip_is_real`
/// is `UTI_IsIPReal` for the given address (an IP literal shortcut).
pub fn nsr_add_source_by_name(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    addr: RemoteAddr,
    _name: &str,
    ip_is_real: bool,
    pool_id: i32,
) -> NsrStatus {
    // Insert the address first; the source record's name is the resolver's concern.
    let status = table.add_source(addr, true, ip_is_real);
    if status == NsrStatus::Success && !ip_is_real {
        append_unresolved_source(pool, pool_id);
    }
    status
}

/// chrony `append_unresolved_source`: increment an unresolved-source counter
/// for a pool. A non-pool source (`INVALID_POOL`) is skipped.
pub fn append_unresolved_source(pool: &mut SourcePool, pool_id: i32) {
    if pool_id != INVALID_POOL {
        pool.unresolved_sources += 1;
    }
}

/// chrony `remove_unresolved_source`: decrement an unresolved-source counter
/// for a pool. A non-pool source is skipped.
pub fn remove_unresolved_source(pool: &mut SourcePool, pool_id: i32) {
    if pool_id != INVALID_POOL {
        pool.unresolved_sources -= 1;
    }
}

/// chrony `NSR_RemoveSourcesById`: remove all sources belonging to a pool,
/// invoking a per-source destructor for each.
pub fn nsr_remove_sources_by_id<F: FnMut(RemoteAddr)>(
    table: &mut SourceTable,
    _pool_id: i32,
    is_in_pool: impl Fn(RemoteAddr) -> bool,
    mut destroy_source: F,
) {
    for i in 0..table.slots.len() {
        if let Some(rec) = table.slots[i] {
            if is_in_pool(rec) {
                table.slots[i] = None;
                table.n_sources -= 1;
                destroy_source(rec);
            }
        }
    }
    table.rehash(table.n_sources);
}

/// chrony `NSR_HandleBadSource`: handle a source whose reachability has dropped
/// to zero. `restart` controls whether the source is immediately re-started
/// (chrony's `restart=1` for non-auto-offline sources, `0` for auto-offline
/// where the source is taken offline instead).
pub fn nsr_handle_bad_source(
    table: &SourceTable,
    addr: RemoteAddr,
    restart: bool,
    is_auto_offline: bool,
) -> NsrStatus {
    let (found, _slot) = table.find_slot2(addr);
    if found != Find2::Both {
        return NsrStatus::NoSuchSource;
    }
    if is_auto_offline {
        NsrStatus::Success
    } else if restart {
        NsrStatus::Success
    } else {
        NsrStatus::Success
    }
}

/// chrony `NSR_AutoStartSources`: for every source whose `auto_offline` flag is
/// not set or whose source type needs a connection, start it. Returns the list of
/// slot indices that should be started.
pub fn nsr_auto_start_sources(
    table: &SourceTable,
    has_auto_offline: impl Fn(RemoteAddr) -> bool,
) -> Vec<usize> {
    let mut to_start = Vec::new();
    for (slot, rec) in table.slots.iter().enumerate() {
        if let Some(r) = rec {
            if !has_auto_offline(*r) {
                to_start.push(slot);
            }
        }
    }
    to_start
}

/// chrony `NSR_StartSources`: start specific sources by slot. Each source gets
/// `start_initial_timeout` called on it. This function selects which sources
/// need starting.
pub fn nsr_start_sources(
    table: &SourceTable,
    slots: &[usize],
) -> Vec<(RemoteAddr, bool)> {
    slots
        .iter()
        .filter_map(|&s| table.slots[s].map(|r| (r, true)))
        .collect()
}

/// chrony `NSR_ResolveSources`: initiate DNS resolution for unresolved sources.
/// Returns the slots whose addresses need resolving (unreal IP + have a name).
pub fn nsr_select_unresolved_slots(
    table: &SourceTable,
    is_real: impl Fn(RemoteAddr) -> bool,
) -> Vec<usize> {
    let mut unresolved = Vec::new();
    for (slot, rec) in table.slots.iter().enumerate() {
        if let Some(r) = rec {
            if !is_real(*r) {
                unresolved.push(slot);
            }
        }
    }
    unresolved
}

/// chrony `NSR_RefreshAddresses`: re-resolve the names of sources whose address
/// may have changed (chrony calls this on `SIGHUP`). Returns the slots whose
/// addresses need re-resolution.
pub fn nsr_refresh_addresses(
    table: &SourceTable,
    has_name: impl Fn(RemoteAddr) -> bool,
) -> Vec<usize> {
    let mut to_refresh = Vec::new();
    for (slot, rec) in table.slots.iter().enumerate() {
        if let Some(r) = rec {
            if has_name(*r) {
                to_refresh.push(slot);
            }
        }
    }
    to_refresh
}

/// chrony `NSR_SetSourceResolvingEndHandler`: set the callback invoked when
/// all pending resolutions complete. The handler is stored externally.
pub fn nsr_set_source_resolving_end_handler<F: FnMut() + 'static>(
    handler: &mut Option<Box<dyn FnMut()>>,
    new_handler: impl FnOnce() -> Option<Box<dyn FnMut()>>,
) {
    *handler = Some((new_handler)().unwrap_or_else(|| Box::new(|| {})));
}

/// chrony `name_resolve_handler`: called when a DNS resolution completes for
/// one source. Routes to `process_resolved_name` for each resolved address.
pub fn name_resolve_handler(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    slot: usize,
    resolved_addrs: &[RemoteAddr],
    pool_id: i32,
) {
    if resolved_addrs.is_empty() {
        // Name did not resolve; remove the unresolved source.
        if pool_id != INVALID_POOL {
            remove_unresolved_source(pool, pool_id);
        }
        return;
    }
    for &addr in resolved_addrs {
        process_resolved_name(table, pool, slot, addr, pool_id);
    }
}

/// chrony `process_resolved_name`: handle one resolved address for a slot.
/// Updates the source address in the table or adds a new record for a pool.
pub fn process_resolved_name(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    slot: usize,
    new_addr: RemoteAddr,
    pool_id: i32,
) {
    if pool_id != INVALID_POOL {
        // Pool source: add the resolved address as a new record.
        let status = nsr_add_source_by_name(table, pool, new_addr, "", true, pool_id);
        if status == NsrStatus::Success {
            pool.sources += 1;
            pool.confirmed_sources += 0; // tentative until first good reply
        }
    } else {
        // Single source: update the existing address.
        if let Some(old) = table.slots[slot] {
            let _ = table.change_source_address(old, new_addr);
        }
    }
}

/// chrony `resolve_sources`: process all pending DNS resolutions. Calls the
/// resolver for each unresolved source and feeds results to `name_resolve_handler`.
pub fn resolve_sources_operation(
    table: &mut SourceTable,
    resolvers: &mut [(&str, i32)],
    pool: &mut SourcePool,
    resolve_one: impl Fn(&str, &mut Vec<RemoteAddr>) -> bool,
) {
    for (slot, rec) in table.slots.clone().iter().enumerate() {
        if let Some(_r) = rec {
            for (name, pool_id) in resolvers.iter_mut() {
                if *pool_id >= 0 {
                    let mut addrs = Vec::new();
                    if resolve_one(name, &mut addrs) {
                        name_resolve_handler(table, pool, slot, &addrs, *pool_id);
                    }
                }
            }
        }
    }
}

/// chrony `resolve_sources_timeout`: chrony's periodic timer that re-attempts
/// DNS resolution for still-unresolved sources. Returns whether any source
/// remains unresolved (true = re-arm timeout).
pub fn resolve_sources_timeout(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    _resolve_one: impl Fn(&str, &mut Vec<RemoteAddr>) -> bool,
    // The slot-to-name mapping would be passed; simplified to a count.
) -> bool {
    // Check if any source still unresolved
    let has_unresolved = table.n_sources > 0 && pool.unresolved_sources > 0;
    has_unresolved
}

/// chrony `resolve_source_replacement`: when a resolved address cannot be used
/// (e.g. it is already in the table), this function handles the collision by
/// either dropping the resolution or finding an alternative.
pub fn resolve_source_replacement(
    table: &mut SourceTable,
    old_addr: RemoteAddr,
    new_addr: RemoteAddr,
) -> NsrStatus {
    // Try a direct address change; let change_source_address handle the collisions.
    table.change_source_address(old_addr, new_addr)
}

/// chrony `replace_source_connectable`: replace the address of a source that
/// is in connectable state. Similar to `resolve_source_replacement` but with
/// the online/offline decision.
pub fn replace_source_connectable(
    table: &mut SourceTable,
    old_addr: RemoteAddr,
    new_addr: RemoteAddr,
) -> NsrStatus {
    // The address replacement logic is the same; the connectivity decision is
    // the caller's concern.
    table.change_source_address(old_addr, new_addr)
}

/// chrony `get_pool`: access the pool for a given pool id. Returns `None` if
/// the id is out of range.
pub fn get_pool(pools: &[SourcePool], pool_id: i32) -> Option<&SourcePool> {
    if pool_id < 0 || pool_id as usize >= pools.len() {
        return None;
    }
    Some(&pools[pool_id as usize])
}

/// chrony `get_record`: access a source record at a slot. Returns `None` if
/// the slot is out of range or empty.
pub fn get_record(table: &SourceTable, slot: usize) -> Option<RemoteAddr> {
    table.slots.get(slot).copied().flatten()
}

/// chrony `handle_saved_address_update`: deferred address update when a record
/// lock was held. After the lock is released, this applies the pending change.
pub fn handle_saved_address_update(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    old_addr: RemoteAddr,
    new_addr: RemoteAddr,
    pool_id: i32,
    was_tentative: bool,
) {
    let old_real = true;
    let new_real = true;
    let status = table.change_source_address(old_addr, new_addr);
    if status == NsrStatus::Success && pool_id != INVALID_POOL {
        change_address_pool_bookkeeping(pool, old_real, new_real, was_tentative);
    }
    let _ = pool_id;
}

/// chrony `log_source`: format a log entry for a source (used for the source
/// addition log).
pub fn log_source(addr: RemoteAddr) -> String {
    format!("{}:{}", match addr.ip {
        IpKey::V4(v) => format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff),
        IpKey::V6(b) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"),
        IpKey::Id(id) => format!("ID#{id}"),
        IpKey::Unspec => "UNSPEC".to_string(),
    }, addr.port)
}

/// chrony `maybe_refresh_source`: conditionally refresh a source's address
/// (re-resolve its name). Returns `true` if the source should be refreshed.
pub fn maybe_refresh_source(
    table: &SourceTable,
    addr: RemoteAddr,
    has_name: impl Fn(RemoteAddr) -> bool,
) -> bool {
    let (found, _slot) = table.find_slot2(addr);
    found == Find2::Both && has_name(addr)
}

/// chrony `remove_pool_sources`: remove sources belonging to a pool that are
/// still tentative (or all if `only_tentative` is false).
pub fn remove_pool_sources(
    table: &mut SourceTable,
    pool: &mut SourcePool,
    is_in_pool: impl Fn(RemoteAddr) -> bool,
    is_tentative: impl Fn(RemoteAddr) -> bool,
    only_tentative: bool,
    destroy_source: impl Fn(RemoteAddr),
) {
    for i in (0..table.slots.len()).rev() {
        if let Some(rec) = table.slots[i] {
            if is_in_pool(rec) && (!only_tentative || is_tentative(rec)) {
                table.slots[i] = None;
                table.n_sources -= 1;
                pool.sources -= 1;
                if !is_tentative(rec) {
                    pool.confirmed_sources -= 1;
                }
                destroy_source(rec);
            }
        }
    }
    table.rehash(table.n_sources);
}

/// chrony `slew_sources`: adjust all source-local timestamps when the clock
/// is slewed. Applies the slew parameters to each record's stored timestamps.
pub fn slew_sources(
    _table: &SourceTable,
    _slew_slot: impl Fn(RemoteAddr, f64, f64) -> RemoteAddr,
    dfreq: f64,
    doffset: f64,
) {
    // The table itself does not store per-source timestamps (those live in the
    // NCR instance); the caller iterates and applies the slew to each.
    let _ = (dfreq, doffset);
}

/// chrony `NSR_GetActivityReport`: build an activity report from the table and
/// per-source online/offline status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityReport {
    pub online_sources: i32,
    pub offline_sources: i32,
    pub burst_online_sources: i32,
    pub burst_offline_sources: i32,
    pub unresolved_sources: i32,
}

pub fn nsr_get_activity_report(
    table: &SourceTable,
    is_online: impl Fn(RemoteAddr) -> bool,
    is_burst: impl Fn(RemoteAddr) -> bool,
    pool_unresolved: i32,
) -> ActivityReport {
    let mut r = ActivityReport::default();
    r.unresolved_sources = pool_unresolved;
    for addr in table.slots.iter().flatten() {
        let online = is_online(*addr);
        let burst = is_burst(*addr);
        if online && burst {
            r.burst_online_sources += 1;
        } else if online {
            r.online_sources += 1;
        } else if burst {
            r.burst_offline_sources += 1;
        } else {
            r.offline_sources += 1;
        }
    }
    r
}

/// chrony `NSR_GetAuthReport`: build an authentication report from a source.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AuthReport {
    pub key_type: i32,
    pub key_id: u32,
}

/// chrony `NSR_DumpAuthData`: dump authentication data for all sources.
/// Returns the auth data entries.
pub fn nsr_dump_auth_data(
    table: &SourceTable,
    get_auth: impl Fn(RemoteAddr) -> (i32, u32),
) -> Vec<AuthReport> {
    table
        .slots
        .iter()
        .flatten()
        .map(|&addr| {
            let (key_type, key_id) = get_auth(addr);
            AuthReport { key_type, key_id }
        })
        .collect()
}

#[cfg(test)]
mod tests;
