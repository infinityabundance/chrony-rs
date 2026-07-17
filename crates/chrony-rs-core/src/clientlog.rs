//! Client access log + response rate limiter — a complete port of chrony 4.5
//! `clientlog.c` (all 35 functions).
//!
//! # What this module is
//!
//! chrony's `clientlog.c` keeps, for a server, a per-client record of how often
//! each client touches each *service* (NTP, NTS-KE, command/monitoring), and
//! decides whether a given response should be **rate-limited** (dropped). It also
//! maintains the RX→TX timestamp map needed for NTP **interleaved mode**. Three
//! mechanisms are entangled here, and the port keeps them faithfully:
//!
//! 1. **A hash table of [`Record`]s** keyed by client IP, with a fixed number of
//!    records per slot ([`SLOT_SIZE`]) and oldest-record eviction when a slot is
//!    full and the table cannot grow (`get_record`, `expand_hashtable`).
//! 2. **A token-bucket rate limiter** per service. Each hit refills tokens by the
//!    elapsed (fixed-point) time, each response spends `tokens_per_hit`, and when
//!    the bucket is dry a probabilistic *leak* (`limit_response_random`) still lets
//!    a fraction through so a spoofed-source flood cannot fully starve a victim
//!    (`CLG_LimitServiceRate`). A rough log2 request-rate estimate is maintained as
//!    an exponential-moving-average-ish value (`update_record`), with a second
//!    estimate for NTP requests that previously timed out so a client that retries
//!    harder when it gets no reply is not rate-limited into the ground.
//! 3. **An ordered circular map of RX→TX timestamps** for interleaved mode, found
//!    by a combined interpolation/binary search (`find_ntp_rx_ts`), trimmed on
//!    backward clock steps, and slew-corrected via a parameter-change handler
//!    (`CLG_SaveNtpTimestamps`, `CLG_GetNtpTxTimestamp`, `handle_slew`, …).
//!
//! # Adaptations (documented, not silent)
//!
//! * **Host boundary.** chrony uses module-global `static` state and reads the real
//!   clock, config, and `/dev/urandom` directly. Here all of that is injected: the
//!   state lives in a [`ClientLog`] value, configuration is passed in as
//!   [`ClientLogConfig`], "now" is passed as a [`Timespec`] to each call, and the
//!   random bytes chrony draws from `UTI_GetRandomBytes` come from an injected
//!   byte source (`rng`). This keeps the brain testable and side-effect-free while
//!   reproducing chrony's arithmetic bit-for-bit.
//! * **Indices, not pointers.** chrony's `get_record`/`get_index` hand out `Record *`
//!   and recover the index by pointer subtraction. The port returns the `usize`
//!   index directly — which is exactly the value chrony's public API returns to
//!   callers anyway (`CLG_GetClientIndex`, `CLG_LogServiceAccess`).
//! * **Typed slots.** chrony stores records in its byte-keyed `ARR_Instance`; the
//!   port uses a `Vec<Record>`. The behavioral contract (fixed-size indexable
//!   slots, set-size, element access) is identical; see [`crate::array`].
//! * **`sizeof` constants.** The memory budget that bounds the table
//!   (`max_slots`) divides the configured limit by `sizeof(Record) + sizeof(...)`.
//!   Those sizes are the chrony 4.5 C ABI sizes on the reference platform
//!   ([`RECORD_SIZE`], [`NTPTS_SIZE`]); they only affect how large the table may
//!   grow, never the per-record arithmetic.
//!
//! # Oracles
//!
//! The integer-exact heart (token bucket, drop decisions, rate estimate, the
//! interleaved map) is differential-tested against the **real compiled
//! `clientlog.c`**: a C generator drives the genuine module through deterministic
//! scenarios with an injected, reproducible random stream and emits input+output
//! vectors (`research/oracle/clientlog-c-vectors.txt`); the Rust port replays the
//! same inputs and must match every output. A second, independent Rust reference
//! cross-checks the token-bucket refill/spend logic. See the tests below.

use std::fmt;

/// Number of distinguished services, chrony `MAX_SERVICES`.
pub const MAX_SERVICES: usize = 3;

/// The services chrony rate-limits independently (`CLG_Service`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum Service {
    /// NTP server responses.
    Ntp = 0,
    /// NTS-KE (key establishment) responses.
    Ntske = 1,
    /// Command/monitoring (`chronyc`) responses.
    Cmdmon = 2,
}

impl Service {
    #[inline]
    fn index(self) -> usize {
        self as usize
    }
}

/// chrony `SLOT_BITS`: log2 of the number of records per hash-table slot.
const SLOT_BITS: u32 = 4;
/// chrony `SLOT_SIZE`: records in one slot.
pub const SLOT_SIZE: u32 = 1 << SLOT_BITS;
/// chrony `MIN_SLOTS`.
const MIN_SLOTS: u32 = 1;
/// chrony `MAX_SLOTS`: hard cap on the number of slots.
const MAX_SLOTS: u32 = 1 << (24 - SLOT_BITS);

/// chrony `TS_FRAC`: fractional bits in the 32-bit fixed-point hit timestamps.
const TS_FRAC: u32 = 4;
/// chrony `INVALID_TS`: the "never hit" timestamp sentinel.
const INVALID_TS: u32 = 0;

/// chrony `RATE_SCALE`: scaling of the 8-bit log2 request-rate estimate.
const RATE_SCALE: i32 = 4;
/// chrony `MIN_RATE`.
const MIN_RATE: i32 = -14 * RATE_SCALE;
/// chrony `INVALID_RATE`: the "no estimate yet" sentinel (also the i8 minimum).
const INVALID_RATE: i8 = -128;

/// chrony `MIN_LIMIT_INTERVAL`.
const MIN_LIMIT_INTERVAL: i32 = -15 - TS_FRAC as i32;
/// chrony `MAX_LIMIT_INTERVAL`.
const MAX_LIMIT_INTERVAL: i32 = 12;
/// chrony `MIN_LIMIT_BURST`.
const MIN_LIMIT_BURST: i32 = 1;
/// chrony `MAX_LIMIT_BURST`.
const MAX_LIMIT_BURST: i32 = 255;

/// chrony `MIN_LEAK_RATE`.
const MIN_LEAK_RATE: i32 = 1;
/// chrony `MAX_LEAK_RATE`.
const MAX_LEAK_RATE: i32 = 4;

/// Nanoseconds per second (`NSEC_PER_SEC`).
const NSEC_PER_SEC: u32 = 1_000_000_000;

/// chrony `NTPTS_DISABLED`.
const NTPTS_DISABLED: u8 = 1;
/// chrony `NTPTS_VALID_TX`.
const NTPTS_VALID_TX: u8 = 2;

/// chrony `NTPTS_FUTURE_LIMIT`: 1 second, in 64-bit NTP units.
const NTPTS_FUTURE_LIMIT: u64 = 1 << 32;
/// chrony `NTPTS_INSERT_LIMIT`.
const NTPTS_INSERT_LIMIT: u32 = 64;
/// chrony `MAX_NTP_TS` (`NTP_TS_HARDWARE`).
const MAX_NTP_TS: usize = 2;

/// `sizeof(Record)` for chrony 4.5 on the reference (LP64) platform. Used only in
/// the `max_slots` memory budget, exactly as chrony's `sizeof (Record)`.
pub const RECORD_SIZE: u64 = 64;
/// `sizeof(NtpTimestamps)` for chrony 4.5 on the reference platform.
pub const NTPTS_SIZE: u64 = 16;

/// A `struct timespec`-equivalent: seconds and nanoseconds, with the same signed
/// widths chrony relies on (`time_t`/`long` are 64-bit here). Several conversions
/// depend on exact integer behavior, so time is *not* collapsed to `f64` for this
/// module (unlike the discipline modules).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct from seconds and nanoseconds.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Timespec { tv_sec, tv_nsec }
    }

    /// chrony `UTI_NormaliseTimespec`.
    fn normalise(&mut self) {
        if self.tv_nsec >= NSEC_PER_SEC as i64 || self.tv_nsec < 0 {
            self.tv_sec += self.tv_nsec / NSEC_PER_SEC as i64;
            self.tv_nsec %= NSEC_PER_SEC as i64;
            if self.tv_nsec < 0 {
                self.tv_sec -= 1;
                self.tv_nsec += NSEC_PER_SEC as i64;
            }
        }
    }

    /// chrony `UTI_DiffTimespecs`: `self - b`, normalised.
    fn diff(self, b: Timespec) -> Timespec {
        let mut r = Timespec { tv_sec: self.tv_sec - b.tv_sec, tv_nsec: self.tv_nsec - b.tv_nsec };
        r.normalise();
        r
    }

    /// chrony `UTI_AddDoubleToTimespec`: `self + increment` seconds, normalised.
    fn add_double(self, increment: f64) -> Timespec {
        let int_part = increment as i64;
        let mut end = Timespec {
            tv_sec: self.tv_sec + int_part,
            tv_nsec: self.tv_nsec + (1.0e9 * (increment - int_part as f64)) as i64,
        };
        end.normalise();
        end
    }
}

/// chrony `LCL_ChangeType`: the kind of clock correction reported to handlers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum ChangeType {
    /// A frequency/offset slew (`LCL_ChangeAdjust`).
    Adjust,
    /// A known step (`LCL_ChangeStep`).
    Step,
    /// An unknown step, e.g. after an external clock jump (`LCL_ChangeUnknownStep`).
    UnknownStep,
}

/// chrony `NTP_Timestamp_Source`: which layer captured a timestamp.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum TimestampSource {
    /// Captured in the daemon (`NTP_TS_DAEMON`).
    Daemon = 0,
    /// Captured by the kernel (`NTP_TS_KERNEL`).
    Kernel = 1,
    /// Captured by hardware (`NTP_TS_HARDWARE`).
    Hardware = 2,
}

impl TimestampSource {
    fn from_index(i: u8) -> TimestampSource {
        match i {
            0 => TimestampSource::Daemon,
            1 => TimestampSource::Kernel,
            _ => TimestampSource::Hardware,
        }
    }
}

/// A client address. Mirrors chrony's `IPAddr` family tag so the hash and
/// comparison ports behave identically.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum ClientIp {
    /// chrony `IPADDR_UNSPEC`: an empty record slot.
    Unspec,
    /// chrony `IPADDR_INET4`.
    V4(u32),
    /// chrony `IPADDR_INET6`.
    V6([u8; 16]),
    /// chrony `IPADDR_ID`: an internal numeric id.
    Id(u32),
}

impl ClientIp {
    fn family(self) -> u16 {
        match self {
            ClientIp::Unspec => 0,
            ClientIp::V4(_) => 1,
            ClientIp::V6(_) => 2,
            ClientIp::Id(_) => 3,
        }
    }
}

/// Per-client record, chrony's `Record`.
#[derive(Clone, Copy, Debug)]
struct Record {
    ip_addr: ClientIp,
    last_hit: [u32; MAX_SERVICES],
    hits: [u32; MAX_SERVICES],
    drops: [u16; MAX_SERVICES],
    tokens: [u16; MAX_SERVICES],
    rate: [i8; MAX_SERVICES],
    ntp_timeout_rate: i8,
    drop_flags: u8,
}

impl Record {
    fn empty() -> Record {
        Record {
            ip_addr: ClientIp::Unspec,
            last_hit: [0; MAX_SERVICES],
            hits: [0; MAX_SERVICES],
            drops: [0; MAX_SERVICES],
            tokens: [0; MAX_SERVICES],
            rate: [0; MAX_SERVICES],
            ntp_timeout_rate: 0,
            drop_flags: 0,
        }
    }
}

/// chrony `NtpTimestamps`: an RX timestamp and the TX timestamp (as an offset) for
/// interleaved-mode responses.
#[derive(Clone, Copy)]
#[derive(Debug)]
struct NtpTimestamps {
    rx_ts: u64,
    flags: u8,
    tx_ts_source: u8,
    slew_epoch: u16,
    tx_ts_offset: i32,
}

impl NtpTimestamps {
    fn blank() -> NtpTimestamps {
        NtpTimestamps { rx_ts: 0, flags: 0, tx_ts_source: 0, slew_epoch: 0, tx_ts_offset: 0 }
    }
}

/// chrony `NtpTimestampMap`: ordered circular buffer of RX→TX timestamps.
#[derive(Debug)]
struct NtpTimestampMap {
    timestamps: Option<Vec<NtpTimestamps>>,
    first: u32,
    size: u32,
    max_size: u32,
    cached_index: u32,
    cached_rx_ts: u64,
    slew_epoch: u16,
    slew_offset: f64,
}

/// Per-service rate-limit configuration (chrony's `CNF_Get*RateLimit` triple).
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    /// Minimum interval between responses, log2 seconds.
    pub interval: i32,
    /// Burst length.
    pub burst: i32,
    /// Leak rate, log2 (probability of letting a response through when dry).
    pub leak_rate: i32,
}

/// Injected configuration, mirroring the `CNF_*` getters `CLG_Initialise` reads.
#[derive(Clone, Debug, Default)]
pub struct ClientLogConfig {
    /// `CNF_GetNTPRateLimit` (None ⇒ disabled).
    pub ntp_ratelimit: Option<RateLimit>,
    /// `CNF_GetNtsRateLimit`.
    pub nts_ratelimit: Option<RateLimit>,
    /// `CNF_GetCommandRateLimit`.
    pub cmd_ratelimit: Option<RateLimit>,
    /// `CNF_GetNoClientLog`.
    pub no_client_log: bool,
    /// `CNF_GetClientLogLimit` (memory budget, bytes).
    pub client_log_limit: u64,
}

/// A per-client report row, chrony's `RPT_ClientAccessByIndex_Report`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAccessReport {
    /// Client address.
    pub ip_addr: ClientIp,
    /// NTP hits.
    pub ntp_hits: u32,
    /// NTS-KE hits.
    pub nke_hits: u32,
    /// Command hits.
    pub cmd_hits: u32,
    /// NTP drops.
    pub ntp_drops: u16,
    /// NTS-KE drops.
    pub nke_drops: u16,
    /// Command drops.
    pub cmd_drops: u16,
    /// NTP estimated interval (log2 seconds; 127 ⇒ unknown).
    pub ntp_interval: i8,
    /// NTS-KE estimated interval.
    pub nke_interval: i8,
    /// Command estimated interval.
    pub cmd_interval: i8,
    /// NTP timeout-request estimated interval.
    pub ntp_timeout_interval: i8,
    /// Seconds since the last NTP hit (`u32::MAX` ⇒ never / future).
    pub last_ntp_hit_ago: u32,
    /// Seconds since the last NTS-KE hit.
    pub last_nke_hit_ago: u32,
    /// Seconds since the last command hit.
    pub last_cmd_hit_ago: u32,
}

/// Server-wide statistics, chrony's `RPT_ServerStatsReport`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStatsReport {
    /// Total NTP hits.
    pub ntp_hits: u64,
    /// Total NTS-KE hits.
    pub nke_hits: u64,
    /// Total command hits.
    pub cmd_hits: u64,
    /// Total NTP drops.
    pub ntp_drops: u64,
    /// Total NTS-KE drops.
    pub nke_drops: u64,
    /// Total command drops.
    pub cmd_drops: u64,
    /// Total records dropped (evicted) for lack of space.
    pub log_drops: u64,
    /// Authenticated NTP hits.
    pub ntp_auth_hits: u64,
    /// Interleaved NTP hits.
    pub ntp_interleaved_hits: u64,
    /// Number of stored interleaved timestamps.
    pub ntp_timestamps: u64,
    /// Span of the stored timestamps, seconds.
    pub ntp_span_seconds: u64,
    /// Daemon-captured RX timestamps.
    pub ntp_daemon_rx_timestamps: u64,
    /// Daemon-captured TX timestamps.
    pub ntp_daemon_tx_timestamps: u64,
    /// Kernel-captured RX timestamps.
    pub ntp_kernel_rx_timestamps: u64,
    /// Kernel-captured TX timestamps.
    pub ntp_kernel_tx_timestamps: u64,
    /// Hardware-captured RX timestamps.
    pub ntp_hw_rx_timestamps: u64,
    /// Hardware-captured TX timestamps.
    pub ntp_hw_tx_timestamps: u64,
}

/// The client access log + rate limiter (chrony's `clientlog.c` module state).
pub struct ClientLog {
    records: Vec<Record>,
    slots: u32,
    max_slots: u32,
    ts_offset: u32,
    /// Lazily-initialised non-zero hash seed (chrony's `static seed` in
    /// `UTI_IPToHash`).
    hash_seed: u32,
    max_tokens: [u16; MAX_SERVICES],
    tokens_per_hit: [u16; MAX_SERVICES],
    token_shift: [i32; MAX_SERVICES],
    leak_rate: [i32; MAX_SERVICES],
    limit_interval: [i32; MAX_SERVICES],
    active: bool,
    ntp_ts_map: NtpTimestampMap,
    total_hits: [u64; MAX_SERVICES],
    total_drops: [u64; MAX_SERVICES],
    total_ntp_auth_hits: u64,
    total_ntp_interleaved_hits: u64,
    total_record_drops: u64,
    total_ntp_rx_timestamps: [u64; MAX_NTP_TS + 1],
    total_ntp_tx_timestamps: [u64; MAX_NTP_TS + 1],
    /// `limit_response_random` carry state (chrony's function statics).
    leak_rnd: u32,
    leak_bits_left: i32,
    /// Injected random byte source (chrony's `UTI_GetRandomBytes`).
    rng: Box<dyn FnMut() -> u8>,
}

impl fmt::Debug for ClientLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientLog")
            .field("records", &self.records.len())
            .field("slots", &self.slots)
            .field("max_slots", &self.max_slots)
            .field("ts_offset", &self.ts_offset)
            .field("hash_seed", &self.hash_seed)
            .field("active", &self.active)
            .field("total_hits", &self.total_hits)
            .field("total_drops", &self.total_drops)
            .field("total_ntp_auth_hits", &self.total_ntp_auth_hits)
            .field("total_ntp_interleaved_hits", &self.total_ntp_interleaved_hits)
            .field("total_record_drops", &self.total_record_drops)
            .finish()
    }
}

#[inline]
fn clamp_i32(lo: i32, x: i32, hi: i32) -> i32 {
    x.max(lo).min(hi)
}

impl ClientLog {
    /// Draw the next random `u32`, mirroring `UTI_GetRandomBytes(&v, 4)` on a
    /// little-endian platform (four successive bytes, least significant first).
    fn random_u32(&mut self) -> u32 {
        let b = [
            (self.rng)(),
            (self.rng)(),
            (self.rng)(),
            (self.rng)(),
        ];
        u32::from_le_bytes(b)
    }

    /// chrony `UTI_IPToHash`, with the seed drawn lazily on first use.
    fn ip_to_hash(&mut self, ip: ClientIp) -> u32 {
        // Bytes are taken in the platform's native order, exactly as chrony reads
        // the raw address field; on the reference (LE) platform this matches the C
        // oracle. Like chrony, the resulting bucket distribution is therefore
        // byte-order dependent — it affects placement only, never correctness.
        let bytes: heapless_bytes::Bytes = match ip {
            ClientIp::V4(a) => heapless_bytes::Bytes::v4(a.to_ne_bytes()),
            ClientIp::V6(a) => heapless_bytes::Bytes::v16(a),
            ClientIp::Id(id) => heapless_bytes::Bytes::v4(id.to_ne_bytes()),
            ClientIp::Unspec => return 0,
        };

        while self.hash_seed == 0 {
            self.hash_seed = self.random_u32();
        }

        let mut hash = self.hash_seed;
        for &byte in bytes.as_slice() {
            hash = 71u32.wrapping_mul(hash).wrapping_add(byte as u32);
        }
        hash.wrapping_add(self.hash_seed)
    }

    /// chrony `compare_ts`: order two fixed-point timestamps, treating
    /// `INVALID_TS` as the smallest and comparing by signed difference.
    fn compare_ts(x: u32, y: u32) -> i32 {
        if x == y {
            return 0;
        }
        if y == INVALID_TS {
            return 1;
        }
        if (x.wrapping_sub(y)) as i32 > 0 {
            1
        } else {
            -1
        }
    }

    /// chrony `compare_total_hits`.
    fn compare_total_hits(x: &Record, y: &Record) -> i32 {
        let mut xh: u32 = 0;
        let mut yh: u32 = 0;
        for i in 0..MAX_SERVICES {
            xh = xh.wrapping_add(x.hits[i]);
            yh = yh.wrapping_add(y.hits[i]);
        }
        if xh > yh {
            1
        } else {
            -1
        }
    }

    /// chrony `get_ts_from_timespec`: convert a wall-clock time to the 32-bit
    /// fixed-point timestamp, with the random `ts_offset` mixed in.
    fn get_ts_from_timespec(&self, ts: Timespec) -> u32 {
        let mut sec = ts.tv_sec as u32;
        let mut nsec = (ts.tv_nsec as u32).wrapping_add(self.ts_offset);
        if nsec >= NSEC_PER_SEC {
            nsec -= NSEC_PER_SEC;
            sec = sec.wrapping_add(1);
        }
        // Fast, accurate-enough fixed-point conversion (chrony's exact expression).
        (sec << TS_FRAC) | ((140740u32.wrapping_mul(nsec >> 15)) >> (32 - TS_FRAC))
    }

    /// chrony `set_bucket_params`: derive bucket capacity, spend-per-hit, and the
    /// token shift from the configured interval and burst.
    fn set_bucket_params(interval: i32, burst: i32) -> (u16, u16, i32) {
        let interval = clamp_i32(MIN_LIMIT_INTERVAL, interval, MAX_LIMIT_INTERVAL);
        let mut burst = clamp_i32(MIN_LIMIT_BURST, burst, MAX_LIMIT_BURST);
        let mut token_shift;

        if interval >= -(TS_FRAC as i32) {
            token_shift = 0;
            while token_shift < interval + TS_FRAC as i32 {
                if (burst << (TS_FRAC as i32 + interval - token_shift)) < (1 << 16) {
                    break;
                }
                token_shift += 1;
            }
        } else {
            // Coarse rate limiting.
            token_shift = interval + TS_FRAC as i32;
            burst = burst.max(1 << -token_shift);
        }

        let tokens_per_packet: u32 = 1u32 << (TS_FRAC as i32 + interval - token_shift);
        let max_tokens: u32 = tokens_per_packet * burst as u32;

        (max_tokens as u16, tokens_per_packet as u16, token_shift)
    }

    /// chrony `CLG_Initialise`.
    ///
    /// `rng` is the injected random byte source standing in for
    /// `UTI_GetRandomBytes` (drawn one byte at a time, as chrony fills buffers).
    pub fn new(config: &ClientLogConfig, rng: Box<dyn FnMut() -> u8>) -> ClientLog {
        let mut clg = ClientLog {
            records: Vec::new(),
            slots: 0,
            max_slots: 0,
            ts_offset: 0,
            hash_seed: 0,
            max_tokens: [0; MAX_SERVICES],
            tokens_per_hit: [0; MAX_SERVICES],
            token_shift: [0; MAX_SERVICES],
            leak_rate: [0; MAX_SERVICES],
            limit_interval: [MIN_LIMIT_INTERVAL; MAX_SERVICES],
            active: false,
            ntp_ts_map: NtpTimestampMap {
                timestamps: None,
                first: 0,
                size: 0,
                max_size: 0,
                cached_index: 0,
                cached_rx_ts: 0,
                slew_epoch: 0,
                slew_offset: 0.0,
            },
            total_hits: [0; MAX_SERVICES],
            total_drops: [0; MAX_SERVICES],
            total_ntp_auth_hits: 0,
            total_ntp_interleaved_hits: 0,
            total_record_drops: 0,
            total_ntp_rx_timestamps: [0; MAX_NTP_TS + 1],
            total_ntp_tx_timestamps: [0; MAX_NTP_TS + 1],
            leak_rnd: 0,
            leak_bits_left: 0,
            rng,
        };

        for i in 0..MAX_SERVICES {
            clg.max_tokens[i] = 0;
            clg.tokens_per_hit[i] = 0;
            clg.token_shift[i] = 0;
            clg.leak_rate[i] = 0;
            clg.limit_interval[i] = MIN_LIMIT_INTERVAL;

            let rl = match i {
                0 => config.ntp_ratelimit,
                1 => config.nts_ratelimit,
                2 => config.cmd_ratelimit,
                _ => continue,
            };
            let Some(rl) = rl else { continue };

            let (mt, tph, ts) = Self::set_bucket_params(rl.interval, rl.burst);
            clg.max_tokens[i] = mt;
            clg.tokens_per_hit[i] = tph;
            clg.token_shift[i] = ts;
            clg.leak_rate[i] = clamp_i32(MIN_LEAK_RATE, rl.leak_rate, MAX_LEAK_RATE);
            clg.limit_interval[i] = clamp_i32(MIN_LIMIT_INTERVAL, rl.interval, MAX_LIMIT_INTERVAL);
        }

        clg.active = !config.no_client_log;
        if !clg.active {
            // chrony LOG_FATALs here; reproduce the invariant as a panic.
            for i in 0..MAX_SERVICES {
                assert!(
                    clg.leak_rate[i] == 0,
                    "rate limiting cannot be enabled with noclientlog"
                );
            }
            return clg;
        }

        // Maximum number of slots within the configured memory limit, accounting
        // for the transient double-copy during table expansion.
        let denom = (RECORD_SIZE + NTPTS_SIZE) * SLOT_SIZE as u64 * 3 / 2;
        let mut max_slots = config.client_log_limit / denom;
        max_slots = max_slots.clamp(MIN_SLOTS as u64, MAX_SLOTS as u64);
        clg.max_slots = max_slots as u32;

        let mut slots2: u32 = 0;
        while (1u64 << (slots2 + 1)) <= clg.max_slots as u64 {
            slots2 += 1;
        }

        clg.slots = 0;
        clg.records = Vec::new();
        clg.expand_hashtable();

        clg.ts_offset = clg.random_u32();
        clg.ts_offset %= NSEC_PER_SEC / (1 << TS_FRAC);

        clg.ntp_ts_map.max_size = 1u32 << (slots2 + SLOT_BITS);

        clg
    }

    /// chrony `expand_hashtable`: double the table (or initialise it). Returns
    /// whether the table grew.
    fn expand_hashtable(&mut self) -> bool {
        if !self.records.is_empty() && 2 * self.slots > self.max_slots {
            return false;
        }

        let old_records = core::mem::take(&mut self.records);

        self.slots = MIN_SLOTS.max(2 * self.slots);
        debug_assert!(self.slots <= self.max_slots || old_records.is_empty());

        self.records = vec![Record::empty(); (self.slots * SLOT_SIZE) as usize];

        if old_records.is_empty() {
            return true;
        }

        for old in old_records.iter() {
            if old.ip_addr == ClientIp::Unspec {
                continue;
            }
            let idx = self.get_record(old.ip_addr).expect("expand always finds a slot");
            self.records[idx] = *old;
        }

        true
    }

    /// chrony `get_record`: locate (or create) the record for `ip`. Returns the
    /// record index, or `None` if logging is inactive or the address has no family.
    fn get_record(&mut self, ip: ClientIp) -> Option<usize> {
        if !self.active
            || !matches!(ip, ClientIp::V4(_) | ClientIp::V6(_))
        {
            return None;
        }

        let mut record_idx;
        let mut oldest_idx: Option<usize>;
        let mut oldest_hit: u32 = 0;

        loop {
            let first = (self.ip_to_hash(ip) % self.slots * SLOT_SIZE) as usize;
            oldest_idx = None;
            let mut last_hit: u32 = 0;
            let mut found_empty = false;
            record_idx = first;

            let mut i = 0usize;
            while i < SLOT_SIZE as usize {
                record_idx = first + i;
                let rec = &self.records[record_idx];

                if Self::compare_ips(ip, rec.ip_addr) == 0 {
                    return Some(record_idx);
                }

                if rec.ip_addr == ClientIp::Unspec {
                    found_empty = true;
                    break;
                }

                for j in 0..MAX_SERVICES {
                    if j == 0 || Self::compare_ts(last_hit, rec.last_hit[j]) < 0 {
                        last_hit = rec.last_hit[j];
                    }
                }

                let replace = match oldest_idx {
                    None => true,
                    Some(o) => {
                        Self::compare_ts(oldest_hit, last_hit) > 0
                            || (oldest_hit == last_hit
                                && Self::compare_total_hits(&self.records[o], rec) > 0)
                    }
                };
                if replace {
                    oldest_idx = Some(record_idx);
                    oldest_hit = last_hit;
                }

                i += 1;
            }

            // If the slot still has an empty record, use it.
            if found_empty {
                break;
            }

            // Resize and retry: the new slot may have empty records.
            if self.expand_hashtable() {
                continue;
            }

            // No other option: replace the oldest record.
            record_idx = oldest_idx.expect("a full slot has an oldest record");
            self.total_record_drops += 1;
            break;
        }

        let rec = &mut self.records[record_idx];
        rec.ip_addr = ip;
        rec.last_hit = [INVALID_TS; MAX_SERVICES];
        rec.hits = [0; MAX_SERVICES];
        rec.drops = [0; MAX_SERVICES];
        rec.tokens = self.max_tokens;
        rec.rate = [INVALID_RATE; MAX_SERVICES];
        rec.ntp_timeout_rate = INVALID_RATE;
        rec.drop_flags = 0;

        Some(record_idx)
    }

    /// chrony `UTI_CompareIPs` (no mask), reduced to the families the log handles.
    fn compare_ips(a: ClientIp, b: ClientIp) -> i32 {
        if a.family() != b.family() {
            return a.family() as i32 - b.family() as i32;
        }
        match (a, b) {
            (ClientIp::Unspec, _) => 0,
            (ClientIp::V4(x), ClientIp::V4(y)) => x.wrapping_sub(y) as i32,
            (ClientIp::Id(x), ClientIp::Id(y)) => x.wrapping_sub(y) as i32,
            (ClientIp::V6(x), ClientIp::V6(y)) => {
                let mut d = 0i32;
                let mut i = 0;
                while d == 0 && i < 16 {
                    d = x[i] as i32 - y[i] as i32;
                    i += 1;
                }
                d
            }
            _ => 0,
        }
    }

    /// chrony `update_record`: refill tokens, bump hits, and update the rough log2
    /// request-rate estimate.
    fn update_record(&mut self, service: Service, record_idx: usize, now: Timespec) {
        let s = service.index();
        let now_ts = self.get_ts_from_timespec(now);
        let tshift = self.token_shift[s];
        let mtokens = self.max_tokens[s] as u32;

        let (prev_hit, interval);
        {
            let record = &mut self.records[record_idx];
            prev_hit = record.last_hit[s];
            record.last_hit[s] = now_ts;
            record.hits[s] = record.hits[s].wrapping_add(1);
            interval = now_ts.wrapping_sub(prev_hit);
        }

        if prev_hit == INVALID_TS || (interval as i32) < 0 {
            return;
        }

        let tokens: u32 = if tshift >= 0 {
            (now_ts >> tshift).wrapping_sub(prev_hit >> tshift)
        } else if now_ts.wrapping_sub(prev_hit) > mtokens {
            mtokens
        } else {
            now_ts.wrapping_sub(prev_hit) << -tshift
        };

        {
            let record = &mut self.records[record_idx];
            record.tokens[s] = (record.tokens[s] as u32 + tokens).min(mtokens) as u16;
        }

        // Convert the interval to scaled, rounded log2.
        let interval2: i32 = if interval != 0 {
            let mut iv = interval + (interval >> 1);
            let mut i2 = -RATE_SCALE * TS_FRAC as i32;
            while i2 < -MIN_RATE {
                if iv <= 1 {
                    break;
                }
                iv >>= 1;
                i2 += RATE_SCALE;
            }
            i2
        } else {
            -RATE_SCALE * (TS_FRAC as i32 + 1)
        };

        // For NTP, update either the normal or the timeout rate depending on
        // whether the client's previous request was answered or dropped.
        let use_timeout =
            service == Service::Ntp && (self.records[record_idx].drop_flags & (1u8 << s)) != 0;

        let rate_val = if use_timeout {
            self.records[record_idx].ntp_timeout_rate
        } else {
            self.records[record_idx].rate[s]
        };

        let new_rate = Self::update_rate(rate_val, interval2);

        let record = &mut self.records[record_idx];
        if use_timeout {
            record.ntp_timeout_rate = new_rate;
        } else {
            record.rate[s] = new_rate;
        }
    }

    /// The EMA-ish rate update from `update_record`, isolated for clarity. All
    /// arithmetic is done in `i32` and truncated to `i8` on store, matching the C.
    fn update_rate(rate: i8, interval2: i32) -> i8 {
        if rate == INVALID_RATE {
            return (-interval2) as i8;
        }
        let r = rate as i32;
        if r < -interval2 {
            (r + 1) as i8
        } else if r > -interval2 {
            if r > RATE_SCALE * 5 / 2 - interval2 {
                (RATE_SCALE * 5 / 2 - interval2) as i8
            } else {
                ((r - interval2 - 1) / 2) as i8
            }
        } else {
            rate
        }
    }

    /// chrony `CLG_GetClientIndex`.
    pub fn get_client_index(&mut self, client: ClientIp) -> i32 {
        match self.get_record(client) {
            None => -1,
            Some(idx) => idx as i32,
        }
    }

    /// chrony `CLG_LogServiceAccess`: log a hit and return the record index (or -1).
    pub fn log_service_access(&mut self, service: Service, client: ClientIp, now: Timespec) -> i32 {
        self.total_hits[service.index()] += 1;

        let Some(idx) = self.get_record(client) else {
            return -1;
        };

        self.update_record(service, idx, now);
        idx as i32
    }

    /// chrony `limit_response_random`: return 1 with probability `1 - 2^-leak_rate`
    /// (i.e. zero on average once per `2^leak_rate`), consuming random bits.
    fn limit_response_random(&mut self, leak_rate: i32) -> i32 {
        if self.leak_bits_left < leak_rate {
            self.leak_rnd = self.random_u32();
            self.leak_bits_left = 8 * 4;
        }
        let r = if self.leak_rnd % (1u32 << leak_rate) != 0 { 1 } else { 0 };
        self.leak_rnd >>= leak_rate;
        self.leak_bits_left -= leak_rate;
        r
    }

    /// chrony `CLG_LimitServiceRate`: decide whether to drop a response. Returns 1
    /// to drop, 0 to allow.
    pub fn limit_service_rate(&mut self, service: Service, index: usize) -> i32 {
        let s = service.index();
        if self.tokens_per_hit[s] == 0 {
            return 0;
        }

        self.records[index].drop_flags &= !(1u8 << s);

        if self.records[index].tokens[s] >= self.tokens_per_hit[s] {
            self.records[index].tokens[s] -= self.tokens_per_hit[s];
            return 0;
        }

        let mut drop = self.limit_response_random(self.leak_rate[s]);

        // A client getting no replies may retry faster; if its estimated request
        // rate while timing out is well above its rate when answered, invert the
        // leak so most requests are answered (but keep estimating the rate).
        if service == Service::Ntp
            && self.records[index].ntp_timeout_rate != INVALID_RATE
            && self.records[index].ntp_timeout_rate as i32
                > self.records[index].rate[s] as i32 + RATE_SCALE
        {
            drop = if drop != 0 { 0 } else { 1 };
        }

        if drop == 0 {
            self.records[index].tokens[s] = 0;
            return 0;
        }

        self.records[index].drop_flags |= 1u8 << s;
        self.records[index].drops[s] = self.records[index].drops[s].wrapping_add(1);
        self.total_drops[s] += 1;
        1
    }

    /// chrony `CLG_UpdateNtpStats`.
    pub fn update_ntp_stats(
        &mut self,
        auth: bool,
        rx_ts_src: TimestampSource,
        tx_ts_src: TimestampSource,
    ) {
        if auth {
            self.total_ntp_auth_hits += 1;
        }
        self.total_ntp_rx_timestamps[rx_ts_src as usize] += 1;
        self.total_ntp_tx_timestamps[tx_ts_src as usize] += 1;
    }

    /// chrony `CLG_GetNtpMinPoll`.
    pub fn get_ntp_min_poll(&self) -> i32 {
        self.limit_interval[Service::Ntp.index()]
    }

    // ---- interleaved-mode RX→TX timestamp map ----

    /// chrony `get_ntp_tss`: element at logical `index` in the circular buffer.
    fn ntp_tss_index(&self, index: u32) -> usize {
        ((self.ntp_ts_map.first + index) & (self.ntp_ts_map.max_size - 1)) as usize
    }

    /// chrony `find_ntp_rx_ts`: combined interpolation/binary search for `rx_ts`.
    /// Returns `(found, index)`; on miss `index` is the insertion point.
    fn find_ntp_rx_ts(&mut self, rx_ts: u64) -> (bool, u32) {
        if self.ntp_ts_map.cached_rx_ts == rx_ts && rx_ts != 0 {
            return (true, self.ntp_ts_map.cached_index);
        }
        if self.ntp_ts_map.size == 0 {
            return (false, 0);
        }

        let mut lo = 0u32;
        let mut hi = self.ntp_ts_map.size - 1;
        let Some(ref ts) = self.ntp_ts_map.timestamps else {
            return (false, 0);
        };
        let mut rx_lo = ts[self.ntp_tss_index(lo)].rx_ts;
        let mut rx_hi = ts[self.ntp_tss_index(hi)].rx_ts;

        // Compare by difference so adjacent NTP eras work. Check < lo before > hi
        // so a "future" timestamp does not break endpoint order.
        if (rx_ts.wrapping_sub(rx_lo) as i64) < 0 {
            return (false, 0);
        } else if (rx_ts.wrapping_sub(rx_hi) as i64) > 0 {
            return (false, self.ntp_ts_map.size);
        }

        let mut i = 0u32;
        loop {
            if rx_ts == rx_hi {
                self.ntp_ts_map.cached_index = hi;
                self.ntp_ts_map.cached_rx_ts = rx_ts;
                return (true, hi);
            } else if rx_ts == rx_lo {
                self.ntp_ts_map.cached_index = lo;
                self.ntp_ts_map.cached_rx_ts = rx_ts;
                return (true, lo);
            } else if lo + 1 == hi {
                return (false, hi);
            }

            let mut x = if hi - lo > 3 && i % 2 == 0 {
                let mut step = (rx_hi - rx_lo) / (hi - lo) as u64;
                if step == 0 {
                    step = 1;
                }
                lo + ((rx_ts - rx_lo) / step) as u32
            } else {
                lo + (hi - lo) / 2
            };

            if x <= lo {
                x = lo + 1;
            } else if x >= hi {
                x = hi - 1;
            }

            let Some(ref ts) = self.ntp_ts_map.timestamps else {
                return (false, 0);
            };
            let rx_x = ts[self.ntp_tss_index(x)].rx_ts;

            if (rx_x.wrapping_sub(rx_ts) as i64) <= 0 {
                lo = x;
                rx_lo = rx_x;
            } else {
                hi = x;
                rx_hi = rx_x;
            }
            i = i.wrapping_add(1);
        }
    }

    /// chrony `push_ntp_tss`: grow the buffer or drop the oldest to make room.
    fn push_ntp_tss(&mut self, mut index: u32) -> u32 {
        if self.ntp_ts_map.size < self.ntp_ts_map.max_size {
            self.ntp_ts_map.size += 1;
        } else {
            self.ntp_ts_map.first = (self.ntp_ts_map.first + 1) % self.ntp_ts_map.max_size;
            index = index.saturating_sub(1);
        }
        index
    }

    /// chrony `set_ntp_tx`: store the TX timestamp as an offset from the RX
    /// timestamp, if it is within the plausible window.
    fn set_ntp_tx(
        tss: &mut NtpTimestamps,
        rx_ts: u64,
        tx_ts: Option<Timespec>,
        tx_src: TimestampSource,
    ) {
        let Some(tx_ts) = tx_ts else {
            tss.flags &= !NTPTS_VALID_TX;
            return;
        };

        let rx_as_ts = ntp64_to_timespec(rx_ts);
        let d = tx_ts.diff(rx_as_ts);

        if d.tv_sec < -2 || d.tv_sec > 1 {
            tss.flags &= !NTPTS_VALID_TX;
            return;
        }

        tss.tx_ts_offset = d.tv_nsec as i32 + d.tv_sec as i32 * NSEC_PER_SEC as i32;
        tss.flags |= NTPTS_VALID_TX;
        tss.tx_ts_source = tx_src as u8;
    }

    /// chrony `get_ntp_tx`: reconstruct the TX timespec from the stored offset.
    fn get_ntp_tx(tss: &NtpTimestamps) -> (Timespec, TimestampSource) {
        let mut offset = tss.tx_ts_offset;
        let tx = if tss.flags & NTPTS_VALID_TX != 0 {
            let mut tx_ts = ntp64_to_timespec(tss.rx_ts);
            if offset >= NSEC_PER_SEC as i32 {
                offset -= NSEC_PER_SEC as i32;
                tx_ts.tv_sec += 1;
            }
            tx_ts.tv_nsec += offset as i64;
            tx_ts.normalise();
            tx_ts
        } else {
            Timespec::default()
        };
        (tx, TimestampSource::from_index(tss.tx_ts_source))
    }

    /// chrony `CLG_SaveNtpTimestamps`.
    pub fn save_ntp_timestamps(
        &mut self,
        rx_ts: u64,
        tx_ts: Option<Timespec>,
        tx_src: TimestampSource,
    ) {
        if !self.active {
            return;
        }

        if self.ntp_ts_map.timestamps.is_none() {
            self.ntp_ts_map.timestamps =
                Some(vec![NtpTimestamps::blank(); self.ntp_ts_map.max_size as usize]);
        }

        let rx = rx_ts;
        if rx == 0 {
            return;
        }

        let (found, mut index) = self.find_ntp_rx_ts(rx);
        if found {
            let i = self.ntp_tss_index(index);
            if let Some(ref mut timestamps) = self.ntp_ts_map.timestamps {
                timestamps[i].flags |= NTPTS_DISABLED;
            }
            return;
        }

        debug_assert!(index <= self.ntp_ts_map.size);

        if index == self.ntp_ts_map.size {
            index = self.push_ntp_tss(index);
        } else {
            // Trim timestamps in the distant future after a backward step.
            while index < self.ntp_ts_map.size {
                let too_far = match self.ntp_ts_map.timestamps.as_ref() {
                    Some(t) => {
                        let last = self.ntp_tss_index(self.ntp_ts_map.size - 1);
                        t[last].rx_ts.wrapping_sub(rx) > NTPTS_FUTURE_LIMIT
                    }
                    None => false,
                };
                if !too_far { break; }
                self.ntp_ts_map.size -= 1;
            }

            if index + NTPTS_INSERT_LIMIT >= self.ntp_ts_map.size {
                index = self.push_ntp_tss(index);
                let mut i = self.ntp_ts_map.size - 1;
                while i > index {
                    let Some(ref timestamps) = self.ntp_ts_map.timestamps else { break; };
                    let src_idx = self.ntp_tss_index(i - 1);
                    let dst_idx = self.ntp_tss_index(i);
                    let src_val = timestamps[src_idx];
                    let Some(ref mut timestamps_mut) = self.ntp_ts_map.timestamps else { break; };
                    timestamps_mut[dst_idx] = src_val;
                    i -= 1;
                }
            } else {
                index = index.saturating_sub(1);
            }
        }

        self.ntp_ts_map.cached_index = index;
        self.ntp_ts_map.cached_rx_ts = rx;

        let slot = self.ntp_tss_index(index);
        let slew_epoch = self.ntp_ts_map.slew_epoch;
        let Some(ref mut timestamps) = self.ntp_ts_map.timestamps else { return; };
        let tss = &mut timestamps[slot];
        tss.rx_ts = rx;
        tss.flags = 0;
        tss.slew_epoch = slew_epoch;
        Self::set_ntp_tx(tss, rx, tx_ts, tx_src);
    }

    /// chrony `handle_slew`: invoked on every clock correction.
    pub fn handle_slew(&mut self, doffset: f64, change_type: ChangeType) {
        if change_type == ChangeType::UnknownStep {
            self.ntp_ts_map.size = 0;
            self.ntp_ts_map.cached_rx_ts = 0;
        }
        self.ntp_ts_map.slew_epoch = self.ntp_ts_map.slew_epoch.wrapping_add(1);
        self.ntp_ts_map.slew_offset = doffset;
    }

    /// chrony `CLG_UndoNtpTxTimestampSlew`: remove a just-applied slew from a TX
    /// timestamp captured before the correction. Returns the (possibly adjusted)
    /// timestamp.
    pub fn undo_ntp_tx_timestamp_slew(&mut self, rx_ts: u64, tx_ts: Timespec) -> Timespec {
        if self.ntp_ts_map.timestamps.is_none() {
            return tx_ts;
        }
        let (found, index) = self.find_ntp_rx_ts(rx_ts);
        if !found {
            return tx_ts;
        }
        let slot = self.ntp_tss_index(index);
        let Some(ref timestamps) = self.ntp_ts_map.timestamps else { return tx_ts; };
        let epoch = timestamps[slot].slew_epoch;
        if epoch.wrapping_add(1) == self.ntp_ts_map.slew_epoch {
            return tx_ts.add_double(self.ntp_ts_map.slew_offset);
        }
        tx_ts
    }

    /// chrony `CLG_UpdateNtpTxTimestamp`.
    pub fn update_ntp_tx_timestamp(
        &mut self,
        rx_ts: u64,
        tx_ts: Option<Timespec>,
        tx_src: TimestampSource,
    ) {
        if self.ntp_ts_map.timestamps.is_none() {
            return;
        }
        let (found, index) = self.find_ntp_rx_ts(rx_ts);
        if !found {
            return;
        }
        let slot = self.ntp_tss_index(index);
        let Some(ref mut timestamps) = self.ntp_ts_map.timestamps else { return; };
        let tss = &mut timestamps[slot];
        Self::set_ntp_tx(tss, rx_ts, tx_ts, tx_src);
    }

    /// chrony `CLG_GetNtpTxTimestamp`: look up the stored TX timestamp for an RX
    /// timestamp. Returns `None` if not found or disabled.
    pub fn get_ntp_tx_timestamp(&mut self, rx_ts: u64) -> Option<(Timespec, TimestampSource)> {
        self.ntp_ts_map.timestamps.as_ref()?;
        let (found, index) = self.find_ntp_rx_ts(rx_ts);
        if !found {
            return None;
        }
        let slot = self.ntp_tss_index(index);
        let Some(ref timestamps) = self.ntp_ts_map.timestamps else { return None; };
        let tss = timestamps[slot];
        if tss.flags & NTPTS_DISABLED != 0 {
            return None;
        }
        Some(Self::get_ntp_tx(&tss))
    }

    /// chrony `CLG_DisableNtpTimestamps`.
    pub fn disable_ntp_timestamps(&mut self, rx_ts: u64) {
        if self.ntp_ts_map.timestamps.is_some() {
            let (found, index) = self.find_ntp_rx_ts(rx_ts);
            if found {
                let slot = self.ntp_tss_index(index);
                if let Some(ref mut timestamps) = self.ntp_ts_map.timestamps {
                    timestamps[slot].flags |= NTPTS_DISABLED;
                }
            }
        }
        self.total_ntp_interleaved_hits += 1;
    }

    /// chrony `CLG_GetNumberOfIndices`.
    pub fn get_number_of_indices(&self) -> i32 {
        if !self.active {
            return -1;
        }
        self.records.len() as i32
    }

    /// chrony `get_interval`: convert a scaled log2 rate to an interval (log2 s).
    fn get_interval(rate: i8) -> i8 {
        if rate == INVALID_RATE {
            return 127;
        }
        let mut r = rate as i32;
        r += if r > 0 { RATE_SCALE / 2 } else { -RATE_SCALE / 2 };
        (r / -RATE_SCALE) as i8
    }

    /// chrony `get_last_ago`: seconds between `x` and `y` (`u32::MAX` if invalid).
    fn get_last_ago(x: u32, y: u32) -> u32 {
        if y == INVALID_TS || (x.wrapping_sub(y) as i32) < 0 {
            return u32::MAX;
        }
        (x.wrapping_sub(y)) >> TS_FRAC
    }

    /// chrony `CLG_GetClientAccessReportByIndex`. Returns `None` when the slot is
    /// empty / out of range / below `min_hits`.
    pub fn get_client_access_report_by_index(
        &mut self,
        index: i32,
        reset: bool,
        min_hits: u32,
        now: Timespec,
    ) -> Option<ClientAccessReport> {
        if !self.active || index < 0 || index >= self.records.len() as i32 {
            return None;
        }
        let idx = index as usize;

        if self.records[idx].ip_addr == ClientIp::Unspec {
            return None;
        }

        let r = if min_hits == 0 {
            true
        } else {
            (0..MAX_SERVICES).any(|i| self.records[idx].hits[i] >= min_hits)
        };

        let report = if r {
            let now_ts = self.get_ts_from_timespec(now);
            let rec = &self.records[idx];
            Some(ClientAccessReport {
                ip_addr: rec.ip_addr,
                ntp_hits: rec.hits[Service::Ntp.index()],
                nke_hits: rec.hits[Service::Ntske.index()],
                cmd_hits: rec.hits[Service::Cmdmon.index()],
                ntp_drops: rec.drops[Service::Ntp.index()],
                nke_drops: rec.drops[Service::Ntske.index()],
                cmd_drops: rec.drops[Service::Cmdmon.index()],
                ntp_interval: Self::get_interval(rec.rate[Service::Ntp.index()]),
                nke_interval: Self::get_interval(rec.rate[Service::Ntske.index()]),
                cmd_interval: Self::get_interval(rec.rate[Service::Cmdmon.index()]),
                ntp_timeout_interval: Self::get_interval(rec.ntp_timeout_rate),
                last_ntp_hit_ago: Self::get_last_ago(now_ts, rec.last_hit[Service::Ntp.index()]),
                last_nke_hit_ago: Self::get_last_ago(now_ts, rec.last_hit[Service::Ntske.index()]),
                last_cmd_hit_ago: Self::get_last_ago(now_ts, rec.last_hit[Service::Cmdmon.index()]),
            })
        } else {
            None
        };

        if reset {
            let rec = &mut self.records[idx];
            for i in 0..MAX_SERVICES {
                rec.hits[i] = 0;
                rec.drops[i] = 0;
            }
        }

        report
    }

    /// chrony `CLG_GetServerStatsReport`.
    pub fn get_server_stats_report(&self) -> ServerStatsReport {
            let ntp_span_seconds = if self.ntp_ts_map.size > 1 {
            let last = self.ntp_tss_index(self.ntp_ts_map.size - 1);
            let first = self.ntp_tss_index(0);
            match self.ntp_ts_map.timestamps.as_ref() {
                Some(timestamps) => (timestamps[last].rx_ts.wrapping_sub(timestamps[first].rx_ts)) >> 32,
                None => 0,
            }
        } else {
            0
        };

        ServerStatsReport {
            ntp_hits: self.total_hits[Service::Ntp.index()],
            nke_hits: self.total_hits[Service::Ntske.index()],
            cmd_hits: self.total_hits[Service::Cmdmon.index()],
            ntp_drops: self.total_drops[Service::Ntp.index()],
            nke_drops: self.total_drops[Service::Ntske.index()],
            cmd_drops: self.total_drops[Service::Cmdmon.index()],
            log_drops: self.total_record_drops,
            ntp_auth_hits: self.total_ntp_auth_hits,
            ntp_interleaved_hits: self.total_ntp_interleaved_hits,
            ntp_timestamps: self.ntp_ts_map.size as u64,
            ntp_span_seconds,
            ntp_daemon_rx_timestamps: self.total_ntp_rx_timestamps[TimestampSource::Daemon as usize],
            ntp_daemon_tx_timestamps: self.total_ntp_tx_timestamps[TimestampSource::Daemon as usize],
            ntp_kernel_rx_timestamps: self.total_ntp_rx_timestamps[TimestampSource::Kernel as usize],
            ntp_kernel_tx_timestamps: self.total_ntp_tx_timestamps[TimestampSource::Kernel as usize],
            ntp_hw_rx_timestamps: self.total_ntp_rx_timestamps[TimestampSource::Hardware as usize],
            ntp_hw_tx_timestamps: self.total_ntp_tx_timestamps[TimestampSource::Hardware as usize],
        }
    }
}

/// chrony `UTI_Ntp64ToTimespec` for the non-`HAVE_LONG_TIME_T` branch: subtract
/// `JAN_1970` from the seconds field and scale the fraction. Zero maps to zero.
fn ntp64_to_timespec(ntp: u64) -> Timespec {
    if ntp == 0 {
        return Timespec::default();
    }
    let ntp_sec = (ntp >> 32) as u32;
    let ntp_frac = ntp as u32;
    Timespec {
        tv_sec: ntp_sec.wrapping_sub(JAN_1970) as i64,
        tv_nsec: (ntp_frac as f64 / NSEC_PER_NTP64) as i64,
    }
}

/// chrony `JAN_1970`: seconds between the NTP epoch and the Unix epoch.
const JAN_1970: u32 = 0x83aa7e80;
/// chrony `NSEC_PER_NTP64`.
const NSEC_PER_NTP64: f64 = 4.294967296;

/// Tiny helper holding the address bytes for [`ClientLog::ip_to_hash`] without an
/// allocation (the hash iterates 4 or 16 bytes).
mod heapless_bytes {
    /// 4- or 16-byte address bytes.
    #[non_exhaustive]
    pub enum Bytes {
        /// IPv4 / id (4 bytes).
        Four([u8; 4]),
        /// IPv6 (16 bytes).
        Sixteen([u8; 16]),
    }
    impl Bytes {
        pub fn v4(b: [u8; 4]) -> Bytes {
            Bytes::Four(b)
        }
        pub fn v16(b: [u8; 16]) -> Bytes {
            Bytes::Sixteen(b)
        }
        pub fn as_slice(&self) -> &[u8] {
            match self {
                Bytes::Four(b) => b,
                Bytes::Sixteen(b) => b,
            }
        }
    }
}

#[cfg(test)]
mod tests;
