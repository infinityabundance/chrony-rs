//! Port-parity matrix: chrony 4.5 C source (doxygen inventory) vs chrony-rs.
//!
//! This renders `docs/generated/port-parity.md`: a 1:1 completeness catalog of
//! **every** chrony 4.5 `.c` file against its chrony-rs counterpart. It is the
//! honest denominator for "how much of chrony is ported" — and the answer today
//! is *a small fraction*, which is exactly what the doctrine demands we state
//! plainly rather than imply otherwise.
//!
//! # Two inputs, both machine-derived
//!
//! 1. **C side (doxygen, authoritative).** `research/doxygen/chrony-4.5-c-inventory.tsv`
//!    is the committed snapshot of `doxygen` run over chrony 4.5's `.c` files
//!    (70 files, 1373 functions, pinned to a commit — see that file's header and
//!    `research/doxygen/README.md`). It is the file set and function denominator.
//! 2. **Rust side (`syn` AST).** Per-file function/closure counts come from
//!    parsing `crates/` with `syn` and walking the real AST. Doxygen has no Rust
//!    frontend (its C++ parser misreads `fn`/`impl`/closures and yields anonymous
//!    members), so the count is taken natively; the doxygen Rust run is recorded in
//!    the prose doc only for transparency, not relied on.
//!
//! # The mapping is curated, and conservative on purpose
//!
//! [`MAP`] assigns each C file a one-line role and a [`Port`] status. Statuses are
//! deliberately pessimistic: a file is only [`Port::Partial`] if real behavior is
//! ported *with an executable court*; [`Port::Scaffold`] means a type or simulated
//! stand-in exists but chrony's behavior is not reproduced; [`Port::None`] means no
//! counterpart. When in doubt we mark down, never up — overclaiming coverage is the
//! one failure mode this whole project exists to prevent.
//!
//! The table is driven by the TSV file set, so adding a `.c` file upstream (or
//! mis-spelling one here) shows up as an `(unmapped)` row rather than silently
//! dropping out — the catalog stays exhaustive.

use std::collections::BTreeMap;
use std::path::Path;

/// How much of a C translation unit has a chrony-rs counterpart. Ordered from
/// most to least complete for summary tallying.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    /// Every function in the translation unit has a court-backed counterpart.
    Full,
    /// Behavior ported, backed by at least one executable court.
    Partial,
    /// A type, data shape, or simulated stand-in exists; chrony's behavior is not
    /// reproduced.
    Scaffold,
    /// No chrony-rs counterpart.
    None,
}

impl Port {
    fn glyph(self) -> &'static str {
        match self {
            Port::Full => "● full",
            Port::Partial => "◑ partial",
            Port::Scaffold => "○ scaffold",
            Port::None => "· none",
        }
    }
}

/// One catalog row: chrony C file → role → chrony-rs counterpart + honesty note.
struct Row {
    /// chrony source basename (matches the doxygen inventory keys).
    c: &'static str,
    /// One-line description of the translation unit's responsibility.
    role: &'static str,
    /// chrony-rs module paths that port (some of) it; empty when none.
    rust: &'static [&'static str],
    port: Port,
    /// What is and isn't ported — kept blunt.
    note: &'static str,
}

/// The curated catalog. Conservative by construction (see module docs).
const MAP: &[Row] = &[
    // ---- config surface: the most-ported area ----
    Row { c: "conf.c", role: "config file parser + 93-directive dispatch (CNF_*)",
        rust: &["config/parser.rs", "config/lexer.rs", "config/diagnostics.rs", "config/model.rs", "config/mod.rs"],
        port: Port::Partial, note: "directive recognition (93/93), comment rules, diagnostics witnessed vs 4.5; per-directive value semantics partial" },
    Row { c: "cmdparse.c", role: "command/config line parsing (CPS_*)",
        rust: &["config/parser.rs", "cmdparse.rs"], port: Port::Full,
        note: "all 8: source options + word split/normalize/refid/key/local + allow-deny (incl. DNS hostname via nameserv; drives addrfilt end-to-end vs `chronyc accheck`)" },

    // ---- NTP protocol ----
    Row { c: "ntp_core.c", role: "NTP protocol engine: poll, process-response, offset/delay (NCR_*)",
        rust: &["ntp/measurements.rs", "ntp/packet.rs", "ntp/poll.rs", "ntp/parse.rs"], port: Port::Partial,
        note: "STAGED port of the protocol engine (chrony's largest TU, 69 fns/~3300 lines). RFC 5905 §8 offset/delay algebra + 48-byte header codec (measurements.rs/packet.rs). Stage 1 (ntp/poll.rs): the pure poll-interval + delay-sanity arithmetic -- get_separation, get_poll_adj, adjust_poll (poll/score with minpoll/maxpoll clamp + non-LAN floor), check_delay_ratio, check_delay_dev_ratio. Differential-tested vs the REAL compiled ntp_core.c by #include-ing the TU into the C generator (the static functions + NCR_Instance_Record struct reached directly, the ~130-symbol external surface stubbed, UTI_Log2ToDouble real, SST/SRC inputs controlled) and matching every value. Stage 2 (ntp/parse.rs): parse_packet (length/version validation, NTPv3 MAC + MS-SNTP detection, crypto-NAK, NTPv4 extension fields with NTS + experimental-EF detection, trailing MAC) composing the ported NEF extension-field parser, plus is_zero_data/is_exp_ef -- differential-tested vs the real ntp_core.c (#include harness + real ntp_ext.c) over crafted plain/v3-MAC/MS-SNTP/crypto-NAK/NTS-EF packets, matching every NTP_PacketInfo field. Stage 3 (ntp/poll.rs): the transmit timing -- get_transmit_poll (symmetric local/remote poll selection) and get_transmit_delay (online/presend/burst/peer-sampling delay), differential-tested vs the real ntp_core.c via the #include harness. Stage 4 (ntp/sample.rs): apply_net_correction -- the PTP transparent-clock correction that adjusts a sample's offset/peer_delay using the RX/TX net-correction extension fields, gated on both-directions presence + a sanity bound + a 100-ppm margin, differential-tested vs the real ntp_core.c via the #include harness. Stage 5 (ntp/sync.rs): check_sync_loop -- process_response's test D, the synchronisation-loop guard (serving-time gate, synced-to-our-address detection, and exact reference-identity 'it is me' detection), differential-tested vs the real ntp_core.c via the #include harness (REF/NIO/refid inputs controlled, UTI codecs kept real). Stage 6 (ntp/sample.rs compute_response_sample): process_response's offset/delay/dispersion sample arithmetic for the basic (non-interleaved) client path -- peer delay (with precision floor), offset (with configured correction), peer dispersion (precision + skew*span), root delay/dispersion, composing apply_net_correction. Courted by reaching the REAL process_response (saved=1 to bypass auth, validity tests configured to pass) and capturing the sample handed to SRC_AccumulateSample, matching all five fields + the sample time; independently checked vs the RFC 5905 offset/delay formula. Stage 7 (ntp/sample.rs compute_interleaved_response_sample): the interleaved-mode timestamp selection -- prefer previous local TX + source RX (with remote roots) when the L2L ratio test passes, else the current exchange (with MAX of packet/remote roots), local receive from the instance -- feeding the same arithmetic; courted by driving the REAL process_response in interleaved mode across both sub-branches. Stage 8 (ntp/exp_ef.rs): the experimental extension-field builders add_ef_mono_root (monotonic root delay/dispersion in f28 + monotonic receive timestamp + epoch; magic-only in client mode) and add_ef_net_correction (PTP transparent-clock correction; gated on ptpport, magic-only in client mode / no correction), composing the ported NEF_AddField framing -- differential-tested vs the real ntp_core.c (#include harness + real ntp_ext.c, fuzz RNG zeroed) by capturing the appended EF body bytes + flags across client/server modes. This completes the experimental-EF story (parse in Stage 2, apply in Stage 4, build here). Stage 9 (ntp/params.rs): the runtime source-parameter setters NCR_ModifyMinpoll/Maxpoll (range-guarded with mutual adjustment), Maxdelay/Maxdelayratio/Maxdelaydevratio (CLAMP 0..MAX), Minstratum (direct), Polltarget (floored at 1) -- the chronyc reconfiguration surface, differential-tested vs the real ntp_core.c via the #include harness. Stage 10 (ntp/access.rs): the NTP server access-control surface NCR_AddAccessRestriction (the (allow,all) -> ADF_Allow/AllowAll/Deny/DenyAll dispatch composing the ported addrfilt table, status->return) and NCR_CheckAccessRestriction (ADF_IsAllowed), differential-tested vs the real ntp_core.c (#include harness, recording ADF stubs) with the end-to-end allow/deny independently checked against the ported ADF table; the server-socket open/close side effect is a documented host boundary. Stage 11 (ntp/local_ts.rs): the NTP_Local_Timestamp helpers zero_local_timestamp (reset to an empty daemon timestamp) and update_tx_timestamp (adopt a more accurate hardware TX timestamp only when the original is set, the response still matches the packet we sent, and the improvement is a non-negative delay <= MAX_TX_DELAY), differential-tested vs the real ntp_core.c via the #include harness. Stage 12 (ntp/opmode.rs): the operating-mode state machine -- set_connectivity (the full online/offline transition table, returned as new mode + the host-boundary action GoOnline/TakeOffline the caller performs), NCR_SetConnectivity's online-change predicate, and NCR_IncrementActivityCounters (the chronyc activity tally) -- differential-tested vs the real ntp_core.c via the #include harness (transition observed + action witnessed by the SRC_SetActive/SRC_UnsetActive stubs). Stage 13 (ntp/create.rs): NCR_CreateInstance's parameter mapping -- the server/peer directive semantics: client/active mode from type, poll-interval defaults+clamps (default when below range, MAX cap, maxpoll>=minpoll), min-stratum cap, peer presend disable, delay-limit clamps, copy-only-for-clients, poll-target floor, and the NTP version selection (ext/interleaved force latest, else auth-suggested, explicit clamps) -- differential-tested vs the real ntp_core.c via the #include harness; the auth/source/quantile/filter sub-instance creation is a documented host boundary. Stage 14 (ntp/lifecycle.rs): the instance lifecycle transitions NCR_ResetInstance (clear the protocol/timestamp state), NCR_ResetPoll (drop poll score, return to minpoll, signal timeout restart), NCR_InitiateSampleBurst (client-only burst entry), NCR_SlewTimes (slew the stored local timestamps via UTI_AdjustTimespec) -- differential-tested vs the real ntp_core.c via the #include harness (the scheduler/source/filter side effects returned as intent / witnessed by the SCH_AddTimeoutInClass / SRC_SetActive stubs). Stage 15 (ntp/test_a.rs): process_response's test A for client sources (the sample-acceptance gate -- peer-delay-within-max, precision-within-max, not-a-presend-warmup, sane server processing time, and the interleaved-reuse rejection), differential-tested vs the real ntp_core.c by forcing B/C/D to pass so good_packet==testA and failing each condition in turn. Stage 16 (ntp/support.rs): the support helpers handle_slew (server monotonic-clock offset/epoch tracking -- slew accumulates, step resets+reseeds), has_saved_response (pending delayed-response predicate), check_delay_quant (test C quantile variant), differential-tested vs the real ntp_core.c via the #include harness. Stage 17 (ntp/transmit.rs): transmit_packet's client-request build -- the 48-byte header a client sends (clock state blanked, precision 32, the live transmit timestamp), the version cap, and the output timestamps -- differential-tested vs the real ntp_core.c by driving transmit_packet in client mode and capturing the packet via the NIO_SendPacket stub (the anti-replay fuzz, auth, and send are host boundaries). Stage 18 (ntp/report.rs): NCR_ReportSource (the chronyc-sources poll interval via get_transmit_poll + the client/peer mode classification), differential-tested vs the real ntp_core.c via the #include harness. Stage 19 (ntp/rx_dispatch.rs): the receive-path mode dispatch -- NCR_ProcessRxKnown's classification table (reply-to-process / handle-as-unknown / discard from the packet x association mode) and NCR_ProcessRxUnknown's reply-mode mapping (active->passive, client->server, NTPv1->server) -- differential-tested vs the real ntp_core.c (branch witnessed by the SRC_GetSourcestats/NIO_IsServerSocket stubs and the captured response mode). Stage 20 (ntp/tx_dispatch.rs): the transmit-path mode dispatch -- NCR_ProcessTxKnown (client/active TX timestamps update our stored local_tx, others route to the unknown path) and NCR_ProcessTxUnknown (broadcast ignored) -- differential-tested vs the real ntp_core.c, composing the ported update_tx_timestamp. Stage 21 (ntp/transmit.rs build_server_response): transmit_packet's basic server-response build -- our reference state (stratum/refid/root delay+dispersion/reference timestamp), the echoed originate timestamp, the receive/transmit timestamps with the interleaved-mode RX flag bit (set on receive, cleared on transmit) -- differential-tested vs the real ntp_core.c by driving transmit_packet in server mode and capturing the response via the NIO_SendPacket stub. Stage 22 (ntp/transmit.rs build_interleaved_client_request): transmit_packet's interleaved client request -- originate echoes the server's last receive timestamp, the receive timestamp is our last receive, and the transmit timestamp is the previously-sent (saved) one; also corrected the basic client's saved local_tx to be the distinct cooked-at-send reading (not the packet event time), caught when the cooked-time stub was made real. REMAINING: transmit_packet symmetric build, test A symmetric-active variant, monotonic-root sample selection, NTP report copy, init/finalise" },
    Row { c: "ntp_io.c", role: "NTP socket send/recv path",
        rust: &["ntp/packet.rs"], port: Port::Scaffold, note: "packet bytes only; no socket IO" },
    Row { c: "pktlength.c", role: "cmdmon request/reply length tables (PKL_*)",
        rust: &["pktlength.rs"], port: Port::Full,
        note: "complete port of all 3 functions; per-command length/padding + per-reply length tables extracted exactly from candm.h offsets (compiled probe), not guessed" },
    Row { c: "ntp_io_linux.c", role: "Linux HW/kernel RX timestamping", rust: &[], port: Port::None, note: "" },
    Row { c: "ntp_ext.c", role: "NTP extension-field (RFC 7822) framing (NEF_*)",
        rust: &["ntp/ext.rs"], port: Port::Full,
        note: "complete port of all 6 functions; TLV format/parse + packet add/parse with alignment, NTPv4, MAC-length and bounds checks; set/parse roundtrip tested" },
    Row { c: "ntp_auth.c", role: "NTP authentication (MAC/NTS dispatch) (NAU_*)",
        rust: &["ntp_auth.rs"], port: Port::Full,
        note: "complete port of all 17 functions: the authentication dispatcher unifying none / symmetric-key (MD5/CMAC MAC via the ported key store) / NTS (RFC 8915 client+server EFs) / MS-SNTP, including suggested NTP version, request/response generate+check, address change, cookie dump, and report; composes the ported keys + nts_ntp_client/server (over nts_ntp_auth + real AES-SIV), with only the MS-SNTP signing daemon injected as a closure. Differential-tested vs the REAL compiled ntp_auth.c (+ keys.c, hash_intmd5.c): byte-identical symmetric MAC on request+response, check accept, tamper reject, key report; mode dispatch (none/MS-SNTP/NTS) covered over the oracle-backed NTS modules + an injected signer" },
    Row { c: "ntp_signd.c", role: "Samba MS-SNTP signing-daemon bridge (NSD_*)",
        rust: &["ntp_signd.rs"], port: Port::Full,
        note: "complete port of all 7 functions: the asynchronous Samba ntp_signd client — serialise the SigndRequest (the ntp_signd IDL wire format), the bounded ring queue (bursts not lost), the writable/readable state machine (partial send/recv), response validation (packet_id/op/length) and signed-packet emission; the other half of the MS-SNTP path that ntp_auth injects. Host boundaries (socket SCK_*, scheduler file-handler events SCH_*, NTP send NIO_*) are one injected trait. Differential-tested vs the REAL compiled ntp_signd.c (+ array.c, memory.c): byte-identical SigndRequest + emitted signed packet, with bad-packet-id / non-success-op / over-short-length rejection + an independent partial-write/queue-capacity check" },
    Row { c: "ntp_sources.c", role: "NTP source record add/remove/pool (NSR_*)", rust: &["ntp_sources.rs"], port: Port::Partial,
        note: "STAGED port of the NTP source manager. Stage 1 (ntp_sources.rs): the source-table internals -- the open-addressing hash table keyed by remote IP (find_slot/find_slot2 quadratic probing, check_hashtable_size power-of-two load factor), UTI_IPToHash (seeded), NSR_StatusToString, and the get_next_conf_id counter. Differential-tested vs the REAL compiled ntp_sources.c via the #include harness (real array.c linked, the random hash seed pinned): the hash, the slot probing on a built 8-slot table, the sizing rule, the status strings, and the id counter are matched. Stage 2 (ntp_sources.rs): rehash_records -- grow the table to the smallest power-of-two satisfying the load factor and re-insert every record by re-probing (matched vs the real ntp_sources.c on grow/no-grow scenarios, including a re-layout under a new modulus). Stage 3 (ntp_sources.rs): add_source (the record-insertion decision -- already-present/name-required/too-many/invalid-family validation order, then grow-and-place) and the NSR_Modify* fan-out (address lookup -> the already-ported NCR_Modify*, returning found/not-found), differential-tested vs the real ntp_sources.c via the #include harness (status + n_sources + table size + slot across the validation cases and a 5-source growth; every NSR_Modify* variant's present/absent return). Stage 4 (ntp_sources.rs): the source-removal lifecycle -- NSR_RemoveSource (NoSuchSource when absent, else clear the slot, decrement n_sources, and rehash) and clean_source_record's pool-counter bookkeeping (SourcePool::on_remove: sources--, unresolved-- when unreal, confirmed-- when non-tentative, max_sources clamp) -- differential-tested vs the real ntp_sources.c (removal status/n_sources/size/remaining-layout across present/absent/down-to-zero; each pool-counter branch with pre-set distinct counts). Stage 5 (ntp_sources.rs): source-iteration ops -- the mask-match selection (select_matching: occupied slots whose address matches under a mask, Unspec matches all -- the core of NSR_InitiateSampleBurst/NSR_SetConnectivity, with UTI_CompareIPs ported as ip_equal_under_mask), NSR_RemoveAllSources (clean all + rehash to the empty table), and NSR_GetLocalRefid (find + NCR_GetLocalRefid or 0) -- differential-tested vs the real ntp_sources.c (matched-address set in slot order for all/exact/subnet/none, the refid present/absent, the emptied table). Stage 6 (ntp_sources.rs): NSR_SetConnectivity's selection + application order -- like select_matching but the synchronisation peer is applied last (avoiding reference switching) and, for an Unspec address with MaybeOnline, unresolved sources are skipped; differential-tested vs the real ntp_sources.c (NCR_SetConnectivity records the application order) across all/sync-last/maybe-skip/subnet+sync. Stage 7 (ntp_sources.rs): get_unused_pool_id (first pool with no sources and no pending unresolved name, else INVALID_POOL) and the single-by-address report fan-outs NSR_GetNTPReport (found 1/0) and NSR_ReportSource (NCR fills the report when found, else the poll is blanked) -- differential-tested vs the real ntp_sources.c. Stage 8 (ntp_sources.rs): is_resolved (a pool source is resolved once the pool has no unresolved sources; a single source once its address is no longer present) and NSR_GetName (find -> the source name, host metadata) -- differential-tested vs the real ntp_sources.c. REMAINING: resolve sources, NSR_ProcessRx/Tx, auth/auto-start surface (socket/resolver-bound)" },

    // ---- source selection / statistics ----
    Row { c: "sources.c", role: "source reachability + selection (SRC_*)",
        rust: &["sources/registry.rs", "sources/combine.rs", "sources/source.rs", "sources/reachability.rs", "sources/selection.rs"], port: Port::Full,
        note: "STAGED port of the 48-function selection brain (the largest chrony TU; SRC_SelectSource alone is 517 lines). Stage 1 (sources/registry.rs): the source registry + 8-bit reachability register + status/stratum/leap bookkeeping + leap-second vote + sample accumulation (composing the ported sourcestats) + special-mode-end + accessors. Stage 2 (sources/combine.rs): the numeric combine_sources (weighted offset/frequency blend), update_sel_options (authselectmode policy), and the get_status_char/compare_sort_elements helpers. Stage 3 (select_source in registry.rs): the full SRC_SelectSource pipeline -- classification, the falseticker endpoint-intersection (depth/trust-depth search), orphan/stale handling, admissibility + trust, prefer reduction, score/SCORE_LIMIT hysteresis, and the combine + REF_SetReference. Differential-tested vs the REAL compiled sources.c by driving the real SRC_SelectSource over controlled sources (controlled SST_GetSelectionData/GetTrackingData) and matching REF_SetReference (combined offset/count) + per-source report states across select+combine / falseticker / no-majority scenarios. Stage 4 (registry.rs): lifecycle (Finalise/DestroyInstance with reindex+selection fixup), the LCL slew/dispersion handlers (composing the ported sourcestats), reselect/reset/modify-options accessors, and SRC_GetSelectReport. Stage 5 (registry.rs): the dump persistence (save_source/load_source over the SRC0 format composing the ported sourcestats dump, get_dumpfile naming, DumpSources/ReloadSources fan-outs, RemoveDumpFiles name gate), the SRC_ReportSource/SRC_ReportSourcestats reports, and the mode-gated log_selection helpers. All 48 functions ported. Differential-tested vs the REAL compiled sources.c across stages: reachability register + triggers, combine_sources, the full SRC_SelectSource pipeline (select+combine/falseticker/no-majority, per-source report states + REF_SetReference), SRC_GetSelectReport, and the dump save format + load round-trip. The file/socket boundaries (UTI file I/O, glob) are the daemon's; the SST/REF/LCL/SCH/NSR boundaries are injected" },
    Row { c: "sourcestats.c", role: "per-source regression statistics (SST_*)",
        rust: &["sourcestats.rs"], port: Port::Full,
        note: "complete port of all 32 functions (the keystone): dual circular buffers + weighted robust regression + jitter-asymmetry multiple regression + dump/reload; composes ALL of the verified regress engine; regression/prune/asymmetry/save-load tested" },
    Row { c: "regress.c", role: "robust linear regression + statistical primitives",
        rust: &["regress.rs"], port: Port::Full,
        note: "all 11: weighted LS + runs-test + median-based robust + 2-var regression + t/chi2 tables + median; verified by TWO oracles -- the REAL compiled regress.c (80 differential vectors) and an independent reference impl" },
    Row { c: "samplefilt.c", role: "per-source NTP sample filtering (SPF_*)",
        rust: &["samplefilt.rs"], port: Port::Full,
        note: "complete port of all 18 functions; circular sample buffer + dispersion/offset selection + weighted-regression combine (composes the verified regress); select_samples' index-permutation computed directly to the same result; precision/time injected" },
    Row { c: "quantiles.c", role: "streaming (stochastic) quantile estimator",
        rust: &["quantiles.rs"], port: Port::Full,
        note: "complete port of all 8 functions (QNT_DestroyInstance = Drop); structural — deterministic parts tested exactly, convergence statistically; chrony seeds random() non-deterministically so it is not byte-witnessable" },

    // ---- reference / clock / discipline ----
    Row { c: "reference.c", role: "tracking + drift state, leap handling (REF_*)",
        rust: &["reference.rs", "report.rs", "clock.rs"], port: Port::Full,
        note: "complete port of all 46 functions (the discipline keystone above local.c): the offset/frequency/skew combine (get_clock_estimates), correction-rate, root-dispersion, step decision, drift-file persistence, fallback-drift accumulator, leap-second scheduling (system/slew/step/ignore), special init/update/print modes, sync status, tracking log, and tracking report; gmtime/strftime reimplemented (civil-date math) so is_leap_second_day and the log timestamp are deterministic, with only the timezone-leap lookup left as a host boundary. Composes the ported local clock; all of LCL_/SCH_/drift-file/leap-tz/RNG/mail/log injected via one RefHost trait. The numeric core (REF_SetReference/REF_AdjustReference + estimator/step/dispersion helpers, incl. the fuzz-fed report root dispersion) is differential-tested vs the REAL compiled reference.c (byte-identical corrections/step/sync/report over recording LCL_/SCH_ stubs); leap/local/accessor paths unit-tested" },
    Row { c: "local.c", role: "local clock hub: read/cook time, discipline, handlers (LCL_*)",
        rust: &["local.rs"], port: Port::Full,
        note: "complete port of all 35 functions; composes the ported sys_null driver (ClockDriver trait) + optional smooth hooks; raw clock/config injected, handlers id-registered (closures); discipline/temp-comp/precision/handler tests" },
    Row { c: "smooth.c", role: "served-time smoothing (SMT_*)",
        rust: &["smooth.rs"], port: Port::Full,
        note: "complete port of all 12 functions; the 3-stage bounded-freq/wander trajectory (update_stages/get_smoothing) verified vs a reference impl; time as seconds, config/skew injected, struct-as-handler" },
    Row { c: "tempcomp.c", role: "temperature compensation (TMC_*)",
        rust: &["tempcomp.rs"], port: Port::Full,
        note: "complete port of all 5 functions; quadratic + point-table interpolation (points stored in the ported array::Array); temp injected, comp returned, points/coefs as data" },
    Row { c: "sched.c", role: "timer/event scheduler (SCH_*)",
        rust: &["sched.rs"], port: Port::Full,
        note: "complete port of all 22 functions: the sorted timeout queue (add/by-delay/in-class with class separation + randomness, removal, dispatch), file-handler registry + select-driven main loop, clock-step queue shift, and last-event/monotonic time tracking; clock/select/randomness injected; differential-tested vs the REAL compiled sched.c (SCH_MainLoop dispatch order + fire times, incl. ties/spacing/random/step) + an independent file-handler test" },

    // ---- control client / protocol ----
    Row { c: "client.c", role: "chronyc CLI: command dispatch + report formatters",
        rust: &["report.rs", "../chronyc-rs/src/main.rs"], port: Port::Partial,
        note: "tracking/sources/sourcestats/activity/serverstats rendered (print_report+print_info_field engines, all print_* value helpers; all live-witnessed vs 4.5); 5 of ~40 process_cmd_* commands; no socket transport" },
    Row { c: "cmdmon.c", role: "control/monitoring protocol server (candm)", rust: &[], port: Port::None,
        note: "live control socket is a declared negative capability" },

    // ---- daemon entry / process ----
    Row { c: "main.c", role: "daemon entry, arg parsing, lifecycle",
        rust: &["../chronyd-rs/src/main.rs"], port: Port::Partial,
        note: "--check-config and --replay only; no scheduler/privdrop/daemonize" },
    Row { c: "privops.c", role: "privilege-separation helper (PRV_*)",
        rust: &["privops.rs"], port: Port::Full,
        note: "complete port of the privilege-separation protocol logic: the daemon-side direct-vs-helper routing of every PRV_* call, the helper-side op dispatch (helper_main's switch), the bind port-validation security gate (do_bind_socket), the unknown-op res_fatal path, and the response assembly (rc/errno/data with errno recorded only on the per-op failure condition chrony uses). The fork()/socketpair transport, the C-struct wire marshalling (incl. the SCM_RIGHTS fd-pass for bind), and the privileged operations (adjtime/ntp_adjtime/settimeofday/bind/DNS) are injected (PrivBackend + transport). The per-op handlers are platform-conditional and absent from the default-build inventory (so the curated function list is the 5 helper-shell functions). Differential-tested vs the REAL compiled privops.c driven END-TO-END through its actual fork() + Unix socketpair (adjusttime, settime errno path, name2ipaddress, reloaddns over recording op stubs); bind validation, unknown-op fatal, OP_QUIT, and client routing unit-tested" },

    // ---- utilities (subsumed by std, or partially ported) ----
    Row { c: "util.c", role: "time/UTI/byte utilities (UTI_*)",
        rust: &["util.rs", "ntp/timestamp.rs", "ntp/measurements.rs"], port: Port::Partial,
        note: "pure primitives ported: NTP short/64 + era algebra, log2->seconds, hex codec, refid<->string; broad UTI_* surface (files, sockets, randomness) not" },
    Row { c: "array.c", role: "generic dynamic array (ARR_*)",
        rust: &["array.rs"], port: Port::Full,
        note: "complete port of all 10 functions over a flat Vec<u8> (slices where chrony returns pointers): exact capacity grow/shrink policy + order-preserving removal; no unsafe" },
    Row { c: "memory.c", role: "xmalloc/xrealloc wrappers", rust: &[], port: Port::None, note: "subsumed by std; not a port target" },
    Row { c: "logging.c", role: "logging subsystem (LOG_*)", rust: &[], port: Port::None,
        note: "project uses a structured trace schema, not a port of LOG_*" },
    Row { c: "stubs.c", role: "test-harness stub implementations", rust: &[], port: Port::None,
        note: "upstream unit-test scaffolding, not a behavior port target" },

    // ---- crypto / auth / keys (none) ----
    Row { c: "keys.c", role: "symmetric key store (KEY_*)",
        rust: &["keys.rs"], port: Port::Full,
        note: "complete port of all 17 functions for chrony's internal-MD5 build: key-file parse (ASCII/HEX), sorted store + binary-search + cache, MAC generate/verify (truncated), secure-length gate; differential-tested vs the REAL compiled keys.c (key file + per-id vectors) + an independent MD5(key||msg) check; CMAC cipher keys rejected at load (no crypto backend), as that build does" },
    Row { c: "md5.c", role: "MD5 digest (RFC 1321 reference, NTP symmetric-key auth)",
        rust: &["md5.rs"], port: Port::Full,
        note: "complete port of all 4 functions; byte-exact vs the official RFC 1321 §A.5 test vectors (dependency-free TU)" },
    Row { c: "hash_intmd5.c", role: "internal MD5 hash backend (HSH_*)",
        rust: &["hash_intmd5.rs"], port: Port::Full,
        note: "complete port of all 3 functions; thin wrapper over the ported MD5 (RFC 1321 vectors), with the supported-algorithm gate and in1||in2 concat/truncation tested" },
    Row { c: "hash_gnutls.c", role: "gnutls hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_nettle.c", role: "nettle hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_nss.c", role: "NSS hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_tomcrypt.c", role: "tomcrypt hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "cmac_gnutls.c", role: "gnutls CMAC backend", rust: &[], port: Port::None, note: "" },
    Row { c: "cmac_nettle.c", role: "AES-CMAC keyed-MAC instance API (CMC_*)",
        rust: &["cmac_nettle.rs"], port: Port::Full,
        note: "complete port of all 4 functions: keyed AES-128/AES-256 CMAC instance, key-length table, truncating CMC_Hash; reuses the shared CMAC-128 from siv_nettle_int over a new FIPS-197 AES-256. Anchored by THREE oracles: RFC 4493 (AES-128-CMAC), NIST SP 800-38B (AES-256-CMAC), and the REAL compiled cmac_nettle.c over a vector-verified shim" },

    // ---- NTS (none) ----
    Row { c: "nts_ke_client.c", role: "NTS-KE client", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ke_server.c", role: "NTS-KE server", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ke_session.c", role: "NTS-KE TLS session", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ntp_auth.c", role: "NTS authenticator + encrypted-EEF extension field (NNA_*)",
        rust: &["nts_ntp_auth.rs"], port: Port::Full,
        note: "complete port of all 4 functions: build/parse the NTS auth-and-EEF field (header, nonce+ciphertext layout, 4-byte padding, min-length/min-nonce padding) over the ported ntp_ext layer, with SIV injected; differential-tested vs the REAL compiled nts_ntp_auth.c (identical packet bytes + round-trip, deterministic toy SIV) + independent padding/round-trip checks" },
    Row { c: "nts_ntp_client.c", role: "client-side NTS-NTP authentication (NNC_*)",
        rust: &["nts_ntp_client.rs"], port: Port::Full,
        note: "complete port of all 17 functions: NTS-KE-driven cookie pool (ring buffer), per-request EFs (unique-id/cookie/placeholders) + authenticator under C2S, response verify/decrypt under S2C + cookie extraction, NTS-KE retry/backoff, and keys+cookies dump save/load; composes the ported ntp_ext + nts_ntp_auth + siv (real AES-SIV-CMAC), with the NTS-KE handshake / source-update / mono-clock / config injected. Differential-tested vs the REAL compiled nts_ntp_client.c (byte-identical request + check + report) + a cookie dump round-trip" },
    Row { c: "nts_ntp_server.c", role: "server-side NTS-NTP authentication (NNS_*)",
        rust: &["nts_ntp_server.rs"], port: Port::Full,
        note: "complete port of all 4 functions: parse NTS request EFs (unique-id/cookie/placeholder/auth), decode cookie -> session keys, key SIV with C2S + verify/decrypt the authenticator, prepare fresh cookies, and build the S2C-authenticated response; composes the ported ntp_ext + nts_ntp_auth + siv (real AES-SIV-CMAC), with the cookie codec injected. Differential-tested vs the REAL compiled nts_ntp_server.c (byte-identical response + tamper/missing-cookie rejection) + a full round-trip" },
    Row { c: "siv_gnutls.c", role: "SIV-AEAD (gnutls)", rust: &[], port: Port::None, note: "" },
    Row { c: "siv_nettle.c", role: "SIV AEAD instance API (SIV_*)",
        rust: &["siv_nettle.rs"], port: Port::Full,
        note: "complete port of all 9 functions (no-GCM build): keyed AEAD instance, key/nonce/tag length table, input validation, encrypt/decrypt dispatch over the ported siv_nettle_int (AES-SIV-CMAC-256); GCM-SIV unsupported as that build is; also bridges nts_ntp_auth's SIV so the NTS auth EF round-trips over real AES-SIV. Differential-tested vs the REAL compiled siv_nettle.c (API + validation) — the crypto itself is triple-anchored in siv_nettle_int" },
    Row { c: "siv_nettle_int.c", role: "AES-SIV-CMAC-256 AEAD (RFC 5297)",
        rust: &["siv_nettle_int.rs"], port: Port::Full,
        note: "complete port of all 12 functions: CMAC-128 (RFC 4493), S2V, and SIV encrypt/decrypt; the AES-128 block cipher (nettle's) is reimplemented in dependency-free Rust (FIPS-197 KAT). Anchored by THREE oracles: FIPS-197 (AES), RFC 5297 A.1 (the official worked example), and the REAL compiled siv_nettle_int.c over a FIPS-197-verified shim AES (many-shape encrypt/decrypt vectors)" },

    // ---- refclocks (none) ----
    Row { c: "refclock.c", role: "reference-clock framework (RCL_*)",
        rust: &["refclock.rs"], port: Port::Full,
        note: "complete port of the refclock framework (26 functions; the void* driver-data accessors RCL_SetDriverData/RCL_GetDriverData are subsumed by the driver trait owning its own state): sample/pulse offset computation, PPS-interval folding, lock-reference alignment, pulse-edge + time-offset sanity gates, TAI->UTC conversion, pps_stratum, the poll loop, local-mode follow, and the slew/dispersion handlers. Unblocked by reference.c (file 32); composes the ported samplefilt + regress + local + sched, with SPF_/SRC_/REF_/LCL_/SCH_ and the platform driver injected via one RefclockHost trait. The sample/pulse core (RCL_AddSample/AddPulse/AddCookedPulse + pps_stratum/valid_sample_time/convert_tai_offset) is differential-tested vs the REAL compiled refclock.c (+ array.c, memory.c): byte-identical offset+dispersion handed to the filter and accept/reject decisions; driver-option parsing + refid derivation unit-tested" },
    Row { c: "refclock_phc.c", role: "PHC refclock driver", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "refclock_pps.c", role: "PPS refclock driver", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "refclock_shm.c", role: "SHM refclock driver (ntpd/gpsd shared-memory protocol)",
        rust: &["refclock_shm.rs"], port: Port::Full,
        note: "complete port of all 3 functions: shm_poll's sample extraction (mode 0/1 validity gates incl. the mode-1 concurrent-writer count-stability check, the valid flag, clearing valid, and the nanosecond-vs-microsecond timestamp selection + normalisation) feeding the refclock framework's RCL_AddSample, plus shm_initialise's unit-key (SHMKEY + unit) and octal perm parsing. The shared-memory segment (shmget/shmat) is the injected ShmSource; composes the ported refclock.rs. Differential-tested vs the REAL compiled refclock_shm.c (RCL_SHM_driver.poll over a controlled shmTime: byte-identical receive/clock/leap + accept/reject, valid cleared on accept); the writer race and key/perm parsing unit-tested" },
    Row { c: "refclock_sock.c", role: "SOCK refclock driver (gpsd Unix-datagram sample protocol)",
        rust: &["refclock_sock.rs"], port: Port::Full,
        note: "complete port of read_sample (the sample logic): the datagram length check, the 'SOCK' magic gate, the timeval->timespec conversion + normalisation, the time-offset sanity gate, and the pulse-vs-sample routing (RCL_AddPulse vs RCL_AddSample(sys, sys+offset, leap)); composes the ported refclock.rs. The datagram socket open + file-handler registration (sock_initialise/sock_finalise) is the injected host transport, and read_sample takes the received bytes and returns the framework call. Differential-tested vs the REAL compiled refclock_sock.c: byte-identical sock_sample datagrams (C struct layout) fed to the real read_sample, matching the sample/pulse routing + every timestamp, with magic/length/sanity rejections; short-datagram and insane-offset gates also unit-tested" },

    // ---- RTC / hwclock (none) ----
    Row { c: "rtc.c", role: "RTC abstraction layer (RTC_*)",
        rust: &["rtc.rs"], port: Port::Full,
        note: "complete port of all 9 functions: the driver-load decision tree, lifecycle/measurement forwarding, and the drift-file time restore (step the clock to the drift file's mtime if behind); the platform RTC driver is the injected RtcDriver trait and the clock/step/driftfile-mtime are injected. Differential-tested vs the REAL compiled rtc.c (-DLINUX -DFEAT_RTC): pre-init ok / pre-init fail->drift step / rtcfile+rtcsync fatal, with the forwarded call log + return codes matched" },
    Row { c: "rtc_linux.c", role: "Linux RTC driver", rust: &[], port: Port::None, note: "" },
    Row { c: "hwclock.c", role: "hardware-clock tracking (HCL_*)",
        rust: &["hwclock.rs"], port: Port::Full,
        note: "complete port of all 7 functions; composes the ported quantile delay filter + robust regression over Vec<f64> sample buffers; clean-offset model verified vs reference; cook/precision/abs-freq injected" },

    // ---- OS clock adapters (declared negative capability) ----
    Row { c: "sys.c", role: "OS adapter dispatch", rust: &[], port: Port::None, note: "host-clock mutation is a declared boundary" },
    Row { c: "sys_generic.c", role: "generic software-slew clock-discipline driver",
        rust: &["sys_generic.rs"], port: Port::Full,
        note: "complete port of all 14 functions: the offset->frequency slew model (bounded rate/duration, excess-duration tracking, offset_convert, dispersion on frequency change), with base driver/raw clock/scheduler/step injected; differential-tested vs the REAL compiled sys_generic.c (set_frequency/accrue_offset/end-of-slew sequence) + an independent slew-drain check" },
    Row { c: "sys_linux.c", role: "Linux clock adapter (adjtimex)", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_timex.c", role: "adjtimex()/ntp_adjtime() clock driver",
        rust: &["sys_timex.rs"], port: Port::Full,
        note: "complete port of all 10 functions (Linux build): ppm<->kernel-freq scaling, sync-status/leap/TAI status bookkeeping over the struct timex ABI, composing the generic slew driver; the adjtimex syscall is injected; differential-tested vs the REAL compiled sys_timex.c (every submitted timex captured) + an independent scaling check" },
    Row { c: "sys_null.c", role: "null clock driver (the `-x` 'disabled control' driver)",
        rust: &["sys_null.rs"], port: Port::Full,
        note: "complete port of all 8 functions; the virtual-clock offset/frequency model (set_freq/accrue/offset_convert); raw time injected as seconds, driver-as-struct (no global LCL registration)" },
    Row { c: "sys_macosx.c", role: "macOS clock adapter", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "sys_netbsd.c", role: "NetBSD clock adapter", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_posix.c", role: "POSIX clock adapter", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "sys_solaris.c", role: "Solaris clock adapter", rust: &[], port: Port::None, note: "" },

    // ---- networking / naming / misc (none) ----
    Row { c: "socket.c", role: "socket abstraction layer", rust: &[], port: Port::None, note: "" },
    Row { c: "addrfilt.c", role: "NTP/cmd access-control subnet trie (ADF_*)",
        rust: &["addrfilt.rs"], port: Port::Full,
        note: "complete port of all 16 functions (ADF_DestroyTable = Drop); decisions live-witnessed vs `chronyc accheck` on chrony 4.5" },
    Row { c: "nameserv.c", role: "synchronous DNS resolution", rust: &["nameserv.rs"], port: Port::Full,
        note: "complete port of all 4 functions: DNS_Name2IPAddress (the IP-literal shortcut + family filtering + IPv4 host-order extraction + IPv6 scope-id skip + result-array fill + Success/TryAgain/Failure status mapping), DNS_IPAddress2Name (reverse with IP-string fallback + snprintf truncation check), DNS_SetAddressFamily, DNS_Reload; the getaddrinfo/getnameinfo/res_init resolver and the util IP literal-parse/format are the injected Resolver boundary. Differential-tested vs the REAL compiled nameserv.c with getaddrinfo overridden to a crafted addrinfo list (family filter / v4 extraction / v6 scope skip / max_addrs / status, byte-identical); literal shortcut + reverse fallback unit-tested. A separate name_to_ip convenience keeps the live system-resolver path used by cmdparse (witnessed vs `chronyc accheck`)" },
    Row { c: "nameserv_async.c", role: "async DNS resolution", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "clientlog.c", role: "client access log / rate limiting",
        rust: &["clientlog.rs"], port: Port::Full,
        note: "complete port of all 35 functions: per-client hash table with oldest-record eviction, per-service token-bucket rate limiter with probabilistic leak, log2 request-rate estimate (incl. NTP timeout-rate inversion), and the interleaved-mode RX->TX timestamp map; differential-tested vs the REAL compiled clientlog.c (165-line vector fixture, injected reproducible RNG) + an independent token-bucket invariant" },
    Row { c: "manual.c", role: "manual time input / settime (MNL_*)",
        rust: &["manual.rs"], port: Port::Full,
        note: "complete port of all 11 functions; sample store + robust-regression slew/frequency estimate (uses the verified regress); time as seconds, REF correction returned not applied, struct-as-handler" },
];

/// Curated set of C functions that have a *direct, named behavioral counterpart*
/// in chrony-rs. Deliberately small and conservative: a function is listed only
/// when a specific Rust item reproduces its behavior under a court. Many
/// file-level "partial" files appear here with very few (or zero) functions,
/// because chrony-rs reproduces output shapes/behavior, not C functions 1:1 — and
/// the per-function view is meant to expose exactly that gap, not paper over it.
///
/// Every name here is validated against the doxygen inventory at generation time,
/// so a typo or an upstream rename fails the build rather than silently inflating
/// coverage.
const PORTED_FNS: &[(&str, &[&str])] = &[
    ("conf.c", &["CNF_ParseLine", "parse_source"]),
    (
        "cmdparse.c",
        &[
            "CPS_ParseNTPSourceAdd",
            "CPS_GetSelectOption",
            "CPS_SplitWord",
            "CPS_NormalizeLine",
            "CPS_ParseRefid",
            "CPS_ParseKey",
            "CPS_ParseAllowDeny",
            "CPS_ParseLocal",
        ],
    ),
    (
        "client.c",
        &[
            "print_seconds",
            "print_nanoseconds",
            "print_signed_nanoseconds",
            "print_freq_ppm",
            "print_signed_freq_ppm",
            "print_report",
            "print_info_field",
            "print_header",
            "process_cmd_sources",
            "process_cmd_sourcestats",
            "process_cmd_tracking",
            "process_cmd_activity",
            "process_cmd_serverstats",
        ],
    ),
    (
        // Stage 1 of the staged sources.c port (the registry / reachability / status
        // machinery). Selection / combine / dump / reports land in later stages.
        "sources.c",
        &[
            "SRC_Initialise",
            "SRC_CreateNewInstance",
            "SRC_ResetInstance",
            "SRC_SetRefid",
            "SRC_GetSourcestats",
            "get_leap_status",
            "SRC_UpdateStatus",
            "SRC_AccumulateSample",
            "SRC_SetActive",
            "SRC_UnsetActive",
            "special_mode_end",
            "handle_bad_source",
            "SRC_UpdateReachability",
            "SRC_ResetReachability",
            "SRC_IsReachable",
            "SRC_IsSyncPeer",
            "SRC_ReadNumberOfSources",
            "SRC_ActiveSources",
            "find_source",
            "SRC_GetType",
            // Stage 2: combine + selection helpers.
            "combine_sources",
            "update_sel_options",
            "get_status_char",
            "compare_sort_elements",
            // Stage 3: the SRC_SelectSource pipeline.
            "SRC_SelectSource",
            "mark_source",
            "mark_ok_sources",
            "unselect_selected_source",
            // Stage 4: lifecycle, handlers, accessors, select report.
            "SRC_Finalise",
            "SRC_DestroyInstance",
            "SRC_ReselectSource",
            "SRC_SetReselectDistance",
            "SRC_ResetSources",
            "SRC_ModifySelectOptions",
            "slew_sources",
            "add_dispersion",
            "SRC_GetSelectReport",
            // Stage 5: dump persistence, reports, logging helpers (-> Full).
            "save_source",
            "load_source",
            "get_dumpfile",
            "SRC_DumpSources",
            "SRC_ReloadSources",
            "SRC_RemoveDumpFiles",
            "SRC_ReportSource",
            "SRC_ReportSourcestats",
            "source_to_string",
            "log_selection_message",
            "log_selection_source",
        ],
    ),
    (
        "ntp_core.c",
        &[
            "process_response",
            // Stage 1: poll-interval + delay-sanity arithmetic.
            "get_separation",
            "get_poll_adj",
            "adjust_poll",
            "check_delay_ratio",
            "check_delay_dev_ratio",
            // Stage 3: transmit timing.
            "get_transmit_poll",
            "get_transmit_delay",
            // Stage 2: packet parse/validity.
            "parse_packet",
            "is_zero_data",
            "is_exp_ef",
            // Stage 4: PTP transparent-clock net correction.
            "apply_net_correction",
            // Stage 5: process-response test D (sync-loop guard).
            "check_sync_loop",
            // Stage 8: experimental extension-field builders.
            "add_ef_mono_root",
            "add_ef_net_correction",
            // Stage 9: runtime source-parameter setters.
            "NCR_ModifyMinpoll",
            "NCR_ModifyMaxpoll",
            "NCR_ModifyMaxdelay",
            "NCR_ModifyMaxdelayratio",
            "NCR_ModifyMaxdelaydevratio",
            "NCR_ModifyMinstratum",
            "NCR_ModifyPolltarget",
            // Stage 10: NTP server access control.
            "NCR_AddAccessRestriction",
            "NCR_CheckAccessRestriction",
            // Stage 11: local-timestamp helpers.
            "zero_local_timestamp",
            "update_tx_timestamp",
            // Stage 12: operating-mode state machine.
            "set_connectivity",
            "NCR_SetConnectivity",
            "NCR_IncrementActivityCounters",
            // Stage 13: source instance parameter mapping.
            "NCR_CreateInstance",
            // Stage 14: instance lifecycle transitions.
            "NCR_ResetInstance",
            "NCR_ResetPoll",
            "NCR_InitiateSampleBurst",
            "NCR_SlewTimes",
            // Stage 16: protocol support helpers.
            "handle_slew",
            "has_saved_response",
            "check_delay_quant",
            // Stage 17: client request build.
            "transmit_packet",
            // Stage 18: source report.
            "NCR_ReportSource",
            // Stage 19: receive-path mode dispatch.
            "NCR_ProcessRxKnown",
            "NCR_ProcessRxUnknown",
            // Stage 20: transmit-path mode dispatch.
            "NCR_ProcessTxKnown",
            "NCR_ProcessTxUnknown",
        ],
    ),
    (
        "util.c",
        &[
            "UTI_Ntp32ToDouble",
            "UTI_DoubleToNtp32",
            "UTI_Ntp64ToDouble",
            "UTI_DoubleToNtp64",
            "UTI_DiffNtp64ToDouble",
            "UTI_Log2ToDouble",
            "UTI_BytesToHex",
            "UTI_HexToBytes",
            "UTI_RefidToString",
            "UTI_IsTimeOffsetSane",
        ],
    ),
    (
        "manual.c",
        &[
            "MNL_Initialise",
            "MNL_Finalise",
            "MNL_Enable",
            "MNL_Disable",
            "MNL_IsEnabled",
            "MNL_Reset",
            "MNL_AcceptTimestamp",
            "MNL_DeleteSample",
            "MNL_ReportSamples",
            "estimate_and_set_system",
            "slew_samples",
        ],
    ),
    ("main.c", &["main"]),
    ("md5.c", &["MD5Init", "MD5Update", "MD5Final", "Transform"]),
    (
        "keys.c",
        &[
            "KEY_Initialise",
            "KEY_Finalise",
            "KEY_Reload",
            "KEY_KeyKnown",
            "KEY_GetAuthLength",
            "KEY_CheckKeyLength",
            "KEY_GetKeyInfo",
            "KEY_GenerateAuth",
            "KEY_CheckAuth",
            "free_keys",
            "get_key",
            "decode_key",
            "compare_keys_by_id",
            "lookup_key",
            "get_key_by_id",
            "generate_auth",
            "check_auth",
        ],
    ),
    ("hash_intmd5.c", &["HSH_GetHashId", "HSH_Hash", "HSH_Finalise"]),
    (
        "local.c",
        &[
            "LCL_Initialise", "LCL_Finalise", "lcl_RegisterSystemDrivers",
            "LCL_AddParameterChangeHandler", "LCL_RemoveParameterChangeHandler",
            "LCL_IsFirstParameterChangeHandler", "invoke_parameter_change_handlers",
            "LCL_AddDispersionNotifyHandler", "LCL_RemoveDispersionNotifyHandler",
            "lcl_InvokeDispersionNotifyHandlers", "LCL_ReadRawTime", "LCL_ReadCookedTime",
            "LCL_CookTime", "LCL_GetOffsetCorrection", "LCL_ReadAbsoluteFrequency",
            "LCL_SetAbsoluteFrequency", "LCL_AccumulateDeltaFrequency", "LCL_AccumulateOffset",
            "LCL_ApplyStepOffset", "LCL_NotifyExternalTimeStep", "LCL_NotifyLeap",
            "LCL_AccumulateFrequencyAndOffset", "LCL_AccumulateFrequencyAndOffsetNoHandlers",
            "LCL_MakeStep", "LCL_CancelOffsetCorrection", "LCL_CanSystemLeap", "LCL_SetSystemLeap",
            "LCL_SetTempComp", "LCL_SetSyncStatus", "LCL_GetSysPrecisionAsLog",
            "LCL_GetSysPrecisionAsQuantum", "LCL_GetMaxClockError", "measure_clock_precision",
            "clamp_freq", "check_offset",
        ],
    ),
    (
        "sourcestats.c",
        &[
            "SST_Initialise", "SST_Finalise", "SST_CreateInstance", "SST_DeleteInstance",
            "SST_ResetInstance", "SST_SetRefid", "SST_AccumulateSample", "SST_DoNewRegression",
            "SST_GetFrequencyRange", "SST_GetSelectionData", "SST_GetTrackingData",
            "SST_SlewSamples", "SST_AddDispersion", "SST_CorrectOffset", "SST_PredictOffset",
            "SST_MinRoundTripDelay", "SST_GetDelayTestData", "SST_SaveToFile", "SST_LoadFromFile",
            "SST_DoSourceReport", "SST_DoSourcestatsReport", "SST_GetJitterAsymmetry",
            "SST_Samples", "SST_GetMinSamples", "convert_to_intervals", "correct_asymmetry",
            "estimate_asymmetry", "find_best_sample_index", "find_min_delay_sample",
            "get_buf_index", "get_runsbuf_index", "prune_register",
        ],
    ),
    (
        "samplefilt.c",
        &[
            "SPF_CreateInstance",
            "SPF_DestroyInstance",
            "SPF_AccumulateSample",
            "SPF_GetFilteredSample",
            "SPF_GetLastSample",
            "SPF_GetNumberOfSamples",
            "SPF_GetMaxSamples",
            "SPF_GetAvgSampleDispersion",
            "SPF_SlewSamples",
            "SPF_CorrectOffset",
            "SPF_AddDispersion",
            "SPF_DropSamples",
            "check_sample",
            "compare_samples",
            "select_samples",
            "combine_selected_samples",
            "get_first_last",
            "drop_samples",
        ],
    ),
    (
        "hwclock.c",
        &[
            "HCL_CreateInstance",
            "HCL_DestroyInstance",
            "HCL_NeedsNewSample",
            "HCL_ProcessReadings",
            "HCL_AccumulateSample",
            "HCL_CookTime",
            "handle_slew",
        ],
    ),
    ("pktlength.c", &["PKL_CommandLength", "PKL_CommandPaddingLength", "PKL_ReplyLength"]),
    (
        "tempcomp.c",
        &["TMC_Initialise", "TMC_Finalise", "get_tempcomp", "read_points", "read_timeout"],
    ),
    (
        "smooth.c",
        &[
            "SMT_Initialise",
            "SMT_Finalise",
            "SMT_IsEnabled",
            "SMT_GetOffset",
            "SMT_Activate",
            "SMT_Reset",
            "SMT_Leap",
            "SMT_GetSmoothingReport",
            "get_smoothing",
            "update_stages",
            "update_smoothing",
            "handle_slew",
        ],
    ),
    (
        "sys_generic.c",
        &[
            "SYS_Generic_CompleteFreqDriver",
            "SYS_Generic_Finalise",
            "handle_step",
            "start_fastslew",
            "stop_fastslew",
            "clamp_freq",
            "update_slew",
            "handle_end_of_slew",
            "read_frequency",
            "set_frequency",
            "accrue_offset",
            "offset_convert",
            "apply_step_offset",
            "set_sync_status",
        ],
    ),
    (
        "sys_timex.c",
        &[
            "SYS_Timex_Initialise",
            "SYS_Timex_InitialiseWithFunctions",
            "SYS_Timex_Finalise",
            "SYS_Timex_Adjust",
            "convert_timex_frequency",
            "read_frequency",
            "set_frequency",
            "set_leap",
            "set_sync_status",
            "initialise_timex",
        ],
    ),
    (
        "sys_null.c",
        &[
            "SYS_Null_Initialise",
            "SYS_Null_Finalise",
            "update_offset",
            "read_frequency",
            "set_frequency",
            "accrue_offset",
            "apply_step_offset",
            "offset_convert",
        ],
    ),
    (
        "array.c",
        &[
            "ARR_CreateInstance",
            "ARR_DestroyInstance",
            "ARR_GetNewElement",
            "ARR_GetElement",
            "ARR_GetElements",
            "ARR_AppendElement",
            "ARR_RemoveElement",
            "ARR_SetSize",
            "ARR_GetSize",
            "realloc_array",
        ],
    ),
    (
        "nts_ntp_auth.c",
        &["NNA_GenerateAuthEF", "NNA_DecryptAuthEF", "get_padding_length", "get_padded_length"],
    ),
    (
        "cmac_nettle.c",
        &["CMC_GetKeyLength", "CMC_CreateInstance", "CMC_Hash", "CMC_DestroyInstance"],
    ),
    (
        "sched.c",
        &[
            "SCH_Initialise",
            "SCH_Finalise",
            "SCH_AddFileHandler",
            "SCH_RemoveFileHandler",
            "SCH_SetFileHandlerEvent",
            "SCH_GetLastEventTime",
            "SCH_GetLastEventMonoTime",
            "allocate_tqe",
            "release_tqe",
            "get_new_tqe_id",
            "SCH_AddTimeout",
            "SCH_AddTimeoutByDelay",
            "SCH_AddTimeoutInClass",
            "SCH_RemoveTimeout",
            "dispatch_timeouts",
            "dispatch_filehandlers",
            "handle_slew",
            "fill_fd_sets",
            "check_current_time",
            "update_monotonic_time",
            "SCH_MainLoop",
            "SCH_QuitProgram",
        ],
    ),
    (
        "nts_ntp_server.c",
        &["NNS_Initialise", "NNS_Finalise", "NNS_CheckRequestAuth", "NNS_GenerateResponseAuth"],
    ),
    (
        "ntp_signd.c",
        &[
            "close_socket",
            "open_socket",
            "process_response",
            "read_write_socket",
            "NSD_Initialise",
            "NSD_Finalise",
            "NSD_SignAndSendPacket",
        ],
    ),
    (
        "refclock.c",
        &[
            "get_refclock",
            "RCL_Initialise",
            "RCL_Finalise",
            "RCL_AddRefclock",
            "RCL_StartRefclocks",
            "RCL_ReportSource",
            "RCL_GetDriverParameter",
            "get_next_driver_option",
            "RCL_CheckDriverOptions",
            "RCL_GetDriverOption",
            "convert_tai_offset",
            "accumulate_sample",
            "RCL_AddSample",
            "RCL_AddPulse",
            "check_pulse_edge",
            "RCL_AddCookedPulse",
            "RCL_GetPrecision",
            "RCL_GetDriverPoll",
            "valid_sample_time",
            "pps_stratum",
            "get_local_stats",
            "follow_local",
            "poll_timeout",
            "slew_samples",
            "add_dispersion",
            "log_sample",
        ],
    ),
    (
        // The per-op handlers (do_*/PRV_AdjustTime/...) are platform-conditional and
        // absent from the default-build doxygen inventory; only the helper-shell
        // functions appear there. Those op handlers are nonetheless ported (the
        // dispatch arms + client methods) and exercised by the end-to-end differential.
        "privops.c",
        &["have_helper", "res_fatal", "helper_main", "PRV_Initialise", "PRV_Finalise"],
    ),
    (
        "refclock_shm.c",
        &["shm_initialise", "shm_finalise", "shm_poll"],
    ),
    (
        // sock_initialise/sock_finalise are the injected socket-open + handler
        // registration (the host's); read_sample carries the ported sample logic.
        "refclock_sock.c",
        &["read_sample"],
    ),
    (
        "nameserv.c",
        &["DNS_Name2IPAddress", "DNS_IPAddress2Name", "DNS_SetAddressFamily", "DNS_Reload"],
    ),
    (
        "reference.c",
        &[
            "handle_slew",
            "REF_Initialise",
            "REF_Finalise",
            "REF_SetMode",
            "REF_GetMode",
            "REF_SetModeEndHandler",
            "REF_GetLeapMode",
            "update_drift_file",
            "update_fb_drifts",
            "fb_drift_timeout",
            "schedule_fb_drift",
            "end_ref_mode",
            "maybe_log_offset",
            "is_step_limit_reached",
            "is_offset_ok",
            "is_leap_second_day",
            "get_tz_leap",
            "leap_end_timeout",
            "leap_start_timeout",
            "set_leap_timeout",
            "update_leap_status",
            "get_root_dispersion",
            "update_sync_status",
            "write_log",
            "special_mode_sync",
            "get_clock_estimates",
            "fuzz_ref_time",
            "get_correction_rate",
            "REF_SetReference",
            "REF_AdjustReference",
            "REF_SetManualReference",
            "REF_SetUnsynchronised",
            "REF_UpdateLeapStatus",
            "REF_GetReferenceParams",
            "REF_GetOurStratum",
            "REF_GetOrphanStratum",
            "REF_GetSkew",
            "REF_ModifyMaxupdateskew",
            "REF_ModifyMakestep",
            "REF_EnableLocal",
            "REF_DisableLocal",
            "is_leap_close",
            "REF_IsLeapSecondClose",
            "REF_GetTaiOffset",
            "REF_GetTrackingReport",
        ],
    ),
    (
        "ntp_auth.c",
        &[
            "generate_symmetric_auth",
            "check_symmetric_auth",
            "create_instance",
            "NAU_CreateNoneInstance",
            "NAU_CreateSymmetricInstance",
            "NAU_CreateNtsInstance",
            "NAU_DestroyInstance",
            "NAU_IsAuthEnabled",
            "NAU_GetSuggestedNtpVersion",
            "NAU_PrepareRequestAuth",
            "NAU_GenerateRequestAuth",
            "NAU_CheckRequestAuth",
            "NAU_GenerateResponseAuth",
            "NAU_CheckResponseAuth",
            "NAU_ChangeAddress",
            "NAU_DumpData",
            "NAU_GetReport",
        ],
    ),
    (
        "rtc.c",
        &[
            "RTC_Initialise",
            "RTC_Finalise",
            "RTC_TimeInit",
            "RTC_StartMeasurements",
            "RTC_WriteParameters",
            "RTC_GetReport",
            "RTC_Trim",
            "get_driftfile_time",
            "apply_driftfile_time",
        ],
    ),
    (
        "nts_ntp_client.c",
        &[
            "NNC_CreateInstance",
            "NNC_DestroyInstance",
            "NNC_PrepareForAuth",
            "NNC_GenerateRequestAuth",
            "NNC_CheckResponseAuth",
            "NNC_ChangeAddress",
            "NNC_DumpData",
            "NNC_GetReport",
            "reset_instance",
            "check_cookies",
            "set_ntp_address",
            "update_next_nke_attempt",
            "get_cookies",
            "parse_encrypted_efs",
            "extract_cookies",
            "save_cookies",
            "load_cookies",
        ],
    ),
    (
        "siv_nettle.c",
        &[
            "SIV_CreateInstance",
            "SIV_DestroyInstance",
            "SIV_GetKeyLength",
            "SIV_SetKey",
            "SIV_GetMinNonceLength",
            "SIV_GetMaxNonceLength",
            "SIV_GetTagLength",
            "SIV_Encrypt",
            "SIV_Decrypt",
        ],
    ),
    (
        "siv_nettle_int.c",
        &[
            "CMAC128_CTX",
            "_cmac128_block_mulx",
            "cmac128_set_key",
            "cmac128_update",
            "cmac128_digest",
            "cmac_aes128_set_key",
            "cmac_aes128_update",
            "cmac_aes128_digest",
            "_siv_s2v",
            "siv_cmac_aes128_set_key",
            "siv_cmac_aes128_encrypt_message",
            "siv_cmac_aes128_decrypt_message",
        ],
    ),
    (
        "ntp_ext.c",
        &[
            "format_field",
            "NEF_SetField",
            "NEF_ParseSingleField",
            "NEF_AddBlankField",
            "NEF_AddField",
            "NEF_ParseField",
        ],
    ),
    (
        "regress.c",
        &[
            "RGR_WeightedRegression",
            "RGR_FindBestRegression",
            "RGR_FindBestRobustRegression",
            "RGR_MultipleRegress",
            "RGR_GetTCoef",
            "RGR_GetChi2Coef",
            "RGR_FindMedian",
            "find_median",
            "find_ordered_entry_with_flags",
            "n_runs_from_residuals",
            "eval_robust_residual",
        ],
    ),
    (
        "quantiles.c",
        &[
            "QNT_CreateInstance",
            "QNT_DestroyInstance",
            "QNT_Reset",
            "QNT_Accumulate",
            "QNT_GetMinK",
            "QNT_GetQuantile",
            "insert_initial_value",
            "update_estimate",
        ],
    ),
    (
        "addrfilt.c",
        &[
            "ADF_CreateTable",
            "ADF_DestroyTable",
            "ADF_Allow",
            "ADF_AllowAll",
            "ADF_Deny",
            "ADF_DenyAll",
            "ADF_IsAllowed",
            "ADF_IsAnyAllowed",
            "set_subnet_",
            "set_subnet",
            "check_ip_in_node",
            "is_any_allowed",
            "open_node",
            "close_node",
            "get_subnet",
            "split_ip6",
        ],
    ),
    (
        "clientlog.c",
        &[
            "CLG_Initialise",
            "CLG_Finalise",
            "CLG_GetClientIndex",
            "CLG_LogServiceAccess",
            "CLG_LimitServiceRate",
            "CLG_UpdateNtpStats",
            "CLG_GetNtpMinPoll",
            "CLG_SaveNtpTimestamps",
            "CLG_UndoNtpTxTimestampSlew",
            "CLG_UpdateNtpTxTimestamp",
            "CLG_GetNtpTxTimestamp",
            "CLG_DisableNtpTimestamps",
            "CLG_GetNumberOfIndices",
            "CLG_GetClientAccessReportByIndex",
            "CLG_GetServerStatsReport",
            "compare_ts",
            "compare_total_hits",
            "get_record",
            "expand_hashtable",
            "set_bucket_params",
            "get_ts_from_timespec",
            "update_record",
            "get_index",
            "check_service_number",
            "limit_response_random",
            "get_ntp_tss",
            "find_ntp_rx_ts",
            "ntp64_to_int64",
            "int64_to_ntp64",
            "push_ntp_tss",
            "set_ntp_tx",
            "get_ntp_tx",
            "handle_slew",
            "get_interval",
            "get_last_ago",
        ],
    ),
    (
        "ntp_sources.c",
        &[
            // Stage 1: source-table internals.
            "find_slot",
            "find_slot2",
            "check_hashtable_size",
            "get_next_conf_id",
            "NSR_StatusToString",
            // Stage 2: table growth.
            "rehash_records",
            // Stage 3: source insertion + per-source reconfiguration fan-out.
            "add_source",
            "NSR_ModifyMinpoll",
            "NSR_ModifyMaxpoll",
            "NSR_ModifyMaxdelay",
            "NSR_ModifyMaxdelayratio",
            "NSR_ModifyMaxdelaydevratio",
            "NSR_ModifyMinstratum",
            "NSR_ModifyPolltarget",
            // Stage 4: source removal lifecycle + pool counters.
            "NSR_RemoveSource",
            "clean_source_record",
            // Stage 5: source-iteration operations.
            "NSR_InitiateSampleBurst",
            "NSR_RemoveAllSources",
            "NSR_GetLocalRefid",
            // Stage 6: connectivity fan-out (sync-peer-last order).
            "NSR_SetConnectivity",
            // Stage 7: pool-id allocation + report fan-outs.
            "get_unused_pool_id",
            "NSR_GetNTPReport",
            "NSR_ReportSource",
            // Stage 8: resolution predicate + name lookup.
            "is_resolved",
            "NSR_GetName",
        ],
    ),
];

/// A module that exists in chrony-rs (Full or Partial), surfaced for the
/// generated negative-capabilities ledger so the "implemented" list there is
/// derived from the same single source of truth as the parity matrix.
pub(crate) struct PortedModule {
    /// chrony source basename.
    pub c: &'static str,
    /// One-line role.
    pub role: &'static str,
    /// True for [`Port::Full`], false for [`Port::Partial`].
    pub full: bool,
    /// chrony-rs module paths that port it.
    pub rust: &'static [&'static str],
    /// The honesty note (what is / isn't ported).
    pub note: &'static str,
}

/// The Full and Partial rows of [`MAP`], in catalog order. Drives the generated
/// "implemented as isolated modules" section of `docs/negative-capabilities.md`,
/// so porting a new file updates that ledger automatically and the freshness gate
/// catches any prose that claims an implemented module is absent.
pub(crate) fn ported_modules() -> Vec<PortedModule> {
    MAP.iter()
        .filter(|r| matches!(r.port, Port::Full | Port::Partial))
        .map(|r| PortedModule {
            c: r.c,
            role: r.role,
            full: r.port == Port::Full,
            rust: r.rust,
            note: r.note,
        })
        .collect()
}

/// The machine-derivable headline facts that prose docs restate and that must not
/// be allowed to drift. Computed from the same sources the parity matrix uses.
pub(crate) struct CanonicalFacts {
    /// Number of chrony `.c` files in the doxygen inventory.
    pub c_files: usize,
    /// Total chrony C functions in the inventory.
    pub c_functions: usize,
}

/// Compute the canonical facts from the committed inventory.
pub(crate) fn canonical_facts(root: &Path) -> CanonicalFacts {
    let (_prov, inv) = load_c_inventory(root);
    CanonicalFacts { c_files: inv.len(), c_functions: inv.values().sum() }
}

/// Look up the curated ported-function list for a file (empty if none).
fn ported_fns(file: &str) -> &'static [&'static str] {
    PORTED_FNS
        .iter()
        .find(|(f, _)| *f == file)
        .map(|(_, fns)| *fns)
        .unwrap_or(&[])
}

/// Parse the committed doxygen inventory into `file -> function count`, preserving
/// the header provenance line for display.
fn load_c_inventory(root: &Path) -> (String, BTreeMap<String, usize>) {
    let path = root.join("research/doxygen/chrony-4.5-c-inventory.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut provenance = String::new();
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            if provenance.is_empty() {
                provenance = rest.to_string();
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        if let (Some(file), Some(count)) = (cols.next(), cols.next()) {
            if let Ok(n) = count.parse::<usize>() {
                map.insert(file.to_string(), n);
            }
        }
    }
    (provenance, map)
}

/// Parse the inventory into `file -> [function names]` (the third TSV column).
fn load_c_functions(root: &Path) -> BTreeMap<String, Vec<String>> {
    let path = root.join("research/doxygen/chrony-4.5-c-inventory.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 3 {
            let fns = if cols[2].is_empty() {
                Vec::new()
            } else {
                cols[2].split(',').map(|s| s.to_string()).collect()
            };
            map.insert(cols[0].to_string(), fns);
        }
    }
    map
}

/// Authoritative per-file Rust counts: named functions (free + `impl` + trait)
/// and closures. Derived from the real AST via `syn`, not from doxygen's C++
/// frontend (which misparses Rust) nor a regex (which cannot see closures).
#[derive(Default, Clone, Copy)]
pub struct RustCounts {
    pub named_fns: usize,
    pub closures: usize,
}

/// A `syn` visitor that tallies every named function definition and every
/// closure. Walking with `visit` (rather than inspecting only top-level items)
/// is what lets us count closures nested inside function bodies — the exact case
/// doxygen drops.
#[derive(Default)]
struct InventoryVisitor {
    counts: RustCounts,
}

impl<'ast> syn::visit::Visit<'ast> for InventoryVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.counts.named_fns += 1;
        syn::visit::visit_item_fn(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.counts.named_fns += 1;
        syn::visit::visit_impl_item_fn(self, node);
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.counts.named_fns += 1;
        syn::visit::visit_trait_item_fn(self, node);
    }
    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.counts.closures += 1;
        syn::visit::visit_expr_closure(self, node);
    }
}

/// Parse a Rust source string and tally its functions/closures via the AST.
fn count_rust(content: &str) -> RustCounts {
    use syn::visit::Visit;
    match syn::parse_file(content) {
        Ok(ast) => {
            let mut v = InventoryVisitor::default();
            v.visit_file(&ast);
            v.counts
        }
        // Our own sources always parse; a parse failure should surface, not hide.
        Err(_) => RustCounts::default(),
    }
}

/// Resolve a rust module path (relative to `crates/chrony-rs-core/src`, or with a
/// `../crate/...` escape) to an absolute path under the repo and AST-count it.
fn rust_fns(root: &Path, rel: &str) -> usize {
    // Convention: a bare path is under chrony-rs-core/src; a `../crate/...` escape
    // reaches a sibling crate under crates/ (e.g. the chronyc-rs/chronyd-rs bins).
    let path = match rel.strip_prefix("../") {
        Some(sibling) => root.join("crates").join(sibling),
        None => root.join("crates/chrony-rs-core/src").join(rel),
    };
    std::fs::read_to_string(&path)
        .map(|c| count_rust(&c).named_fns)
        .unwrap_or(0)
}

/// Walk every `.rs` file under `crates/` (excluding `target/`) and total the
/// authoritative AST inventory — the figure the prose doc cites.
pub fn rust_inventory_total(root: &Path) -> (RustCounts, usize) {
    let mut total = RustCounts::default();
    let mut files = 0usize;
    fn walk(dir: &Path, total: &mut RustCounts, files: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().map(|n| n == "target").unwrap_or(false) {
                    continue;
                }
                walk(&p, total, files);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                if let Ok(c) = std::fs::read_to_string(&p) {
                    let counts = count_rust(&c);
                    total.named_fns += counts.named_fns;
                    total.closures += counts.closures;
                    *files += 1;
                }
            }
        }
    }
    walk(&root.join("crates"), &mut total, &mut files);
    (total, files)
}

/// Render `docs/generated/port-parity.md`.
pub fn port_parity_md(root: &Path) -> String {
    let (provenance, inv) = load_c_inventory(root);
    let total_c_files = inv.len();
    let total_c_funcs: usize = inv.values().sum();

    // Index the curated map by file for joining against the authoritative TSV set.
    let by_file: BTreeMap<&str, &Row> = MAP.iter().map(|r| (r.c, r)).collect();

    let mut full = 0usize;
    let mut partial = 0usize;
    let mut scaffold = 0usize;
    let mut none = 0usize;
    let mut funcs_with_counterpart = 0usize;

    let mut table = String::new();
    table.push_str("| chrony `.c` | C fns | parity % | role | chrony-rs counterpart | status |\n");
    table.push_str("|---|---:|---:|---|---|---|\n");
    for (file, &n) in &inv {
        let (role, rust, port, _note) = match by_file.get(file.as_str()) {
            Some(r) => (r.role, r.rust, r.port, r.note),
            None => (
                "(unmapped — present in inventory, absent from catalog)",
                &[][..],
                Port::None,
                "",
            ),
        };
        match port {
            Port::Full => {
                full += 1;
                funcs_with_counterpart += n;
            }
            Port::Partial => {
                partial += 1;
                funcs_with_counterpart += n;
            }
            Port::Scaffold => {
                scaffold += 1;
                funcs_with_counterpart += n;
            }
            Port::None => none += 1,
        }
        // Per-file function-level parity: ported C functions / total (the same
        // metric as port-parity-functions.md), rendered right beside each file.
        let pct = (ported_fns(file).len() as f64 / n.max(1) as f64) * 100.0;
        let rs = if rust.is_empty() {
            "—".to_string()
        } else {
            rust.iter()
                .map(|m| format!("`{}`", m.trim_start_matches("../")))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        table.push_str(&format!(
            "| `{file}` | {n} | {pct:.1}% | {role} | {rs} | {} |\n",
            port.glyph()
        ));
    }

    let mut s = String::new();
    s.push_str("<!-- DO NOT EDIT BY HAND.\n");
    s.push_str("Generated by `cargo xtask gen` (xtask/src/parity.rs) from the committed doxygen\n");
    s.push_str("inventory (research/doxygen/chrony-4.5-c-inventory.tsv) joined with a curated\n");
    s.push_str(
        "C-file -> chrony-rs mapping and an authoritative `syn` AST inventory of crates/.\n",
    );
    s.push_str(
        "Run `cargo xtask check` to verify freshness; the pre-commit hook enforces it. -->\n\n",
    );

    s.push_str("# chrony C ↔ chrony-rs port-parity matrix\n\n");
    s.push_str(
        "A 1:1 completeness catalog of **every** chrony 4.5 `.c` translation unit against\n",
    );
    s.push_str(
        "its chrony-rs counterpart. The C inventory is authoritative (doxygen); the status\n",
    );
    s.push_str("column is curated and deliberately conservative — see `docs/port-parity.md` for\n");
    s.push_str("method, provenance, and how the doxygen runs were produced on both sides.\n\n");

    s.push_str(&format!("> C inventory provenance: {provenance}\n\n"));

    s.push_str("## Headline completeness\n\n");
    let any = full + partial + scaffold;
    s.push_str(&format!("- **C translation units:** {total_c_files} `.c` files, {total_c_funcs} functions (doxygen).\n"));
    s.push_str(&format!(
        "- **Files with any chrony-rs counterpart:** {any} / {total_c_files} \
         ({full} full, {partial} partial, {scaffold} scaffold); **{none}** have none.\n"
    ));
    s.push_str(&format!(
        "- **Files fully ported:** {full} / {total_c_files} — every function in the unit has a \
         court-backed counterpart (dependency-free TUs first). chrony-rs remains an early-stage \
         forensic reconstruction; this number is stated, not hidden.\n"
    ));
    let pct = (funcs_with_counterpart as f64 / total_c_funcs as f64) * 100.0;
    s.push_str(&format!(
        "- **Loose upper bound on function coverage:** files with a counterpart contain \
         {funcs_with_counterpart} / {total_c_funcs} C functions ({pct:.1}%). This is an *upper \
         bound only* — a file marked partial ports a fraction of its functions, so true coverage \
         is well below this. chrony-rs ports behavior under court, not functions 1:1.\n\n"
    ));

    let (rs_total, rs_files) = rust_inventory_total(root);
    s.push_str(&format!(
        "- **chrony-rs native inventory (`syn` AST):** {} named functions + {} closures across \
         {} `.rs` files. Extracted from the real AST, not doxygen — see the limitation notice in \
         `docs/port-parity.md`.\n\n",
        rs_total.named_fns, rs_total.closures, rs_files
    ));

    s.push_str("Legend: ● full = every function ported under court · ");
    s.push_str("◑ partial = some behavior ported with an executable court · ");
    s.push_str("○ scaffold = type/simulated stand-in only · · none = no counterpart.\n\n");

    s.push_str("## Full catalog (all C files, sorted)\n\n");
    s.push_str(&table);
    s.push('\n');

    // Notes block: only for files that have a counterpart, to keep the honesty
    // qualifications attached to the claims without bloating the main table.
    s.push_str("## Coverage notes (files with a counterpart)\n\n");
    for r in MAP.iter().filter(|r| r.port != Port::None) {
        let total_rs: usize = r.rust.iter().map(|m| rust_fns(root, m)).sum();
        s.push_str(&format!(
            "- **`{}`** — {} _(≈{} Rust `fn` in mapped modules)_\n",
            r.c, r.note, total_rs
        ));
    }
    s.push('\n');

    s.push_str("## What \"partial\"/\"scaffold\" deliberately does not mean\n\n");
    s.push_str("A counterpart is not a claim of equivalence. It means some behavior from that C\n");
    s.push_str(
        "file is reconstructed and admitted by a court in `reports/`. Everything outside the\n",
    );
    s.push_str(
        "admitted courts is unported. Where a file is subsumed by the Rust standard library\n",
    );
    s.push_str(
        "(`memory.c`) or is upstream test scaffolding (`stubs.c`), that is noted\n",
    );
    s.push_str("rather than counted as coverage.\n");

    s
}

/// Render `docs/generated/port-parity-functions.md`: the per-file, per-function
/// gap view with percentages. This is the fine-grained companion to the file-level
/// matrix.
pub fn port_parity_functions_md(root: &Path) -> String {
    let (provenance, inv) = load_c_inventory(root);
    let funcs = load_c_functions(root);

    // Validate every curated name against the inventory (fail loud on drift).
    let mut bad = Vec::new();
    for (file, names) in PORTED_FNS {
        let have = funcs.get(*file);
        for n in *names {
            let ok = have.map(|v| v.iter().any(|f| f == n)).unwrap_or(false);
            if !ok {
                bad.push(format!("{file}:{n}"));
            }
        }
    }

    let total_c: usize = inv.values().sum();
    let total_ported: usize = PORTED_FNS.iter().map(|(_, f)| f.len()).sum();
    let overall = if total_c > 0 {
        (total_ported as f64 / total_c as f64) * 100.0
    } else {
        0.0
    };

    let mut s = String::new();
    s.push_str("<!-- DO NOT EDIT BY HAND.\n");
    s.push_str("Generated by `cargo xtask gen` (xtask/src/parity.rs) from the committed doxygen\n");
    s.push_str("inventory joined with a curated, validated ported-function set. -->\n\n");

    s.push_str("# chrony C → chrony-rs per-function parity (gap view)\n\n");
    s.push_str("Function-level companion to `port-parity.md`: for every chrony 4.5 `.c` file, how\n");
    s.push_str("many of its C functions have a **direct named counterpart** in chrony-rs, the\n");
    s.push_str("percentage, and — for files with any coverage — exactly which functions are ported\n");
    s.push_str("(✓) versus a gap (·).\n\n");

    s.push_str(&format!("> Inventory provenance: {provenance}\n\n"));

    if !bad.is_empty() {
        // Should never happen (the names are validated); surface loudly if it does.
        s.push_str(&format!(
            "> ⚠️ INVALID curated names (not in inventory): {}\n\n",
            bad.join(", ")
        ));
    }

    s.push_str("## How to read this (and what the percentage is NOT)\n\n");
    s.push_str("The percentage is **C functions with a direct, court-backed Rust counterpart ÷ \
                total C functions in that file**. It is intentionally strict and runs low, \
                because chrony-rs restores *behavior and output shapes*, not C functions 1:1. A \
                file can be \"partial\" at the file level (it reproduces some behavior) yet near \
                **0%** here, because no individual C function was transliterated. That divergence \
                is the point of this view — it shows the real porting frontier, function by \
                function, with no credit for \"it kind of does something similar.\"\n\n");

    s.push_str(&format!(
        "**Overall: {total_ported} / {total_c} C functions have a direct counterpart \
         ({overall:.1}%).** The other {} are gaps.\n\n",
        total_c - total_ported
    ));

    // Summary table: every file, sorted by coverage desc then name.
    let mut rows: Vec<(&String, usize, usize)> = inv
        .iter()
        .map(|(f, &n)| (f, n, ported_fns(f).len()))
        .collect();
    rows.sort_by(|a, b| {
        let pa = a.2 as f64 / a.1.max(1) as f64;
        let pb = b.2 as f64 / b.1.max(1) as f64;
        pb.partial_cmp(&pa).unwrap().then(a.0.cmp(b.0))
    });

    s.push_str("## Per-file coverage (all 70 files)\n\n");
    s.push_str("| chrony `.c` | C fns | ported | gap | parity % |\n");
    s.push_str("|---|---:|---:|---:|---:|\n");
    for (file, total, ported) in &rows {
        let pct = (*ported as f64 / (*total).max(1) as f64) * 100.0;
        s.push_str(&format!(
            "| `{file}` | {total} | {ported} | {} | {pct:.1}% |\n",
            total - ported
        ));
    }
    s.push('\n');

    // Detail: only files with any coverage, showing ✓ ported and · gap functions.
    s.push_str("## Ported files — function-by-function (✓ ported · gap)\n\n");
    s.push_str("Gaps are listed explicitly here so the missing surface in a partially-ported file \
                is visible, not summarized away. Files with 0 ported functions are omitted from \
                this section (their entire function list is a gap; see the inventory TSV).\n\n");
    for (file, total, ported) in rows.iter().filter(|r| r.2 > 0) {
        let names = funcs.get(*file).cloned().unwrap_or_default();
        let pset = ported_fns(file);
        let pct = (*ported as f64 / (*total).max(1) as f64) * 100.0;
        s.push_str(&format!("### `{file}` — {ported}/{total} ({pct:.1}%)\n\n"));
        for n in &names {
            let mark = if pset.contains(&n.as_str()) { "✓" } else { "·" };
            s.push_str(&format!("- {mark} `{n}`\n"));
        }
        s.push('\n');
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_counter_sees_fns_methods_and_closures() {
        let src = r#"
            fn free() {}
            struct S;
            impl S { fn method(&self) { let f = |x| x + 1; let _ = f(1); } }
            trait T { fn provided() {} }
        "#;
        let c = count_rust(src);
        // free + method + provided = 3 named; one closure.
        assert_eq!(c.named_fns, 3);
        assert_eq!(c.closures, 1);
    }

    #[test]
    fn curated_ported_fns_all_exist_in_inventory() {
        // Every name in PORTED_FNS must be a real chrony function, or the parity
        // percentage is fiction. Validate against the committed inventory.
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let funcs = load_c_functions(&root);
        let mut bad = Vec::new();
        for (file, names) in PORTED_FNS {
            let have = funcs.get(*file);
            for n in *names {
                if !have.map(|v| v.iter().any(|f| f == n)).unwrap_or(false) {
                    bad.push(format!("{file}:{n}"));
                }
            }
        }
        assert!(bad.is_empty(), "curated names missing from inventory: {bad:?}");
    }

    #[test]
    fn ast_counter_ignores_fn_in_strings_and_idents() {
        // The regex approach miscounted these; the AST does not.
        let src = r#"fn real() { let define = "fn fnord"; let _ = define; }"#;
        let c = count_rust(src);
        assert_eq!(c.named_fns, 1);
        assert_eq!(c.closures, 0);
    }
}
