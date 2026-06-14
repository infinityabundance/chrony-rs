# Negative capabilities

The things `chrony-rs` deliberately does **not** do yet. Each entry is a promise
that the absence is intentional and fails *closed* (errors or is simply absent),
never silently approximated. Removing an entry from this ledger requires the
corresponding court and evidence to exist first.

## Daemon / clock

- **No real system-clock mutation.** No `step`/`slew` of a live clock exists.
- **No `--lab-daemon` mode.** Deferred to Stage 6 behind explicit lab guards.
- **No NTP server/responder.** Client-shaped packet handling only; serving time
  to peers is out of scope at this stage.

## Control

- **No live control-socket transport.** `chronyc-rs tracking|sources|sourcestats|
  activity|ntpdata` against a running daemon is not implemented; the binary exits
  non-zero with an explanation. Only offline `render-tracking` works.
- **No control protocol encode/decode.** The Unix/UDP control wire format is not
  yet modeled.

## NTP wire

- **No extension-field parsing.** Trailing bytes after the 48-byte header are
  preserved verbatim (so round trips stay byte-identical) but **not interpreted**.
- **No authentication (MAC/key-id) verification.** Bytes are preserved, not checked.
- **No NTS.** No handshake, cookies, records, or key material. (See `nts-atlas.md`
  when it lands.)

## Config

- **Recognized ≠ modeled.** All known chrony directives are *recognized* (so a
  valid file passes `--check-config`), but only a small subset is given typed
  semantics. Unmodeled directives are preserved, not executed.
- **No `include`/`confdir` expansion.** Recognized as keywords, not followed.
- **No exact diagnostic-text parity** beyond what `config-atlas.md` admits;
  messages are normalized until witnessed against the oracle.

## Discipline / sources / state

- **No measurement stage.** Offsets/delays are not yet computed from NTP packet
  timestamps. This gates almost everything downstream (filtering, selection input,
  discipline). Offsets are never fabricated to advance a court.
- **Source selection is partial and algorithmic, not oracle-witnessed.** The
  reachability register and selectability gate are reconstructed precisely; the
  falseticker intersection reproduces the *core idea* only — no clustering/
  combining, no `f`-loop refinement, no `prefer`/`trust` bias, no reselection
  hysteresis. The selected source is a documented min-root-distance stand-in, and
  selection is **not yet wired into replay** (no real offsets to feed it).
- **No sample filtering/regression/jitter estimation.** Not implemented.
- **No discipline model** (offset/frequency/skew/step/slew). Not implemented.
- **No drift/dump/state file read or write.** Not implemented.
- **No refclock or RTC support.** Not implemented.

## Replay

- **Replay executes, but applies no chrony policy.** `--replay` now drives a
  validated trace through a deterministic simulated clock and emits a reproducible
  decision-log hash. It does **not** yet implement chrony's source selection,
  sample filtering, or clock discipline — the `selected_source` it reports is a
  transparent "latest online source" placeholder, not a chrony decision, and it is
  not compared against a chrony oracle.
- **No oracle comparison.** Expectation checking is limited to the runner's own
  decision-log hash (regression self-consistency), never an assertion of parity
  with real `chronyd` output.

## OS / platform

- **No OS clock adapters.** No `adjtimex`/`clock_adjtime`/BSD/macOS/illumos code.
- **No privilege/capability handling, chroot, or sandbox.** Not implemented.

## Unsafe

- **No `unsafe` code.** The current count is zero (see `security-boundary.md`).
  This is recorded even though it is zero, so a future addition is conspicuous.
