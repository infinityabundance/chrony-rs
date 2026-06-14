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

- **No source selection, filtering, or combining.** Not implemented.
- **No discipline model** (offset/frequency/skew/step/slew). Not implemented.
- **No drift/dump/state file read or write.** Not implemented.
- **No refclock or RTC support.** Not implemented.

## Replay

- **No replay execution.** `--replay` loads and structurally validates a trace;
  it does not yet drive the brain or compare against oracle outputs.

## OS / platform

- **No OS clock adapters.** No `adjtimex`/`clock_adjtime`/BSD/macOS/illumos code.
- **No privilege/capability handling, chroot, or sandbox.** Not implemented.

## Unsafe

- **No `unsafe` code.** The current count is zero (see `security-boundary.md`).
  This is recorded even though it is zero, so a future addition is conspicuous.
