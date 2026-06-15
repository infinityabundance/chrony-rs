# Packet atlas

The byte-level court for NTP wire format. Implemented in
`chrony-rs-core/src/ntp/`. The contract: decode is **total** (no input panics),
encode is the exact inverse of decode for any decoded value, and trailing bytes
are preserved verbatim.

## Header (RFC 5905 §7.3, 48 bytes)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 1 | LI(2) · VN(3) · Mode(3) | packed byte; fields masked on re-encode |
| 1 | 1 | Stratum | 0 = KoD/unspecified, 1 = primary, 16 = unsync |
| 2 | 1 | Poll | log2 seconds, **signed** |
| 3 | 1 | Precision | log2 seconds, signed |
| 4 | 4 | Root Delay | NTP short (16.16) |
| 8 | 4 | Root Dispersion | NTP short (16.16) |
| 12 | 4 | Reference ID | raw 4 bytes; interpretation is context-dependent |
| 16 | 8 | Reference Timestamp | NTP timestamp (32.32) |
| 24 | 8 | Origin Timestamp | |
| 32 | 8 | Receive Timestamp | |
| 40 | 8 | Transmit Timestamp | |
| 48 | .. | tail | extension fields / MAC / NTS — preserved, not parsed |

## Court status (`CHRONY.PACKET.*`)

| ID | Description | Status |
|----|-------------|--------|
| 1 | basic header decode | admitted (`decode_then_encode_is_byte_identical`) |
| 2 | timestamp fields | admitted (`timestamp_roundtrips_bit_exact`) |
| 3 | stratum/poll/precision | admitted (signed poll/precision tested) |
| 4 | root delay/dispersion | admitted (short fixed-point test) |
| 5 | reference ID behavior | partial (ASCII vs IPv4 refid distinguished) |
| 6 | mode/version handling | admitted (`byte_zero_fields_pack_independently`) |
| 7 | kiss-o-death | admitted (`kiss_of_death_rate_is_detected`) |
| 8 | malformed (too short) rejection | admitted (`short_buffer_is_rejected_not_panicked`) |
| 9 | extension fields | deferred (tail preserved, not parsed) |
| 10 | authentication fields | deferred (tail preserved) |
| 11 | NTS records | deferred |
| 12 | roundtrip byte identity | admitted |
| 13 | hostile packet fuzz regression | planned (smoke run pending) |

## Traps recorded in code

- **Tail preservation.** Dropping bytes after the header would break round-trip
  byte parity; `NtpPacket::tail` keeps them and `encode` re-emits them.
- **Signed poll/precision.** These are `i8`, not `u8`. A common bug.
- **Reference ID is context-dependent.** ASCII refid (stratum 1), IPv4 address
  (stratum >1 over v4), or ASCII kiss code (stratum 0). Raw bytes kept; meaning
  resolved by helpers, not by the wire type.
- **No "invalid" bit patterns at this layer.** Rejecting a bad stratum is a
  *policy* decision for source selection, not a wire-format error. Decode accepts
  any 48+ byte buffer.

## Measurement (RFC 5905 §8)

`ntp::Measurement::from_exchange` computes, from the four exchange timestamps:

```text
offset θ = ((T2 - T1) + (T3 - T4)) / 2
delay  δ = (T4 - T1) - (T3 - T2)
```

Implemented in `ntp/measurements.rs`. Key fidelity point: timestamp differences
are taken on the **raw 64-bit values with wrapping arithmetic** (reinterpreted as
signed), never via absolute-seconds conversion — so the algebra is exact across
the 2036 era rollover. `delay` is returned raw (slightly-negative values from
coarse resolution are a filter-stage policy, not a wire-format clamp). Tested with
symmetric, asymmetric, negative-offset, and era-rollover vectors, plus an
end-to-end `tests/pipeline.rs` that feeds **computed** offsets into source
selection.

## No-panic guarantee

`NtpPacket::decode` returns `Result<_, PacketError>`; the only failure is a
buffer shorter than 48 bytes. This underwrites `CHRONY.SECURITY.2` ("no panic on
hostile packets"). A future fuzz campaign will harden it with minimized seeds and
regression fixtures.
