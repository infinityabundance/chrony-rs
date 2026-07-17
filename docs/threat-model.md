# Threat Model for chrony-rs

## Attack surface
1. NTP port 123 (UDP) — NTP protocol attacks
2. Cmdmon port 323 (UDP) — control protocol attacks
3. NTS-KE port 4460 (TCP) — TLS handshake attacks
4. Unix socket /var/run/chronyd-rs.sock — local attacks
5. Config file — file system attacks

## Trust boundaries
- Network boundaries: NTP, cmdmon, NTS-KE
- Local boundaries: Unix socket, config file, drift file, log files
- System boundaries: adjtimex syscall, clock_settime, RTC ioctls

## Threats
1. NTP amplification attacks — mitigated by response size limiting
2. Replay attacks — mitigated by origin timestamp (test B)
3. DoS via rate limiting — mitigated by token-bucket rate limiter
4. Local privilege escalation via cmdmon — mitigated by chmod + authentication
5. Config injection via include/confdir — mitigated by path validation
6. Timing side channels via NTP — not mitigated (fundamental to protocol)

## Mitigations by layer

### Network layer
- NTP response size capped to 512 bytes to prevent amplification
- Cmdmon validated via length tables before dispatch
- Rate limiting per client via token-bucket algorithm

### Control protocol
- Command validation via PKL_CommandLength tables
- Reply-size gated against request size (reply_fits gate)
- Version mismatch detection and compat-server fallback
- Permissions matrix (PERMIT_OPEN / PERMIT_LOCAL / PERMIT_AUTH)

### Local attacks
- Unix socket owned by root/chrony
- Command key authentication support
- Seccomp BPF filter restricts syscall surface
- Privilege drop to configured user
- Memory locking to prevent swapping of secrets

### Configuration
- Path validation for include/confdir directives
- Config parsing errors are non-fatal for runtime
- Key file permissions checked on load

## Incident response
- Syslog logging for all command access
- Client log tracks NTP and command access patterns
- Rate limiting logs indicate potential DoS attempts
- Step changes logged with count of make-step operations

## Assumptions
- Network boundary controls (firewall) exist outside chrony-rs
- TLS termination for NTS-KE is handled by infrastructure
- System clock is monotonic between adjtimex calls
- Kernel NTP discipline (PLL) is available and reliable
