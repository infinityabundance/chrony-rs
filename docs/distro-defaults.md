# Distro defaults

chrony's *shipped configuration* differs by distribution, and a forensic port must
accept what real systems actually deploy. This page records the distro defaults
witnessed so far.

## Ubuntu 24.04 (chrony 4.5-1ubuntu4.2)

The packaged `/etc/chrony/chrony.conf` uses (comments stripped):

```
confdir /etc/chrony/conf.d
pool ntp.ubuntu.com        iburst maxsources 4
pool 0.ubuntu.pool.ntp.org iburst maxsources 1
pool 1.ubuntu.pool.ntp.org iburst maxsources 1
pool 2.ubuntu.pool.ntp.org iburst maxsources 2
sourcedir /run/chrony-dhcp
sourcedir /etc/chrony/sources.d
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
```

- **chrony-rs accepts it** (`--check-config` → OK, 4 sources, 15 directives),
  matching `chronyd -p` (exit 0). Captured as
  `tools/oracle/config-fixtures/valid_ubuntu_default.conf`.
- It exercises `sourcedir`, `confdir`, `ntsdumpdir`, and the `maxsources` pool
  option — none of which chrony-rs *models*, all of which it correctly
  *recognizes* and preserves.

### What this caught

The Ubuntu default was the fixture that exposed `sourcedir` missing from
chrony-rs's recognition set, and the directive-recognition sweep then exposed five
*fabricated* entries (wrong NTS names, `open_commands`, `ntpcache`). Real distro
configs are excellent oracles precisely because they use the long tail of
directives a hand-written test would omit. See `oracle.md` and `version-lineage.md`.

## Not yet witnessed

Debian, RHEL/Fedora, Arch, Alpine, NixOS, FreeBSD, and others ship different
defaults (different pools, `rtconutc`, `hwtimestamp`, NTS enablement). Capturing
them requires those packages; tracked as a `vendor-ecology.md` campaign.
