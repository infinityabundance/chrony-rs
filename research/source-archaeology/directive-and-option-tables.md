# chrony 4.5 directive & source-option tables (extracted from C)

Provenance for the recognition/option tables in `chrony-rs-core`. Each set is
extracted from chrony 4.5 source and cross-witnessed with `chronyd -p`. See
`../doxygen/README.md` for the indexing method and `../../docs/source-archaeology.md`
for the behavior map.

## Config directives — `conf.c` dispatch (93)

The complete `strcasecmp(command, "…")` set in `CNF_ParseLine`. Full list:
`chrony-4.5-conf.c-directives.txt` in this directory; mirrored in
`chrony-rs-core::config::known_directives()`.

Two correction passes, each from a different oracle:

- **Oracle (`chronyd -p`) removed 5 fabricated entries** that chrony rejects:
  `ntsca`, `ntscert`, `ntskey`, `open_commands`, `ntpcache`.
- **Source diff (`conf.c` vs `KNOWN_DIRECTIVES`) added 11 missing entries**:
  `bindacqdevice`, `bindcmddevice`, `binddevice`, `clockprecision`, `commandkey`,
  `generatecommandkey`, `hwtstimeout`, `linux_freq_scale`, `linux_hz`,
  `nosystemcert`, `ptpport`.

`commandkey`/`generatecommandkey`/`linux_hz`/`linux_freq_scale` are legacy/compat
directives chrony still *recognizes* (it warns or ignores). Recognition parity
includes them; modeling does not.

## Source options — `cmdparse.c::CPS_ParseNTPSourceAdd`

`server`/`pool`/`peer` options. Unknown option (or value option missing its value)
makes chrony's parser `return 0`, reported by `conf.c` as
`Could not parse <kw> directive`.

### Flag options (no value), incl. `CPS_GetSelectOption`

```
auto_offline burst copy iburst offline nts xleave        (boolean branches)
noselect prefer require trust                              (CPS_GetSelectOption)
```

### Value options (consume one word)

```
certset key asymmetry extfield filter maxdelay maxdelayratio maxdelaydevratio
maxdelayquant maxpoll maxsamples maxsources mindelay minpoll minsamples minstratum
ntsport offset port polltarget presend version
```

## Comment characters — `conf.c`

A line is a comment only when its first non-whitespace character is one of
`# % ! ;`. Not mid-line. Witnessed and encoded in `config::lexer::COMMENT_CHARS`.
