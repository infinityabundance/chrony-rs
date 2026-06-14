# Doxygen source archaeology (chrony 4.5)

The C chrony source is the primary oracle for *structure*, not just behavior.
Doxygen gives a navigable index of every function, file, and call relationship,
which is how the directive and source-option tables in `chrony-rs` were extracted
exactly rather than guessed.

The generated Doxygen output is **large and not committed** (doctrine: heavy
evidence stays reproducible, not vendored). This directory records how to
regenerate it and what it was used to extract.

## Regenerate

```sh
curl -fsSLO https://chrony-project.org/releases/chrony-4.5.tar.gz
tar xzf chrony-4.5.tar.gz && cd chrony-4.5
doxygen -g /tmp/chrony.doxyfile
sed -i 's#^OUTPUT_DIRECTORY .*#OUTPUT_DIRECTORY = /tmp/chrony-doxygen#;
        s#^GENERATE_HTML .*#GENERATE_HTML = YES#;
        s#^GENERATE_XML .*#GENERATE_XML = YES#;
        s#^EXTRACT_ALL .*#EXTRACT_ALL = YES#;
        s#^EXTRACT_STATIC .*#EXTRACT_STATIC = YES#;
        s#^OPTIMIZE_OUTPUT_FOR_C .*#OPTIMIZE_OUTPUT_FOR_C = YES#' /tmp/chrony.doxyfile
doxygen /tmp/chrony.doxyfile     # -> /tmp/chrony-doxygen/{html,xml}
```

This indexes ~310 entities; `conf.c` alone exposes ~135 functions.

## What it was used to extract (see ../source-archaeology/)

| Artifact | chrony source | Used for |
|----------|---------------|----------|
| 93 config directives | `conf.c` command dispatch (`strcasecmp(command, …)`) | `KNOWN_DIRECTIVES` recognition set |
| source flag options | `cmdparse.c::CPS_ParseNTPSourceAdd` boolean branches | `SOURCE_FLAG_OPTS` |
| source value options | `cmdparse.c::CPS_ParseNTPSourceAdd` value branches | `SOURCE_VALUE_OPTS` |
| select options | `cmdparse.c::CPS_GetSelectOption` | source select flags |
| comment chars `# % ! ;` | `conf.c` line handling | lexer comment rule |

## Why C-vs-Rust diffing matters

Probing the oracle binary (`chronyd -p`) tells you *whether* a directive is
accepted; the C source tells you the *complete set* and the *exact arity/branch*
for each option. The two together caught both fabricated entries (oracle) and
missing entries (source diff) in `chrony-rs`'s tables — eleven directives were
missing until the `conf.c` dispatch was diffed against `KNOWN_DIRECTIVES`.
