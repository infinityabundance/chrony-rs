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

## Full-tree inventory for the port-parity matrix

The whole-tree function inventory that backs
[`docs/generated/port-parity.md`](../../docs/port-parity.md) is committed as
[`chrony-4.5-c-inventory.tsv`](chrony-4.5-c-inventory.tsv) (70 `.c` files, 1373
functions), pinned to chrony commit `120dfb8b36b942c31ddfc0220ca1475159ac5031`
(tag 4.5, mirror `github.com/mlichvar/chrony`). Regenerate it with:

```sh
git clone --depth 1 --branch 4.5 https://github.com/mlichvar/chrony /tmp/chrony-src
cat > /tmp/Doxyfile.c <<'EOF'
INPUT = /tmp/chrony-src
FILE_PATTERNS = *.c *.h
RECURSIVE = NO
EXCLUDE_PATTERNS = */test/*
OPTIMIZE_OUTPUT_FOR_C = YES
EXTRACT_ALL = YES
EXTRACT_STATIC = YES
GENERATE_HTML = NO
GENERATE_XML = YES
XML_OUTPUT = /tmp/cxml
EOF
doxygen /tmp/Doxyfile.c
# then reduce /tmp/cxml/*_8c.xml (memberdef kind="function") -> the TSV.
```

### Rust side is NOT doxygen — and why

Doxygen has no Rust frontend; run over the Rust crates (`EXTENSION_MAPPING
rs=C++`) it misparses `fn`/`impl`/generics and emits anonymous, incomplete members
(e.g. ~15 unnamed "functions" for `report.rs`). It is therefore **not** used for
any Rust count. The authoritative Rust inventory is taken natively from the `syn`
AST in `xtask/src/parity.rs` (named functions + closures). See the limitation
notice in `docs/port-parity.md`.

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
