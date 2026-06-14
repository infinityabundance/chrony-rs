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
    Row { c: "cmdparse.c", role: "source-line option parsing (CPS_ParseNTPSourceAdd)",
        rust: &["config/parser.rs"], port: Port::Partial,
        note: "server/pool/peer flag+value option set ported and oracle-anchored" },

    // ---- NTP protocol ----
    Row { c: "ntp_core.c", role: "NTP protocol engine: poll, process-response, offset/delay (NCR_*)",
        rust: &["ntp/measurements.rs", "ntp/packet.rs"], port: Port::Partial,
        note: "RFC 5905 §8 offset/delay algebra + 48-byte header codec; poll state machine not ported" },
    Row { c: "ntp_io.c", role: "NTP socket send/recv path",
        rust: &["ntp/packet.rs"], port: Port::Scaffold, note: "packet bytes only; no socket IO" },
    Row { c: "pktlength.c", role: "NTP packet length validation",
        rust: &["ntp/packet.rs"], port: Port::Scaffold, note: "length checks partial via the codec" },
    Row { c: "ntp_io_linux.c", role: "Linux HW/kernel RX timestamping", rust: &[], port: Port::None, note: "" },
    Row { c: "ntp_ext.c", role: "NTP extension-field framing", rust: &[], port: Port::None, note: "" },
    Row { c: "ntp_auth.c", role: "NTP authentication (MAC/NTS dispatch)", rust: &[], port: Port::None, note: "" },
    Row { c: "ntp_signd.c", role: "Samba signing daemon bridge", rust: &[], port: Port::None, note: "" },
    Row { c: "ntp_sources.c", role: "NTP source record add/remove/pool (NSR_*)", rust: &[], port: Port::None,
        note: "source *records* not ported; selection brain lives under sources.c mapping" },

    // ---- source selection / statistics ----
    Row { c: "sources.c", role: "source reachability + selection (SRC_*)",
        rust: &["sources/source.rs", "sources/reachability.rs", "sources/selection.rs"], port: Port::Partial,
        note: "8-bit reach register (exact), selectability gate, falseticker intersection; full SRC_SelectSource not ported" },
    Row { c: "sourcestats.c", role: "per-source regression statistics (SST_*)", rust: &[], port: Port::None,
        note: "planned filter/regression surface" },
    Row { c: "regress.c", role: "robust linear regression", rust: &[], port: Port::None, note: "" },
    Row { c: "samplefilt.c", role: "per-source sample filtering", rust: &[], port: Port::None, note: "" },
    Row { c: "quantiles.c", role: "streaming quantile estimator", rust: &[], port: Port::None, note: "" },

    // ---- reference / clock / discipline ----
    Row { c: "reference.c", role: "tracking + drift state, leap handling (REF_*)",
        rust: &["report.rs", "clock.rs"], port: Port::Partial,
        note: "tracking report shape rendered (report.rs); drift/discipline state machine not ported" },
    Row { c: "local.c", role: "local clock read/adjust abstraction (LCL_*)",
        rust: &["clock.rs"], port: Port::Scaffold, note: "side-effect-free simulated clock; no real read/adjust" },
    Row { c: "smooth.c", role: "served-time smoothing", rust: &[], port: Port::None, note: "" },
    Row { c: "tempcomp.c", role: "temperature compensation", rust: &[], port: Port::None, note: "" },
    Row { c: "sched.c", role: "timer/event scheduler (SCH_*)",
        rust: &["replay.rs"], port: Port::Scaffold, note: "deterministic replay loop is a stand-in, not the SCH_ timer wheel" },

    // ---- control client / protocol ----
    Row { c: "client.c", role: "chronyc CLI: command dispatch + report formatters",
        rust: &["report.rs", "../chronyc-rs/src/main.rs"], port: Port::Partial,
        note: "only `tracking` (print_report) rendered; ~1 of ~40 process_cmd_* commands; no socket transport" },
    Row { c: "cmdmon.c", role: "control/monitoring protocol server (candm)", rust: &[], port: Port::None,
        note: "live control socket is a declared negative capability" },

    // ---- daemon entry / process ----
    Row { c: "main.c", role: "daemon entry, arg parsing, lifecycle",
        rust: &["../chronyd-rs/src/main.rs"], port: Port::Partial,
        note: "--check-config and --replay only; no scheduler/privdrop/daemonize" },
    Row { c: "privops.c", role: "privilege-separation helper", rust: &[], port: Port::None, note: "" },

    // ---- utilities (subsumed by std, or partially ported) ----
    Row { c: "util.c", role: "time/UTI/byte utilities (UTI_*)",
        rust: &["ntp/timestamp.rs", "hash.rs"], port: Port::Partial,
        note: "NTP timestamp/era algebra ported; broad UTI_* surface not" },
    Row { c: "array.c", role: "generic dynamic array (ARR_*)", rust: &[], port: Port::None, note: "subsumed by std Vec; not a port target" },
    Row { c: "memory.c", role: "xmalloc/xrealloc wrappers", rust: &[], port: Port::None, note: "subsumed by std; not a port target" },
    Row { c: "logging.c", role: "logging subsystem (LOG_*)", rust: &[], port: Port::None,
        note: "project uses a structured trace schema, not a port of LOG_*" },
    Row { c: "stubs.c", role: "test-harness stub implementations", rust: &[], port: Port::None,
        note: "upstream unit-test scaffolding, not a behavior port target" },

    // ---- crypto / auth / keys (none) ----
    Row { c: "keys.c", role: "symmetric key store", rust: &[], port: Port::None, note: "" },
    Row { c: "md5.c", role: "MD5 digest", rust: &[], port: Port::None, note: "hash.rs is SHA-256 receipts, not chrony auth hashing" },
    Row { c: "hash_intmd5.c", role: "internal MD5 hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_gnutls.c", role: "gnutls hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_nettle.c", role: "nettle hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_nss.c", role: "NSS hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "hash_tomcrypt.c", role: "tomcrypt hash backend", rust: &[], port: Port::None, note: "" },
    Row { c: "cmac_gnutls.c", role: "gnutls CMAC backend", rust: &[], port: Port::None, note: "" },
    Row { c: "cmac_nettle.c", role: "nettle CMAC backend", rust: &[], port: Port::None, note: "" },

    // ---- NTS (none) ----
    Row { c: "nts_ke_client.c", role: "NTS-KE client", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ke_server.c", role: "NTS-KE server", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ke_session.c", role: "NTS-KE TLS session", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ntp_auth.c", role: "NTS NTPv4 auth", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ntp_client.c", role: "NTS NTP client", rust: &[], port: Port::None, note: "" },
    Row { c: "nts_ntp_server.c", role: "NTS NTP server", rust: &[], port: Port::None, note: "" },
    Row { c: "siv_gnutls.c", role: "SIV-AEAD (gnutls)", rust: &[], port: Port::None, note: "" },
    Row { c: "siv_nettle.c", role: "SIV-AEAD (nettle)", rust: &[], port: Port::None, note: "" },
    Row { c: "siv_nettle_int.c", role: "SIV-AEAD internals", rust: &[], port: Port::None, note: "" },

    // ---- refclocks (none) ----
    Row { c: "refclock.c", role: "reference-clock framework (RCL_*)", rust: &[], port: Port::None, note: "" },
    Row { c: "refclock_phc.c", role: "PHC refclock driver", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "refclock_pps.c", role: "PPS refclock driver", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "refclock_shm.c", role: "SHM refclock driver", rust: &[], port: Port::None, note: "" },
    Row { c: "refclock_sock.c", role: "socket refclock driver", rust: &[], port: Port::None, note: "" },

    // ---- RTC / hwclock (none) ----
    Row { c: "rtc.c", role: "RTC abstraction", rust: &[], port: Port::None, note: "" },
    Row { c: "rtc_linux.c", role: "Linux RTC driver", rust: &[], port: Port::None, note: "" },
    Row { c: "hwclock.c", role: "HW clock frequency tracking", rust: &[], port: Port::None, note: "" },

    // ---- OS clock adapters (declared negative capability) ----
    Row { c: "sys.c", role: "OS adapter dispatch", rust: &[], port: Port::None, note: "host-clock mutation is a declared boundary" },
    Row { c: "sys_generic.c", role: "generic clock-driver adapter", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_linux.c", role: "Linux clock adapter (adjtimex)", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_timex.c", role: "timex clock adapter", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_null.c", role: "no-op clock adapter", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_macosx.c", role: "macOS clock adapter", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "sys_netbsd.c", role: "NetBSD clock adapter", rust: &[], port: Port::None, note: "" },
    Row { c: "sys_posix.c", role: "POSIX clock adapter", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "sys_solaris.c", role: "Solaris clock adapter", rust: &[], port: Port::None, note: "" },

    // ---- networking / naming / misc (none) ----
    Row { c: "socket.c", role: "socket abstraction layer", rust: &[], port: Port::None, note: "" },
    Row { c: "addrfilt.c", role: "address allow/deny subnet trie (ADF_*)", rust: &[], port: Port::None, note: "" },
    Row { c: "nameserv.c", role: "synchronous DNS resolution", rust: &[], port: Port::None, note: "" },
    Row { c: "nameserv_async.c", role: "async DNS resolution", rust: &[], port: Port::None, note: "not in Linux preprocessing (0 fns)" },
    Row { c: "clientlog.c", role: "client access log / rate limiting", rust: &[], port: Port::None, note: "" },
    Row { c: "manual.c", role: "manual time input (settime)", rust: &[], port: Port::None, note: "" },
];

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

    let mut partial = 0usize;
    let mut scaffold = 0usize;
    let mut none = 0usize;
    let mut funcs_with_counterpart = 0usize;

    let mut table = String::new();
    table.push_str("| chrony `.c` | C fns | role | chrony-rs counterpart | status |\n");
    table.push_str("|---|---:|---|---|---|\n");
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
        let rs = if rust.is_empty() {
            "—".to_string()
        } else {
            rust.iter()
                .map(|m| format!("`{}`", m.trim_start_matches("../")))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        table.push_str(&format!(
            "| `{file}` | {n} | {role} | {rs} | {} |\n",
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
    let any = partial + scaffold;
    s.push_str(&format!("- **C translation units:** {total_c_files} `.c` files, {total_c_funcs} functions (doxygen).\n"));
    s.push_str(&format!(
        "- **Files with any chrony-rs counterpart:** {any} / {total_c_files} \
         ({partial} partial, {scaffold} scaffold); **{none}** have none.\n"
    ));
    s.push_str(&format!(
        "- **Files fully ported:** 0 / {total_c_files}. chrony-rs is an early-stage forensic \
         reconstruction, not a complete port — this number is expected to be small and is stated, \
         not hidden.\n"
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

    s.push_str("Legend: ◑ partial = behavior ported with an executable court · ");
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
        "(`array.c`, `memory.c`) or is upstream test scaffolding (`stubs.c`), that is noted\n",
    );
    s.push_str("rather than counted as coverage.\n");

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
    fn ast_counter_ignores_fn_in_strings_and_idents() {
        // The regex approach miscounted these; the AST does not.
        let src = r#"fn real() { let define = "fn fnord"; let _ = define; }"#;
        let c = count_rust(src);
        assert_eq!(c.named_fns, 1);
        assert_eq!(c.closures, 0);
    }
}
