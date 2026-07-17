//! Address-based access control — a complete port of chrony 4.5 `addrfilt.c`.
//!
//! # What this is
//!
//! chrony decides whether an NTP client (or command client) at a given IP is
//! allowed by walking a radix trie of `allow`/`deny` subnet rules. `addrfilt.c`
//! implements that trie; it is self-contained (its only chrony include is
//! `memory.h`, for allocation Rust does for free), so it ports in full. All 16 of
//! its functions have counterparts here:
//!
//! | chrony `addrfilt.c` | here |
//! |---------------------|------|
//! | `ADF_CreateTable` | [`AuthTable::new`] |
//! | `ADF_Allow` / `ADF_AllowAll` | [`AuthTable::allow`] / [`AuthTable::allow_all`] |
//! | `ADF_Deny` / `ADF_DenyAll` | [`AuthTable::deny`] / [`AuthTable::deny_all`] |
//! | `ADF_IsAllowed` | [`AuthTable::is_allowed`] |
//! | `ADF_IsAnyAllowed` | [`AuthTable::is_any_allowed`] |
//! | `ADF_DestroyTable` | `Drop` (automatic) |
//! | `set_subnet_` / `set_subnet` | [`AuthTable::set_subnet_`] / [`TableNode::set_subnet`] |
//! | `check_ip_in_node` / `is_any_allowed` | [`TableNode::check_ip`] / [`TableNode::any_allowed`] |
//! | `open_node` / `close_node` | [`TableNode::open`] / [`TableNode::close`] |
//! | `get_subnet` / `split_ip6` | [`get_subnet`] / [`split_ip6`] |
//!
//! # Trie shape (from the C, preserved exactly)
//!
//! `NBITS = 4` bits are consumed per level, so each node fans out to 16 children.
//! A node's [`State`] is `Allow`, `Deny`, or `AsParent` (inherit). A lookup walks
//! the address nibble-by-nibble, remembering the most specific explicit state
//! seen; the table starts default-`Deny` (`ADF_CreateTable`). `*All` variants
//! prune (`close`) the subtree so the new state applies uniformly underneath.
//!
//! # Oracle
//!
//! chrony exposes this very table through `chronyc accheck <ip>`. The integration
//! evidence that ports' decisions match real chrony 4.5 lives under
//! `reports/oracle/` and `docs/chronyc-parity.md`; the unit tests below encode the
//! access-control semantics directly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Bits consumed per trie level (chrony's `NBITS`).
const NBITS: u32 = 4;
/// Fan-out per node (`1 << NBITS`).
const TABLE_SIZE: usize = 1 << NBITS;

/// A node's access state (chrony's `State`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Deny,
    Allow,
    /// Inherit the nearest explicit ancestor state.
    AsParent,
}

/// Result of a subnet mutation (chrony's `ADF_Status`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum AdfStatus {
    Success,
    BadSubnet,
}

/// A subnet specifier for `allow`/`deny`: a v4 or v6 address, or `Unspec` (apply
/// to both families, only valid with a zero subnet width — chrony's `IPADDR_UNSPEC`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[non_exhaustive]
pub enum Subnet {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Unspec,
}

/// `split_ip6`: pack 16 address bytes into 4 big-endian 32-bit words.
fn split_ip6(ip: &Ipv6Addr) -> [u32; 4] {
    let o = ip.octets();
    let mut dst = [0u32; 4];
    for (i, w) in dst.iter_mut().enumerate() {
        *w = u32::from_be_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]);
    }
    dst
}

/// `get_subnet`: extract the `NBITS`-wide trie index at bit offset `at`.
fn get_subnet(addr: &[u32], at: u32) -> usize {
    let off = (at / 32) as usize;
    let at = at % 32;
    ((addr[off] >> (32 - NBITS - at)) & ((1 << NBITS) - 1)) as usize
}

/// One trie node (chrony's `TableNode`). Children are owned, so `Drop` is the
/// `ADF_DestroyTable`/`close_node` free path.
#[derive(Debug)]
struct TableNode {
    state: State,
    extended: Option<Vec<TableNode>>,
}

impl TableNode {
    fn new(state: State) -> Self {
        TableNode { state, extended: None }
    }

    /// `open_node`: materialize 16 children defaulting to `AsParent`.
    fn open(&mut self) {
        if self.extended.is_none() {
            self.extended = Some((0..TABLE_SIZE).map(|_| TableNode::new(State::AsParent)).collect());
        }
    }

    /// `close_node`: prune the whole subtree back to this node (Rust frees it).
    fn close(&mut self) {
        self.extended = None;
    }

    /// `set_subnet`: set `new_state` for the subnet `ip/subnet_bits` rooted here.
    /// `ip_len` is the number of 32-bit words in `ip` (1 for v4, 4 for v6).
    fn set_subnet(
        &mut self,
        ip: &[u32],
        ip_len: i32,
        subnet_bits: i32,
        new_state: State,
        delete_children: bool,
    ) -> AdfStatus {
        if subnet_bits < 0 || subnet_bits > 32 * ip_len {
            return AdfStatus::BadSubnet;
        }

        let mut node = self;
        let mut bits_to_go = subnet_bits;
        let mut bits_consumed = 0u32;

        if bits_to_go & (NBITS as i32 - 1) == 0 {
            // Subnet width is a whole number of nibbles: one leaf to set.
            while bits_to_go > 0 {
                let subnet = get_subnet(ip, bits_consumed);
                node.open();
                node = &mut node.extended.as_mut().unwrap()[subnet];
                bits_to_go -= NBITS as i32;
                bits_consumed += NBITS;
            }
            if delete_children {
                node.close();
            }
            node.state = new_state;
        } else {
            // Partial nibble: descend the whole nibbles, then set N siblings.
            while bits_to_go >= NBITS as i32 {
                let subnet = get_subnet(ip, bits_consumed);
                node.open();
                node = &mut node.extended.as_mut().unwrap()[subnet];
                bits_to_go -= NBITS as i32;
                bits_consumed += NBITS;
            }
            // 1 leftover bit -> 8 entries, 2 -> 4, 3 -> 2.
            let n = 1usize << (NBITS - bits_to_go as u32);
            let base = get_subnet(ip, bits_consumed) & !(n - 1);
            debug_assert!(base + n <= TABLE_SIZE);
            node.open();
            let ext = node.extended.as_mut().unwrap();
            for child in ext.iter_mut().skip(base).take(n) {
                if delete_children {
                    child.close();
                }
                child.state = new_state;
            }
        }
        AdfStatus::Success
    }

    /// `check_ip_in_node`: walk `ip`, returning whether the most specific explicit
    /// state along the path is `Allow`.
    fn check_ip(&self, ip: &[u32]) -> bool {
        let mut node = self;
        let mut bits_consumed = 0u32;
        let mut state = State::Deny;
        loop {
            if node.state != State::AsParent {
                state = node.state;
            }
            match &node.extended {
                Some(ext) => {
                    let subnet = get_subnet(ip, bits_consumed);
                    node = &ext[subnet];
                    bits_consumed += NBITS;
                }
                None => break,
            }
        }
        matches!(state, State::Allow)
    }

    /// `is_any_allowed`: whether any leaf under this node resolves to `Allow`.
    fn any_allowed(&self, parent: State) -> bool {
        let state = if self.state != State::AsParent {
            self.state
        } else {
            parent
        };
        match &self.extended {
            Some(ext) => ext.iter().any(|c| c.any_allowed(state)),
            None => state == State::Allow,
        }
    }
}

/// The access-control table (chrony's `ADF_AuthTableInst`): one trie per family.
#[derive(Debug)]
pub struct AuthTable {
    base4: TableNode,
    base6: TableNode,
}

impl Default for AuthTable {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthTable {
    /// `ADF_CreateTable`: a table that denies everything by default.
    pub fn new() -> Self {
        AuthTable {
            base4: TableNode::new(State::Deny),
            base6: TableNode::new(State::Deny),
        }
    }

    /// `set_subnet_`: family dispatch for a subnet mutation.
    fn set_subnet_(
        &mut self,
        subnet: Subnet,
        subnet_bits: i32,
        new_state: State,
        delete_children: bool,
    ) -> AdfStatus {
        match subnet {
            Subnet::V4(ip) => {
                let words = [u32::from(ip)];
                self.base4.set_subnet(&words, 1, subnet_bits, new_state, delete_children)
            }
            Subnet::V6(ip) => {
                let words = split_ip6(&ip);
                self.base6.set_subnet(&words, 4, subnet_bits, new_state, delete_children)
            }
            Subnet::Unspec => {
                // Applies to both families; only a zero width is meaningful.
                if subnet_bits != 0 {
                    return AdfStatus::BadSubnet;
                }
                let z4 = [0u32];
                let z6 = [0u32; 4];
                if self.base4.set_subnet(&z4, 1, 0, new_state, delete_children) == AdfStatus::Success
                    && self.base6.set_subnet(&z6, 4, 0, new_state, delete_children)
                        == AdfStatus::Success
                {
                    AdfStatus::Success
                } else {
                    AdfStatus::BadSubnet
                }
            }
        }
    }

    /// `ADF_Allow`: allow the subnet (leaving any finer rules underneath intact).
    pub fn allow(&mut self, subnet: Subnet, subnet_bits: i32) -> AdfStatus {
        self.set_subnet_(subnet, subnet_bits, State::Allow, false)
    }

    /// `ADF_AllowAll`: allow the subnet and prune any finer rules under it.
    pub fn allow_all(&mut self, subnet: Subnet, subnet_bits: i32) -> AdfStatus {
        self.set_subnet_(subnet, subnet_bits, State::Allow, true)
    }

    /// `ADF_Deny`: deny the subnet (leaving any finer rules underneath intact).
    pub fn deny(&mut self, subnet: Subnet, subnet_bits: i32) -> AdfStatus {
        self.set_subnet_(subnet, subnet_bits, State::Deny, false)
    }

    /// `ADF_DenyAll`: deny the subnet and prune any finer rules under it.
    pub fn deny_all(&mut self, subnet: Subnet, subnet_bits: i32) -> AdfStatus {
        self.set_subnet_(subnet, subnet_bits, State::Deny, true)
    }

    /// `ADF_IsAllowed`: whether a concrete address is permitted.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.base4.check_ip(&[u32::from(ip)]),
            IpAddr::V6(ip) => self.base6.check_ip(&split_ip6(&ip)),
        }
    }

    /// `ADF_IsAnyAllowed`: whether any address of the given family is permitted.
    /// `v6 = false` checks the IPv4 trie, `true` the IPv6 trie.
    pub fn is_any_allowed(&self, v6: bool) -> bool {
        let base = if v6 { &self.base6 } else { &self.base4 };
        base.any_allowed(State::AsParent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Subnet {
        Subnet::V4(s.parse().unwrap())
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a [`Subnet`] from an address string, choosing the family by parse.
    fn subnet(s: &str) -> Subnet {
        match s.parse::<IpAddr>().unwrap() {
            IpAddr::V4(a) => Subnet::V4(a),
            IpAddr::V6(a) => Subnet::V6(a),
        }
    }

    /// Build each scenario's table from the same op script the C oracle ran (`/tmp/nadf`).
    fn scenario(label: &str) -> AuthTable {
        let mut t = AuthTable::new();
        match label {
            "s1" => {
                t.allow(subnet("10.0.0.0"), 8);
                t.allow(subnet("192.168.1.0"), 24);
            }
            "s2" => {
                t.allow(Subnet::V4("0.0.0.0".parse().unwrap()), 0);
                t.deny(subnet("192.168.0.0"), 16);
                t.allow(subnet("192.168.1.0"), 24);
            }
            "s3" => {
                t.allow(subnet("10.0.0.0"), 8);
                t.allow(subnet("10.1.0.0"), 16);
                t.deny_all(subnet("10.0.0.0"), 8);
            }
            "s4" => {
                t.allow(subnet("2001:db8::"), 32);
                t.deny(subnet("2001:db8:1::"), 48);
            }
            other => panic!("unknown scenario {other}"),
        }
        t
    }

    #[test]
    fn matches_real_addrfilt_c_over_battery() {
        // Differential test vs the REAL compiled addrfilt.c (subnet trie) over four scenarios --
        // subnet allow, allow-all + overlapping deny/allow, deny_all pruning, and IPv6 -- with a
        // 15-address battery. Upgrades the ADF port from live-witnessed to compiled-oracle-backed.
        let v = include_str!("../../../research/oracle/addrfilt-c-vectors.txt");
        let field = |l: &str, k: &str| -> String {
            l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap().to_string()
        };

        let mut tables = std::collections::HashMap::new();
        for label in ["s1", "s2", "s3", "s4"] {
            tables.insert(label, scenario(label));
        }

        for l in v.lines() {
            if let Some(rest) = l.strip_prefix("Q ") {
                let label = rest.split_whitespace().next().unwrap();
                let addr = field(l, "ip");
                let allowed = field(l, "allowed") == "1";
                let t = &tables[label];
                assert_eq!(t.is_allowed(ip(&addr)), allowed, "{label} ip={addr}");
            } else if let Some(rest) = l.strip_prefix("ANY ") {
                // "ANY s1 v4=1 v6=0" -- family INET4 then INET6.
                let label = rest.split_whitespace().next().unwrap();
                let t = &tables[label];
                assert_eq!(t.is_any_allowed(false), field(l, "v4") == "1", "{label} any v4");
                assert_eq!(t.is_any_allowed(true), field(l, "v6") == "1", "{label} any v6");
            }
        }

        // Scenario 5: out-of-range subnet bits are rejected (BadSubnet), matching the oracle.
        let mut t = AuthTable::new();
        assert_eq!(t.allow(subnet("10.0.0.0"), 33), AdfStatus::BadSubnet);
        assert_eq!(t.allow(subnet("2001:db8::"), 129), AdfStatus::BadSubnet);
    }

    #[test]
    fn default_table_denies_everything() {
        let t = AuthTable::new();
        assert!(!t.is_allowed(ip("10.0.0.1")));
        assert!(!t.is_allowed(ip("::1")));
        assert!(!t.is_any_allowed(false));
        assert!(!t.is_any_allowed(true));
    }

    #[test]
    fn allow_subnet_then_longest_prefix_wins() {
        let mut t = AuthTable::new();
        assert_eq!(t.allow(v4("10.0.0.0"), 8), AdfStatus::Success);
        assert!(t.is_allowed(ip("10.1.2.3")));
        assert!(t.is_allowed(ip("10.255.255.255")));
        assert!(!t.is_allowed(ip("11.0.0.1")));

        // A more specific deny inside the allowed /8 overrides it.
        assert_eq!(t.deny(v4("10.1.0.0"), 16), AdfStatus::Success);
        assert!(!t.is_allowed(ip("10.1.2.3")));
        assert!(t.is_allowed(ip("10.2.3.4")));
        assert!(t.is_any_allowed(false));
    }

    #[test]
    fn non_nibble_aligned_prefix_sets_correct_range() {
        // /17 is not a multiple of NBITS(4): exercises the multi-entry branch.
        let mut t = AuthTable::new();
        assert_eq!(t.allow(v4("192.168.0.0"), 17), AdfStatus::Success);
        assert!(t.is_allowed(ip("192.168.0.1")));
        assert!(t.is_allowed(ip("192.168.127.255")));
        assert!(!t.is_allowed(ip("192.168.128.0")));
        assert!(!t.is_allowed(ip("192.168.200.1")));
    }

    #[test]
    fn allow_all_prunes_finer_rules() {
        let mut t = AuthTable::new();
        t.allow(v4("10.0.0.0"), 8);
        t.deny(v4("10.1.0.0"), 16);
        assert!(!t.is_allowed(ip("10.1.2.3")));
        // AllowAll over the /8 wipes the nested deny.
        t.allow_all(v4("10.0.0.0"), 8);
        assert!(t.is_allowed(ip("10.1.2.3")));
    }

    #[test]
    fn unspec_allow_opens_both_families_only_at_zero_width() {
        let mut t = AuthTable::new();
        assert_eq!(t.allow(Subnet::Unspec, 0), AdfStatus::Success);
        assert!(t.is_allowed(ip("8.8.8.8")));
        assert!(t.is_allowed(ip("2001:db8::1")));
        // Non-zero width with Unspec is rejected.
        assert_eq!(t.allow(Subnet::Unspec, 8), AdfStatus::BadSubnet);
    }

    #[test]
    fn out_of_range_subnet_width_is_bad() {
        let mut t = AuthTable::new();
        assert_eq!(t.allow(v4("10.0.0.0"), 33), AdfStatus::BadSubnet);
        assert_eq!(t.allow(v4("10.0.0.0"), -1), AdfStatus::BadSubnet);
        assert_eq!(t.allow(Subnet::V6("2001:db8::".parse().unwrap()), 129), AdfStatus::BadSubnet);
    }

    #[test]
    fn matches_live_chrony_accheck_oracle() {
        // The exact rule set fed to chrony 4.5; decisions captured via
        // `chronyc accheck` (reports/oracle/chronyc-live/accheck.raw.out). Applying
        // the same rules in order here must reproduce chrony's allow/deny verdicts.
        let mut t = AuthTable::new();
        t.allow(v4("10.0.0.0"), 8);
        t.deny(v4("10.1.0.0"), 16);
        t.allow(v4("192.168.0.0"), 17);
        t.deny(v4("10.1.2.0"), 24);
        t.allow(v4("10.1.2.128"), 25);

        let oracle: &[(&str, bool)] = &[
            ("10.0.0.1", true),
            ("10.1.2.3", false),
            ("10.1.2.200", true),
            ("10.2.3.4", true),
            ("11.0.0.1", false),
            ("192.168.0.1", true),
            ("192.168.127.255", true),
            ("192.168.128.1", false),
            ("8.8.8.8", false),
        ];
        for (addr, allowed) in oracle {
            assert_eq!(t.is_allowed(ip(addr)), *allowed, "accheck mismatch for {addr}");
        }
    }

    #[test]
    fn ipv6_prefix_matching() {
        let mut t = AuthTable::new();
        t.allow(Subnet::V6("2001:db8::".parse().unwrap()), 32);
        assert!(t.is_allowed(ip("2001:db8::1")));
        assert!(t.is_allowed(ip("2001:db8:ffff::1")));
        assert!(!t.is_allowed(ip("2001:db9::1")));
        assert!(t.is_any_allowed(true));
        assert!(!t.is_any_allowed(false));
    }
}
