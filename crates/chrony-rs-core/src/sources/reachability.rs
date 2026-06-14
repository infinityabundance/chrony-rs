//! Source reachability register.
//!
//! chrony tracks each source's recent responsiveness in a small shift register
//! (`reachability` in `sources.c`, `SRC_UpdateReachability`). On every poll the
//! register shifts left by one and the new low bit records whether *that* poll
//! got a usable response. A source is "reachable" while any bit is set; it goes
//! unreachable only after `SOURCE_REACH_BITS` consecutive misses clear the whole
//! register.
//!
//! This is one of the most exactly-specified pieces of chrony behavior, so it is
//! reconstructed precisely:
//!
//!   * width is **8 bits** (`SOURCE_REACH_BITS = 8`),
//!   * register is masked to 8 bits after each shift,
//!   * reachable ⇔ register != 0,
//!   * the classic operator-visible octal display (e.g. `377` = all 8 set) comes
//!     straight from this register.
//!
//! The "% reachability" chrony reports is the popcount over the window.

/// chrony's `SOURCE_REACH_BITS`.
pub const REACH_BITS: u32 = 8;

const REACH_MASK: u16 = (1 << REACH_BITS) - 1; // 0xFF

/// An 8-bit reachability shift register.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Reachability {
    /// Only the low 8 bits are meaningful; kept in a u16 so the pre-mask shift has
    /// room and the masking step is observable rather than implicit in the type.
    reg: u16,
}

impl Reachability {
    /// A fresh, fully-unreachable register (no polls recorded yet).
    pub const fn new() -> Self {
        Reachability { reg: 0 }
    }

    /// Record the outcome of one poll: shift left, OR in 1 on success, then mask
    /// back to 8 bits. This mirrors `SRC_UpdateReachability` exactly.
    pub fn register(&mut self, got_response: bool) {
        self.reg <<= 1;
        if got_response {
            self.reg |= 1;
        }
        self.reg &= REACH_MASK;
    }

    /// True while any bit is set — chrony's definition of reachable.
    pub fn is_reachable(self) -> bool {
        self.reg != 0
    }

    /// The raw 8-bit register value (low byte). Useful for the octal display.
    pub fn bits(self) -> u8 {
        self.reg as u8
    }

    /// chrony's operator-facing reachability register is printed in **octal**
    /// (e.g. `377`, `017`). Reproduced here for `chronyc sources` parity later.
    pub fn octal(self) -> String {
        format!("{:o}", self.reg)
    }

    /// Reachability as a percentage over the 8-poll window: popcount / 8 * 100,
    /// matching how chrony summarizes recent success.
    pub fn percentage(self) -> u32 {
        (self.reg.count_ones() * 100) / REACH_BITS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_register_is_unreachable() {
        // CHRONY.SOURCE.6 (boundary) — nothing heard yet.
        let r = Reachability::new();
        assert!(!r.is_reachable());
        assert_eq!(r.bits(), 0);
        assert_eq!(r.percentage(), 0);
    }

    #[test]
    fn one_success_makes_reachable_with_low_bit() {
        // CHRONY.SOURCE.2
        let mut r = Reachability::new();
        r.register(true);
        assert!(r.is_reachable());
        assert_eq!(r.bits(), 0b0000_0001);
        assert_eq!(r.octal(), "1");
    }

    #[test]
    fn eight_successes_fill_the_register() {
        let mut r = Reachability::new();
        for _ in 0..8 {
            r.register(true);
        }
        assert_eq!(r.bits(), 0xFF);
        assert_eq!(r.octal(), "377"); // the familiar "all reachable" display
        assert_eq!(r.percentage(), 100);
    }

    #[test]
    fn register_is_masked_to_eight_bits() {
        // Shifting past 8 bits must drop the high history, not accumulate it.
        let mut r = Reachability::new();
        for _ in 0..12 {
            r.register(true);
        }
        assert_eq!(r.bits(), 0xFF, "must not exceed 8 bits of history");
    }

    #[test]
    fn becomes_unreachable_after_eight_consecutive_misses() {
        // CHRONY.SOURCE.6 — a reachable source decays to unreachable only after the
        // whole window of misses, not on the first one.
        let mut r = Reachability::new();
        r.register(true);
        // Seven misses: the single success bit shifts up but is still in-window.
        for i in 0..7 {
            r.register(false);
            assert!(r.is_reachable(), "still reachable after {} miss(es)", i + 1);
        }
        // Eighth miss shifts the last success bit out of the 8-bit window.
        r.register(false);
        assert!(!r.is_reachable(), "unreachable after 8 consecutive misses");
    }

    #[test]
    fn percentage_counts_set_bits() {
        let mut r = Reachability::new();
        r.register(true);
        r.register(false);
        r.register(true);
        r.register(false);
        // bits = 0b1010 → 2 of 8 → 25%.
        assert_eq!(r.percentage(), 25);
    }
}
