//! Mismatch confirmation: a mismatch becomes a divergence only after it has
//! been seen in `confirmations` consecutive checks spanning at least `grace`.
//! This is what separates "sync in flight" from "diverged" without an event
//! bus on the Go side.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// (pair, collection, mechanism, docID) identifies one mismatch; the pair is
/// `"<node a>|<node b>"` with a < b.
pub type Key = (String, String, &'static str, String);

struct Pending {
    first_seen: Instant,
    count: u32,
    emitted: bool,
}

pub struct Confirmer {
    confirmations: u32,
    grace: Duration,
    pending: HashMap<Key, Pending>,
}

impl Confirmer {
    pub fn new(confirmations: u32, grace: Duration) -> Self {
        Self {
            confirmations,
            grace,
            pending: HashMap::new(),
        }
    }

    /// Feed one check's mismatches. Returns the keys that just became
    /// confirmed divergences, with their latest detail and check count.
    /// A key absent from `mismatches` is cleared, unless `frozen` says its
    /// pair was not eligible this check (a member down or in grace): frozen
    /// keys are neither counted nor cleared, and any of them present in
    /// `mismatches` are ignored.
    pub fn observe<D>(
        &mut self,
        now: Instant,
        mismatches: Vec<(Key, D)>,
        frozen: impl Fn(&Key) -> bool,
    ) -> Vec<(Key, D, u32)> {
        let seen: HashSet<&Key> = mismatches.iter().map(|(k, _)| k).collect();
        self.pending.retain(|k, _| seen.contains(k) || frozen(k));
        let mut confirmed = Vec::new();
        for (key, detail) in mismatches {
            if frozen(&key) {
                continue;
            }
            let p = self.pending.entry(key.clone()).or_insert(Pending {
                first_seen: now,
                count: 0,
                emitted: false,
            });
            p.count += 1;
            if !p.emitted
                && p.count >= self.confirmations
                && now.duration_since(p.first_seen) >= self.grace
            {
                p.emitted = true;
                confirmed.push((key, detail, p.count));
            }
        }
        confirmed
    }

    /// Mismatches seen but not (yet) confirmed.
    pub fn pending(&self) -> usize {
        self.pending.values().filter(|p| !p.emitted).count()
    }

    /// Confirmed divergences whose mismatch is still present.
    pub fn unresolved(&self) -> usize {
        self.pending.values().filter(|p| p.emitted).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> Key {
        ("a|b".to_string(), "Users".to_string(), "M3", id.to_string())
    }

    fn never(_: &Key) -> bool {
        false
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn confirms_after_r_consecutive_checks() {
        let mut c = Confirmer::new(3, secs(0));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), 1)], never).is_empty());
        assert!(c
            .observe(t0 + secs(1), vec![(key("a"), 2)], never)
            .is_empty());
        let out = c.observe(t0 + secs(2), vec![(key("a"), 3)], never);
        assert_eq!(out, vec![(key("a"), 3, 3)]);
        assert!(
            c.observe(t0 + secs(3), vec![(key("a"), 4)], never)
                .is_empty(),
            "no re-emit"
        );
    }

    #[test]
    fn grace_window_delays_confirmation() {
        let mut c = Confirmer::new(1, secs(10));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), ())], never).is_empty());
        assert!(c
            .observe(t0 + secs(5), vec![(key("a"), ())], never)
            .is_empty());
        assert_eq!(
            c.observe(t0 + secs(10), vec![(key("a"), ())], never).len(),
            1
        );
    }

    #[test]
    fn a_clear_check_resets_the_count() {
        let mut c = Confirmer::new(2, secs(0));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), ())], never).is_empty());
        assert!(c.observe::<()>(t0 + secs(1), Vec::new(), never).is_empty());
        assert_eq!(c.pending(), 0);
        assert!(c
            .observe(t0 + secs(2), vec![(key("a"), ())], never)
            .is_empty());
        assert_eq!(
            c.observe(t0 + secs(3), vec![(key("a"), ())], never).len(),
            1
        );
    }

    #[test]
    fn unresolved_counts_emitted_mismatches_still_present() {
        let mut c = Confirmer::new(1, secs(0));
        let t0 = Instant::now();
        assert_eq!(c.observe(t0, vec![(key("a"), ())], never).len(), 1);
        assert_eq!(c.unresolved(), 1);
        c.observe::<()>(t0 + secs(1), Vec::new(), never);
        assert_eq!(c.unresolved(), 0);
    }

    /// A frozen key (its pair ineligible this check) keeps its count when
    /// absent and gains nothing when present; other keys proceed normally.
    #[test]
    fn frozen_keys_are_neither_cleared_nor_counted() {
        let mut c = Confirmer::new(2, secs(0));
        let t0 = Instant::now();
        let frozen = |k: &Key| k.0 == "a|b";
        let other = (
            "a|c".to_string(),
            "Users".to_string(),
            "M3",
            "x".to_string(),
        );
        assert!(c
            .observe(t0, vec![(key("a"), ()), (other.clone(), ())], never)
            .is_empty());
        // Check 2: pair a|b frozen. "a" absent must not clear; "a" present must not count.
        assert!(
            c.observe(t0 + secs(1), vec![(other.clone(), ())], frozen)
                .len()
                == 1
        );
        assert!(c
            .observe(t0 + secs(2), vec![(key("a"), ())], frozen)
            .is_empty());
        // Check 4: eligible again; "a" now has count 2 -> confirmed.
        assert_eq!(
            c.observe(t0 + secs(3), vec![(key("a"), ())], never).len(),
            1
        );
    }

    #[test]
    fn heal_then_recur_emits_again() {
        let mut c = Confirmer::new(1, secs(0));
        let t0 = Instant::now();
        assert_eq!(c.observe(t0, vec![(key("a"), ())], never).len(), 1);
        assert!(c
            .observe(t0 + secs(1), vec![(key("a"), ())], never)
            .is_empty());
        assert!(c.observe::<()>(t0 + secs(2), Vec::new(), never).is_empty());
        assert_eq!(
            c.observe(t0 + secs(3), vec![(key("a"), ())], never).len(),
            1
        );
    }
}
