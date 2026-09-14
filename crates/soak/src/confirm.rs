//! Mismatch confirmation: a mismatch becomes a divergence only after it has
//! been seen in `confirmations` consecutive checks spanning at least `grace`.
//! This is what separates "sync in flight" from "diverged" without an event
//! bus on the Go side.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// (collection, mechanism, docID) identifies one mismatch.
pub type Key = (String, &'static str, String);

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
    /// A key absent from `mismatches` is cleared.
    pub fn observe<D>(&mut self, now: Instant, mismatches: Vec<(Key, D)>) -> Vec<(Key, D, u32)> {
        let seen: HashSet<&Key> = mismatches.iter().map(|(k, _)| k).collect();
        self.pending.retain(|k, _| seen.contains(k));
        let mut confirmed = Vec::new();
        for (key, detail) in mismatches {
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
        ("Users".to_string(), "M3", id.to_string())
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn confirms_after_r_consecutive_checks() {
        let mut c = Confirmer::new(3, secs(0));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), 1)]).is_empty());
        assert!(c.observe(t0 + secs(1), vec![(key("a"), 2)]).is_empty());
        let out = c.observe(t0 + secs(2), vec![(key("a"), 3)]);
        assert_eq!(out, vec![(key("a"), 3, 3)]);
        assert!(
            c.observe(t0 + secs(3), vec![(key("a"), 4)]).is_empty(),
            "no re-emit"
        );
    }

    #[test]
    fn grace_window_delays_confirmation() {
        let mut c = Confirmer::new(1, secs(10));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), ())]).is_empty());
        assert!(c.observe(t0 + secs(5), vec![(key("a"), ())]).is_empty());
        assert_eq!(c.observe(t0 + secs(10), vec![(key("a"), ())]).len(), 1);
    }

    #[test]
    fn a_clear_check_resets_the_count() {
        let mut c = Confirmer::new(2, secs(0));
        let t0 = Instant::now();
        assert!(c.observe(t0, vec![(key("a"), ())]).is_empty());
        assert!(c.observe::<()>(t0 + secs(1), Vec::new()).is_empty());
        assert_eq!(c.pending(), 0);
        assert!(c.observe(t0 + secs(2), vec![(key("a"), ())]).is_empty());
        assert_eq!(c.observe(t0 + secs(3), vec![(key("a"), ())]).len(), 1);
    }

    #[test]
    fn unresolved_counts_emitted_mismatches_still_present() {
        let mut c = Confirmer::new(1, secs(0));
        let t0 = Instant::now();
        assert_eq!(c.observe(t0, vec![(key("a"), ())]).len(), 1);
        assert_eq!(c.unresolved(), 1);
        c.observe::<()>(t0 + secs(1), Vec::new());
        assert_eq!(c.unresolved(), 0);
    }

    #[test]
    fn heal_then_recur_emits_again() {
        let mut c = Confirmer::new(1, secs(0));
        let t0 = Instant::now();
        assert_eq!(c.observe(t0, vec![(key("a"), ())]).len(), 1);
        assert!(c.observe(t0 + secs(1), vec![(key("a"), ())]).is_empty());
        assert!(c.observe::<()>(t0 + secs(2), Vec::new()).is_empty());
        assert_eq!(c.observe(t0 + secs(3), vec![(key("a"), ())]).len(), 1);
    }
}
