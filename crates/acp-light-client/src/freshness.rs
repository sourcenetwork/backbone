use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use crate::SyncState;

/// Local acceptance bounds for authenticated revision timestamps.
#[derive(Clone, Copy, Debug)]
pub struct FreshnessPolicy {
    pub max_age: Duration,
    pub max_future_skew: Duration,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(30),
            max_future_skew: Duration::from_secs(15),
        }
    }
}

pub(crate) struct ObservedState {
    pub revision: SyncState,
    observed_at: Instant,
    age_on_arrival: Duration,
}

impl ObservedState {
    pub fn new(revision: SyncState) -> eyre::Result<Self> {
        let age_on_arrival = unix_now()?.saturating_sub(Duration::from_secs(revision.timestamp));
        Ok(Self {
            revision,
            observed_at: Instant::now(),
            age_on_arrival,
        })
    }

    pub fn check(&self, policy: FreshnessPolicy) -> eyre::Result<()> {
        check_age(
            policy,
            Duration::from_secs(self.revision.timestamp),
            unix_now()?,
            self.age_on_arrival
                .saturating_add(self.observed_at.elapsed()),
        )
    }
}

fn unix_now() -> eyre::Result<Duration> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?)
}

fn check_age(
    policy: FreshnessPolicy,
    timestamp: Duration,
    now: Duration,
    monotonic_age: Duration,
) -> eyre::Result<()> {
    eyre::ensure!(
        timestamp <= now.saturating_add(policy.max_future_skew),
        "verified revision timestamp exceeds allowed clock skew"
    );
    eyre::ensure!(
        now.saturating_sub(timestamp).max(monotonic_age) < policy.max_age,
        "verified revision is stale; wait for a fresh finalized revision"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_age_and_monotonic_elapsed_both_bound_acceptance() {
        let policy = FreshnessPolicy::default();
        let timestamp = Duration::from_secs(100);
        assert!(check_age(policy, timestamp, Duration::from_secs(129), Duration::ZERO).is_ok());
        assert!(check_age(policy, timestamp, Duration::from_secs(130), Duration::ZERO).is_err());
        assert!(check_age(policy, timestamp, Duration::from_secs(84), Duration::ZERO).is_err());
        assert!(check_age(policy, timestamp, Duration::from_secs(85), Duration::ZERO).is_ok());
        // A wall-clock rollback cannot extend a revision's monotonic lifetime.
        assert!(check_age(policy, timestamp, timestamp, Duration::from_secs(30)).is_err());
        assert!(check_age(policy, Duration::MAX, timestamp, Duration::ZERO).is_err());
    }
}
