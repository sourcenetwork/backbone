//! Known-cause tags for divergent docs, decided live from the doc's last
//! successful write and the mesh's outage windows.
//!
//! `write-during-outage`: a member of the divergent pair other than the
//! writer was down when the doc was last written. `write-during-recovery`:
//! the writer or a pair member had come back less than [`RECOVERY_MS`]
//! before the write (a node answers queries before its replicator link is
//! up). Both are the M0 finding; anything untagged is the alarm.
use serde::Serialize;

/// Writes this soon after a recovery count as made during it.
pub const RECOVERY_MS: u64 = 30_000;

/// One node outage: `up` is `None` while the node is still down.
#[derive(Clone, Debug)]
pub struct Outage {
    pub node: usize,
    pub down_ms: u64,
    pub up_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tag {
    WriteDuringOutage,
    WriteDuringRecovery,
}

/// Tag for a doc whose last write ran on `writer` at `wall_ms`, diverging on
/// the pair `(a, b)`.
pub fn tag(writer: usize, wall_ms: u64, pair: (usize, usize), outages: &[Outage]) -> Option<Tag> {
    let involved = |n: usize| n == writer || n == pair.0 || n == pair.1;
    let peer_down = outages.iter().any(|o| {
        o.node != writer
            && involved(o.node)
            && o.down_ms <= wall_ms
            && o.up_ms.is_none_or(|up| wall_ms <= up)
    });
    if peer_down {
        return Some(Tag::WriteDuringOutage);
    }
    let recovering = outages.iter().any(|o| {
        involved(o.node)
            && o.up_ms
                .is_some_and(|up| up <= wall_ms && wall_ms - up <= RECOVERY_MS)
    });
    recovering.then_some(Tag::WriteDuringRecovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    const R0: usize = 0;
    const R1: usize = 1;
    const G0: usize = 2;

    fn outage(node: usize, down: u64, up: Option<u64>) -> Outage {
        Outage {
            node,
            down_ms: down,
            up_ms: up,
        }
    }

    #[test]
    fn peer_down_at_write_time() {
        let o = [outage(G0, 1_000, Some(20_000))];
        assert_eq!(tag(R0, 5_000, (R0, G0), &o), Some(Tag::WriteDuringOutage));
        // Still down (no up yet) counts too.
        let o = [outage(G0, 1_000, None)];
        assert_eq!(tag(R0, 5_000, (R0, G0), &o), Some(Tag::WriteDuringOutage));
    }

    #[test]
    fn peer_or_writer_recovered_just_before() {
        let o = [outage(G0, 1_000, Some(20_000))];
        assert_eq!(
            tag(R0, 25_000, (R0, G0), &o),
            Some(Tag::WriteDuringRecovery)
        );
        // Writer's own recovery, pair member elsewhere.
        let o = [outage(R0, 1_000, Some(20_000))];
        assert_eq!(
            tag(R0, 40_000, (R0, R1), &o),
            Some(Tag::WriteDuringRecovery)
        );
        // Past the window: nothing.
        assert_eq!(tag(R0, 60_000, (R0, R1), &o), None);
    }

    #[test]
    fn outages_of_uninvolved_nodes_do_not_count() {
        let o = [outage(R1, 1_000, Some(20_000))];
        assert_eq!(tag(R0, 5_000, (R0, G0), &o), None);
        assert_eq!(tag(R0, 25_000, (R0, G0), &o), None);
    }

    #[test]
    fn outage_wins_over_recovery() {
        let o = [outage(G0, 1_000, Some(20_000)), outage(R0, 21_000, None)];
        // Writer R0 cannot really write while down, but if it did the peer's
        // recovery is the weaker claim.
        assert_eq!(tag(G0, 25_000, (R0, G0), &o), Some(Tag::WriteDuringOutage));
    }
}
