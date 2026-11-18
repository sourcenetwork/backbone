//! The revision a client follows and the term it was accepted in.
//!
//! Every device of a deployment holds its consensus key, so the blocks of a
//! device that was replaced verify like those of the device that replaced it.
//! A term certificate, approved under the deployment's operator policy, says
//! which device proposes from a term on and names the last block of the term
//! before as its cut. A client accepts a revision of a term above 0 only under
//! that certificate, and drops a revision it accepted that the term voided.

use std::sync::Arc;

use parking_lot::RwLock;
use vera_domain::TermCertificate;

use crate::freshness::{FreshnessPolicy, ObservedState};
use crate::{ProofClient, SyncState};

/// A revision this client accepted that a later term voided.
///
/// It was finalized by a device that had been replaced. Whatever a caller
/// decided from it, or from a revision before it and above the term's cut,
/// rests on state the deployment does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voided {
    /// The revision that was accepted.
    pub revision: SyncState,
    /// The term whose certificate voided it.
    pub term: u64,
}

/// What header sync and verified responses have established so far.
#[derive(Default)]
pub(crate) struct Tracked {
    pub head: Option<ObservedState>,
    /// Certificate of the newest term this client verified.
    pub certificate: Option<Arc<TermCertificate>>,
    pub voided: Option<Voided>,
}

impl Tracked {
    pub fn certified_term(&self) -> u64 {
        self.certificate
            .as_ref()
            .map_or(0, |certificate| certificate.change.term)
    }

    /// Whether `revision` may become the head under the certificate held.
    fn admit(&self, revision: &SyncState) -> eyre::Result<()> {
        eyre::ensure!(
            revision.term <= self.certified_term(),
            "finalized revision's term has no verified certificate"
        );
        let Some(certificate) = &self.certificate else {
            return Ok(());
        };
        eyre::ensure!(
            certificate.admits(revision.height, revision.term),
            "finalized revision above a term's cut carries an earlier term"
        );
        eyre::ensure!(
            revision.term < certificate.change.term
                || revision.height > certificate.change.cut.height,
            "finalized revision carries a term at or below that term's cut"
        );
        Ok(())
    }
}

/// Make `revision` the head unless an accepted revision is at or above it.
pub(crate) fn observe_revision(
    state: &RwLock<Tracked>,
    notify: &tokio::sync::Notify,
    freshness: FreshnessPolicy,
    revision: SyncState,
) -> eyre::Result<SyncState> {
    let observed = ObservedState::new(revision)?;
    observed.check(freshness)?;
    let mut tracked = state.write();
    if let Some(previous) = tracked.head.as_ref() {
        if observed.revision.height <= previous.revision.height {
            if observed.revision.height == previous.revision.height {
                eyre::ensure!(
                    observed.revision == previous.revision,
                    "conflicting finalized revision at the same height"
                );
            }
            // Repeated certificates cannot reset the monotonic age of a cached revision.
            previous.check(freshness)?;
            return Ok(previous.revision.clone());
        }
        eyre::ensure!(
            vera_domain::term_extends(previous.revision.term, observed.revision.term),
            "finalized revision term precedes an observed revision's term"
        );
    }
    tracked.admit(&observed.revision)?;
    let current = observed.revision.clone();
    tracked.head = Some(observed);
    notify.notify_waiters();
    Ok(current)
}

/// Verify the certificate of `revision`'s term when it is above the term held,
/// and drop the head when that term voids it.
///
/// The head is void when it lies above the certificate's cut, or is another
/// block at the cut's height. A head below the cut cannot be judged from the
/// certificate, so it is compared with the block the node holds at its height,
/// and counts as void unless the node shows that block: a caller that checks
/// again what it decided loses nothing, and one that is not told may.
pub(crate) async fn certify(
    client: &ProofClient,
    state: &RwLock<Tracked>,
    revision: &SyncState,
) -> eyre::Result<()> {
    if revision.term <= state.read().certified_term() {
        return Ok(());
    }
    let certificate = client.verified_term(revision.term, revision.height).await?;
    let head = state.read().head.as_ref().map(|head| head.revision.clone());
    let departed = match head {
        Some(head) if head.height < certificate.change.cut.height => {
            let held = client.verified_state(head.height).await.ok();
            held.is_none_or(|held| held.block_hash != head.block_hash)
                .then_some(head)
        }
        _ => None,
    };
    adopt(state, certificate, departed.as_ref());
    Ok(())
}

/// Hold `certificate` unless one of its term or a later one is held.
/// `departed` is a head the caller found to differ from the node's block at its height.
fn adopt(state: &RwLock<Tracked>, certificate: TermCertificate, departed: Option<&SyncState>) {
    let mut tracked = state.write();
    if tracked.certified_term() >= certificate.change.term {
        return;
    }
    let void = tracked.head.as_ref().is_some_and(|head| {
        !certificate.keeps(head.revision.height, &head.revision.block_hash)
            || departed == Some(&head.revision)
    });
    if void {
        tracked.voided = tracked.head.take().map(|head| Voided {
            revision: head.revision,
            term: certificate.change.term,
        });
        tracing::warn!(
            term = certificate.change.term,
            cut = certificate.change.cut.height,
            "accepted revision voided by a later term"
        );
    }
    tracked.certificate = Some(Arc::new(certificate));
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use vera_domain::{TermChange, TermCut};

    use super::*;

    const CUT: u64 = 20;

    fn revision(height: u64, term: u64, block: u8) -> SyncState {
        SyncState {
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            term,
            module_state_root: B256::repeat_byte(1),
            block_hash: B256::repeat_byte(block),
        }
    }

    fn certificate(term: u64) -> TermCertificate {
        TermCertificate {
            change: TermChange {
                genesis_id: B256::repeat_byte(7),
                term,
                holder: B256::repeat_byte(8),
                cut: TermCut {
                    height: CUT,
                    block: B256::repeat_byte(20),
                },
            },
            approvals: vec![],
        }
    }

    fn observe(state: &RwLock<Tracked>, revision: SyncState) -> eyre::Result<SyncState> {
        observe_revision(
            state,
            &tokio::sync::Notify::new(),
            FreshnessPolicy::default(),
            revision,
        )
    }

    #[test]
    fn a_term_above_zero_needs_its_certificate() {
        let state = RwLock::new(Tracked::default());
        let error = observe(&state, revision(21, 1, 21)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "finalized revision's term has no verified certificate"
        );
        observe(&state, revision(19, 0, 19)).unwrap();
        assert!(observe(&state, revision(21, 1, 21)).is_err());

        adopt(&state, certificate(1), None);
        assert!(observe(&state, revision(21, 2, 21)).is_err());
        observe(&state, revision(21, 1, 21)).unwrap();
        assert_eq!(state.read().voided, None);
    }

    #[test]
    fn a_head_above_the_cut_is_dropped_and_reported() {
        let state = RwLock::new(Tracked::default());
        let replaced = revision(23, 0, 23);
        observe(&state, replaced.clone()).unwrap();

        adopt(&state, certificate(1), None);
        assert!(state.read().head.is_none());
        assert_eq!(
            state.read().voided,
            Some(Voided {
                revision: replaced,
                term: 1
            })
        );

        // The new term's blocks start below the height the client had reached.
        let error = observe(&state, revision(22, 0, 22)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "finalized revision above a term's cut carries an earlier term"
        );
        assert_eq!(observe(&state, revision(21, 1, 21)).unwrap().height, 21);
    }

    #[test]
    fn the_cut_itself_and_blocks_below_it_are_kept() {
        for kept in [revision(CUT, 0, 20), revision(CUT - 1, 0, 19)] {
            let state = RwLock::new(Tracked::default());
            observe(&state, kept.clone()).unwrap();
            adopt(&state, certificate(1), None);
            assert_eq!(state.read().head.as_ref().unwrap().revision, kept);
            assert_eq!(state.read().voided, None);
        }

        let state = RwLock::new(Tracked::default());
        observe(&state, revision(CUT, 0, 99)).unwrap();
        adopt(&state, certificate(1), None);
        assert!(state.read().head.is_none(), "another block at the cut");
    }

    #[test]
    fn a_head_that_left_the_holders_history_below_the_cut_is_dropped() {
        let state = RwLock::new(Tracked::default());
        let departed = revision(CUT - 2, 0, 18);
        observe(&state, departed.clone()).unwrap();
        adopt(&state, certificate(1), Some(&departed));
        assert!(state.read().head.is_none());
        assert_eq!(state.read().voided.as_ref().unwrap().revision, departed);
    }

    #[test]
    fn a_block_of_a_term_lies_above_its_cut_and_an_older_certificate_changes_nothing() {
        let state = RwLock::new(Tracked::default());
        adopt(&state, certificate(2), None);
        let error = observe(&state, revision(CUT, 2, 20)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "finalized revision carries a term at or below that term's cut"
        );
        observe(&state, revision(CUT, 1, 20)).unwrap();

        adopt(&state, certificate(1), None);
        assert_eq!(state.read().certified_term(), 2);
        assert!(state.read().head.is_some());
    }
}
