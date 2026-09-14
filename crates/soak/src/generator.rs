//! Seeded data-op planner (axis 1).
//!
//! Pure: the op sequence is a function of (seed, profile, node count) only.
//! Execution outcomes never feed back, so a replay from the same seed plans
//! the identical sequence even if some ops failed the first time. Victims for
//! update/delete are ledger *slots* (creation order); the executor maps slots
//! to the docIDs it learned from create responses.
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

/// Stream derivation constant for the data axis (topology gets its own).
const DATA_AXIS: u64 = 0x5eed_da7a_0000_0001;

/// Weight table over op kinds plus shape parameters. Weights, not percents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub create: u32,
    pub update: u32,
    pub delete: u32,
    pub query: u32,
    /// Target create payload size before store amplification.
    pub doc_bytes: usize,
    /// Ops per second on the virtual schedule.
    pub rate: f64,
    pub collection: String,
}

impl Profile {
    /// The skeleton profile from the design (section 2).
    pub fn p0_crud() -> Self {
        Self {
            name: "p0-crud".into(),
            create: 30,
            update: 40,
            delete: 5,
            query: 25,
            doc_bytes: 1200,
            rate: 20.0,
            collection: "Users".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Create,
    Update,
    Delete,
    Query,
}

/// One planned op.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedOp {
    pub index: u64,
    pub virtual_ts_ms: u64,
    pub node: usize,
    pub kind: OpKind,
    /// Ledger slot for update/delete victims; the slot a create fills.
    pub slot: Option<usize>,
    /// GraphQL literal: create input object, update input object, or the
    /// query selection. None for delete.
    pub payload: Option<String>,
}

pub struct Generator {
    rng: StdRng,
    profile: Profile,
    nodes: usize,
    next_index: u64,
    /// Slots handed out so far (creation order).
    created: usize,
    /// Live slots; deletes swap_remove, so evolution depends only on the seed.
    live: Vec<usize>,
}

impl Generator {
    pub fn new(seed: u64, profile: Profile, nodes: usize) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed ^ DATA_AXIS),
            profile,
            nodes,
            next_index: 0,
            created: 0,
            live: Vec::new(),
        }
    }

    pub fn next_op(&mut self) -> PlannedOp {
        let (c, u, d, q, rate) = (
            self.profile.create,
            self.profile.update,
            self.profile.delete,
            self.profile.query,
            self.profile.rate,
        );
        let r = self.rng.gen_range(0..c + u + d + q);
        let mut kind = if r < c {
            OpKind::Create
        } else if r < c + u {
            OpKind::Update
        } else if r < c + u + d {
            OpKind::Delete
        } else {
            OpKind::Query
        };
        // A victim op with nothing live becomes a create; still seed-determined.
        if matches!(kind, OpKind::Update | OpKind::Delete) && self.live.is_empty() {
            kind = OpKind::Create;
        }
        let node = self.rng.gen_range(0..self.nodes);
        let (slot, payload) = match kind {
            OpKind::Create => {
                let slot = self.created;
                self.created += 1;
                self.live.push(slot);
                (Some(slot), Some(self.create_input()))
            }
            OpKind::Update => {
                let pos = self.rng.gen_range(0..self.live.len());
                (Some(self.live[pos]), Some(self.update_input()))
            }
            OpKind::Delete => {
                let pos = self.rng.gen_range(0..self.live.len());
                (Some(self.live.swap_remove(pos)), None)
            }
            OpKind::Query => (None, Some(self.query_selection())),
        };
        let index = self.next_index;
        self.next_index += 1;
        PlannedOp {
            index,
            virtual_ts_ms: (index as f64 * 1000.0 / rate) as u64,
            node,
            kind,
            slot,
            payload,
        }
    }

    fn alnum(&mut self, len: usize) -> String {
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| CHARS[self.rng.gen_range(0..CHARS.len())] as char)
            .collect()
    }

    /// At most 8 significant digits, under the 15-digit float roundtrip
    /// ceiling (a known runtime asymmetry).
    fn score(&mut self) -> String {
        format!("{:.2}", self.rng.gen_range(0..1_000_000) as f64 / 100.0)
    }

    fn create_input(&mut self) -> String {
        let name = self.alnum(8);
        let age = self.rng.gen_range(0..100);
        let score = self.score();
        let blob = self.alnum(self.profile.doc_bytes.saturating_sub(64));
        format!("{{name: \"{name}\", age: {age}, score: {score}, blob: \"{blob}\"}}")
    }

    fn update_input(&mut self) -> String {
        let age = self.rng.gen_range(0..100);
        let score = self.score();
        format!("{{age: {age}, score: {score}}}")
    }

    fn query_selection(&mut self) -> String {
        let age = self.rng.gen_range(0..100);
        format!(
            "{}(limit: 10, filter: {{age: {{_gt: {age}}}}}) {{ _docID name age }}",
            self.profile.collection
        )
    }
}

impl Iterator for Generator {
    type Item = PlannedOp;
    fn next(&mut self) -> Option<PlannedOp> {
        Some(self.next_op())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(seed: u64, n: usize) -> Vec<PlannedOp> {
        Generator::new(seed, Profile::p0_crud(), 2)
            .take(n)
            .collect()
    }

    #[test]
    fn same_seed_same_sequence() {
        assert_eq!(plan(42, 500), plan(42, 500));
    }

    #[test]
    fn different_seed_different_sequence() {
        assert_ne!(plan(42, 500), plan(43, 500));
    }

    /// Victims are always slots that were created earlier and not yet deleted.
    #[test]
    fn victims_are_live_slots() {
        let mut created = 0usize;
        let mut deleted = std::collections::HashSet::new();
        for op in plan(7, 2000) {
            match op.kind {
                OpKind::Create => {
                    assert_eq!(op.slot, Some(created));
                    created += 1;
                }
                OpKind::Update | OpKind::Delete => {
                    let slot = op.slot.expect("victim slot");
                    assert!(slot < created, "slot {slot} not created yet");
                    assert!(!deleted.contains(&slot), "slot {slot} already deleted");
                    if op.kind == OpKind::Delete {
                        deleted.insert(slot);
                    }
                }
                OpKind::Query => assert_eq!(op.slot, None),
            }
        }
        assert!(
            created > 0 && !deleted.is_empty(),
            "profile must exercise all kinds"
        );
    }
}
