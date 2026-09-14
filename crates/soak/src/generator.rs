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

/// Access-control profile: share of creates that are protected (owned by the
/// owner identity) and share of protected docs that get a reader grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpProfile {
    pub protected_pct: u32,
    pub grant_pct: u32,
}

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
    /// Fields named in `encryptFields:` on every create. Empty = plaintext profile.
    #[serde(default)]
    pub encrypt_fields: Vec<String>,
    /// Field with a searchable-encryption index; the query op becomes an SE query.
    #[serde(default)]
    pub se_field: Option<String>,
    /// Give every document its own `name` instead of drawing one of
    /// `NAME_POOL`, so an SE query matches exactly one document.
    #[serde(default)]
    pub unique_names: bool,
    /// Node indices that receive create ops; `None` = any node. Other ops are unaffected.
    #[serde(default)]
    pub create_nodes: Option<Vec<usize>>,
    #[serde(default)]
    pub acp: Option<AcpProfile>,
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
            encrypt_fields: Vec::new(),
            se_field: None,
            unique_names: false,
            create_nodes: None,
            acp: None,
        }
    }

    /// M1b V1: encrypted `secret`/`pin`, SE index on `name` (spec 62, section 2).
    pub fn p1_encrypted() -> Self {
        Self {
            name: "p1-encrypted".into(),
            collection: "Vault".into(),
            encrypt_fields: vec!["secret".into(), "pin".into()],
            se_field: Some("name".into()),
            ..Self::p0_crud()
        }
    }

    /// p1 with one document per name: same weights, fields and sizes, but the
    /// SE query returns a single document, so a miss is the first-responder
    /// defect and not the many-documents-per-name query shape (133 part 4,
    /// rank 3). 307 remains the colliding-name result.
    pub fn p1_unique() -> Self {
        Self {
            name: "p1-unique".into(),
            unique_names: true,
            ..Self::p1_encrypted()
        }
    }

    /// M1b V2: local document ACP, protected + public docs, reader grants (spec 64).
    pub fn p2_acp() -> Self {
        Self {
            name: "p2-acp".into(),
            collection: "User".into(),
            acp: Some(AcpProfile {
                protected_pct: 60,
                grant_pct: 30,
            }),
            ..Self::p0_crud()
        }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "p0-crud" => Some(Self::p0_crud()),
            "p1-encrypted" => Some(Self::p1_encrypted()),
            "p1-unique" => Some(Self::p1_unique()),
            "p2-acp" => Some(Self::p2_acp()),
            _ => None,
        }
    }

    /// Needs the ACP-enabled cluster (local ACP, owner/reader identities).
    pub fn is_acp(&self) -> bool {
        self.acp.is_some()
    }

    /// Needs the encryption-enabled cluster (dev mode, identities, SE key).
    pub fn is_encrypted(&self) -> bool {
        !self.encrypt_fields.is_empty() || self.se_field.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Create,
    Update,
    Delete,
    Query,
    Grant,
}

/// Who issues an op on an ACP profile. `None` = the op has no identity (p0/p1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Owner,
    Reader,
    Anon,
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
    /// SE query only: ledger slots whose name equals `payload` at planning
    /// time; the executor resolves them to docIDs. Empty otherwise.
    #[serde(default)]
    pub expect_slots: Vec<usize>,
    #[serde(default)]
    pub actor: Option<Actor>,
}

pub const NAME_POOL: usize = 40;

pub struct Generator {
    rng: StdRng,
    profile: Profile,
    nodes: usize,
    next_index: u64,
    /// Slots handed out so far (creation order).
    created: usize,
    /// Live slots; deletes swap_remove, so evolution depends only on the seed.
    live: Vec<usize>,
    /// Name per slot (creation order); only filled for encrypted profiles.
    names: Vec<String>,
    /// Creator per slot (creation order); only filled for ACP profiles.
    owner_of: Vec<Actor>,
    /// Create node per slot (creation order); only filled for ACP profiles.
    /// Grants go there: the local DAC state lives on the node that served
    /// the relationship add.
    create_node: Vec<usize>,
    /// Protected slots that already received a reader grant.
    granted: std::collections::HashSet<usize>,
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
            names: Vec::new(),
            owner_of: Vec::new(),
            create_node: Vec::new(),
            granted: std::collections::HashSet::new(),
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
        let acp = self.profile.acp;
        let r = self.rng.gen_range(0..c + u + d + q);
        let mut kind = if r < c {
            OpKind::Create
        } else if r < c + u {
            // On ACP profiles the first `grant_pct` percent of the update band are grants.
            match acp {
                Some(a) if (r - c) * 100 < u * a.grant_pct => OpKind::Grant,
                _ => OpKind::Update,
            }
        } else if r < c + u + d {
            OpKind::Delete
        } else {
            OpKind::Query
        };
        let grant_candidates: Vec<usize> = if kind == OpKind::Grant {
            self.live
                .iter()
                .copied()
                .filter(|s| {
                    self.owner_of.get(*s) == Some(&Actor::Owner) && !self.granted.contains(s)
                })
                .collect()
        } else {
            Vec::new()
        };
        // A victim op with nothing live becomes a create; still seed-determined.
        if ((matches!(kind, OpKind::Update | OpKind::Delete)
            || (kind == OpKind::Query && (self.profile.se_field.is_some() || acp.is_some())))
            && self.live.is_empty())
            || (kind == OpKind::Grant && grant_candidates.is_empty())
        {
            kind = OpKind::Create;
        }
        let mut node = match (&kind, &self.profile.create_nodes) {
            (OpKind::Create, Some(allowed)) if !allowed.is_empty() => {
                allowed[self.rng.gen_range(0..allowed.len())]
            }
            _ => self.rng.gen_range(0..self.nodes),
        };
        let mut expect_slots = Vec::new();
        let mut actor = None;
        let (slot, payload) = match kind {
            OpKind::Create => {
                let slot = self.created;
                self.created += 1;
                self.live.push(slot);
                let payload = if self.profile.is_encrypted() {
                    let mut name = format!("name-{:02}", self.rng.gen_range(0..NAME_POOL));
                    // p1-unique draws the same pool value, so both profiles
                    // plan the same ops from a seed; the slot suffix is what
                    // makes the name unique per document.
                    if self.profile.unique_names {
                        name = format!("{name}-{slot:06}");
                    }
                    self.names.push(name.clone());
                    self.create_input_vault(&name)
                } else {
                    self.create_input()
                };
                if let Some(a) = acp {
                    let protected = self.rng.gen_range(0..100) < a.protected_pct;
                    let who = if protected { Actor::Owner } else { Actor::Anon };
                    self.owner_of.push(who);
                    self.create_node.push(node);
                    actor = Some(who);
                }
                (Some(slot), Some(payload))
            }
            OpKind::Update => {
                let pos = self.rng.gen_range(0..self.live.len());
                let payload = if self.profile.is_encrypted() {
                    self.update_input_vault()
                } else {
                    self.update_input()
                };
                if acp.is_some() {
                    actor = Some(self.owner_of[self.live[pos]]);
                }
                (Some(self.live[pos]), Some(payload))
            }
            OpKind::Delete => {
                let pos = self.rng.gen_range(0..self.live.len());
                let slot = self.live.swap_remove(pos);
                if acp.is_some() {
                    actor = Some(self.owner_of[slot]);
                }
                (Some(slot), None)
            }
            OpKind::Grant => {
                let slot = grant_candidates[self.rng.gen_range(0..grant_candidates.len())];
                self.granted.insert(slot);
                node = self.create_node[slot];
                actor = Some(Actor::Owner);
                (Some(slot), None)
            }
            // ACP query: the executor reads the slot as owner, reader and anon.
            OpKind::Query if acp.is_some() => {
                let pos = self.rng.gen_range(0..self.live.len());
                (Some(self.live[pos]), None)
            }
            OpKind::Query if self.profile.se_field.is_some() => {
                let pos = self.rng.gen_range(0..self.live.len());
                let name = self.names[self.live[pos]].clone();
                expect_slots = self
                    .live
                    .iter()
                    .copied()
                    .filter(|s| self.names[*s] == name)
                    .collect();
                (None, Some(name))
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
            expect_slots,
            actor,
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

    fn create_input_vault(&mut self, name: &str) -> String {
        let secret = self.alnum(16);
        let pin = format!("{:04}", self.rng.gen_range(0..10_000));
        let score = self.score();
        let blob = self.alnum(self.profile.doc_bytes.saturating_sub(96));
        format!(
            "{{name: \"{name}\", secret: \"{secret}\", pin: \"{pin}\", score: {score}, blob: \"{blob}\"}}"
        )
    }

    fn update_input_vault(&mut self) -> String {
        let secret = self.alnum(16);
        let score = self.score();
        format!("{{secret: \"{secret}\", score: {score}}}")
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
                OpKind::Grant => panic!("p0 plans no grants"),
            }
        }
        assert!(
            created > 0 && !deleted.is_empty(),
            "profile must exercise all kinds"
        );
    }

    #[test]
    fn old_manifest_profile_still_loads() {
        let old = r#"{"name":"p0-crud","create":30,"update":40,"delete":5,"query":25,
                      "doc_bytes":1200,"rate":5.0,"collection":"Users"}"#;
        let p: Profile = serde_json::from_str(old).expect("old profile json");
        assert_eq!(
            p,
            Profile {
                rate: 5.0,
                ..Profile::p0_crud()
            }
        );
        assert!(p.encrypt_fields.is_empty() && p.se_field.is_none() && !p.is_encrypted());
    }

    #[test]
    fn p1_encrypted_shape() {
        let p = Profile::p1_encrypted();
        assert_eq!(p.collection, "Vault");
        assert_eq!(
            p.encrypt_fields,
            vec!["secret".to_string(), "pin".to_string()]
        );
        assert_eq!(p.se_field.as_deref(), Some("name"));
        assert!(p.is_encrypted());
        let back: Profile = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn profile_by_name() {
        assert_eq!(Profile::by_name("p0-crud"), Some(Profile::p0_crud()));
        assert_eq!(
            Profile::by_name("p1-encrypted"),
            Some(Profile::p1_encrypted())
        );
        assert_eq!(Profile::by_name("nope"), None);
    }

    /// p0 must not move: hash of the first 500 ops for seed 42, 2 nodes.
    #[test]
    fn p0_plan_is_frozen() {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for op in plan(42, 500) {
            (
                op.index,
                op.virtual_ts_ms,
                op.node,
                op.kind as u8,
                op.slot,
                op.payload,
            )
                .hash(&mut h);
        }
        assert_eq!(h.finish(), 12263656268250365760);
    }

    fn plan_p1(seed: u64, n: usize) -> Vec<PlannedOp> {
        Generator::new(seed, Profile::p1_encrypted(), 4)
            .take(n)
            .collect()
    }

    #[test]
    fn p0_ops_have_no_expect_slots() {
        assert!(plan(42, 500).iter().all(|op| op.expect_slots.is_empty()));
    }

    #[test]
    fn p1_create_and_update_payloads() {
        let ops = plan_p1(9, 400);
        let create = ops.iter().find(|o| o.kind == OpKind::Create).unwrap();
        let p = create.payload.as_deref().unwrap();
        assert!(p.starts_with("{name: \"") && p.contains("secret: \"") && p.contains("pin: \""));
        assert!(p.contains("score: ") && p.contains("blob: \"") && !p.contains("age:"));
        let update = ops.iter().find(|o| o.kind == OpKind::Update).unwrap();
        let u = update.payload.as_deref().unwrap();
        assert!(u.starts_with("{secret: \"") && u.contains("score: ") && !u.contains("age:"));
    }

    /// An SE query names a live doc's name and lists every live slot with that name.
    #[test]
    fn p1_query_carries_expected_live_slots() {
        let mut names: std::collections::HashMap<usize, String> = Default::default();
        let mut live = std::collections::HashSet::new();
        let mut queries = 0;
        for op in plan_p1(11, 3000) {
            match op.kind {
                OpKind::Create => {
                    let slot = op.slot.unwrap();
                    let p = op.payload.as_deref().unwrap();
                    let name = p["{name: \"".len()..]
                        .split('"')
                        .next()
                        .unwrap()
                        .to_string();
                    names.insert(slot, name);
                    live.insert(slot);
                }
                OpKind::Delete => {
                    live.remove(&op.slot.unwrap());
                }
                OpKind::Query => {
                    queries += 1;
                    let name = op.payload.as_deref().expect("SE query payload is the name");
                    let mut want: Vec<usize> =
                        live.iter().copied().filter(|s| names[s] == name).collect();
                    want.sort();
                    let mut got = op.expect_slots.clone();
                    got.sort();
                    assert_eq!(got, want, "op {}", op.index);
                    assert!(!got.is_empty());
                }
                OpKind::Update => {}
                OpKind::Grant => panic!("p1 plans no grants"),
            }
        }
        assert!(queries > 50, "profile must exercise SE queries");
    }

    #[test]
    fn p1_names_come_from_a_small_pool() {
        let names: std::collections::HashSet<String> = plan_p1(3, 2000)
            .into_iter()
            .filter(|o| o.kind == OpKind::Create)
            .map(|o| {
                o.payload.unwrap()["{name: \"".len()..]
                    .split('"')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(names.len() <= NAME_POOL && names.len() > 10);
    }

    #[test]
    fn create_nodes_restricts_creates_only() {
        let mut p = Profile::p1_encrypted();
        p.create_nodes = Some(vec![0, 1]);
        let ops: Vec<PlannedOp> = Generator::new(21, p, 4).take(2000).collect();
        assert!(ops
            .iter()
            .filter(|o| o.kind == OpKind::Create)
            .all(|o| o.node < 2));
        assert!(
            ops.iter().any(|o| o.kind != OpKind::Create && o.node >= 2),
            "other ops still reach Go nodes"
        );
    }

    #[test]
    fn create_nodes_absent_keeps_p0_frozen_and_loads_old_json() {
        let old = r#"{"name":"p0-crud","create":30,"update":40,"delete":5,"query":25,
                      "doc_bytes":1200,"rate":5.0,"collection":"Users"}"#;
        let p: Profile = serde_json::from_str(old).unwrap();
        assert_eq!(p.create_nodes, None);
    }

    fn plan_p1_frozen_input() -> Vec<PlannedOp> {
        Generator::new(42, Profile::p1_encrypted(), 4)
            .take(500)
            .collect()
    }

    /// p1 must not move either: hash of the first 500 ops for seed 42, 4 nodes.
    #[test]
    fn p1_plan_is_frozen() {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for op in plan_p1_frozen_input() {
            (
                op.index,
                op.virtual_ts_ms,
                op.node,
                op.kind as u8,
                op.slot,
                op.payload,
                op.expect_slots,
            )
                .hash(&mut h);
        }
        assert_eq!(h.finish(), 133609464861947189);
    }

    fn plan_p1_unique(seed: u64, n: usize) -> Vec<PlannedOp> {
        Generator::new(seed, Profile::p1_unique(), 4)
            .take(n)
            .collect()
    }

    /// p1-unique must not move either: hash of the first 500 ops for seed 42,
    /// 4 nodes, same shape as the p0 and p1 locks.
    #[test]
    fn p1_unique_plan_is_frozen() {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for op in plan_p1_unique(42, 500) {
            (
                op.index,
                op.virtual_ts_ms,
                op.node,
                op.kind as u8,
                op.slot,
                op.payload,
                op.expect_slots,
            )
                .hash(&mut h);
        }
        assert_eq!(h.finish(), 18060237726193507568);
    }

    /// The point of the profile: over a plan the size of run 307 (seed 307,
    /// 4 nodes, 5401 ops executed) no two documents share a name, so an SE
    /// query has exactly one right answer.
    #[test]
    fn p1_unique_never_repeats_a_name() {
        let names: Vec<String> = plan_p1_unique(307, 5401)
            .into_iter()
            .filter(|o| o.kind == OpKind::Create)
            .map(|o| {
                o.payload.unwrap()["{name: \"".len()..]
                    .split('"')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(
            names.len() > 1000,
            "expected 307-sized creates, got {}",
            names.len()
        );
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "p1-unique repeated a name");
        // Every SE query therefore expects exactly one slot.
        assert!(plan_p1_unique(307, 5401)
            .iter()
            .filter(|o| o.kind == OpKind::Query)
            .all(|o| o.expect_slots.len() == 1));
    }

    /// Identical to p1 apart from the names, and it is still an SE profile.
    #[test]
    fn p1_unique_matches_p1_except_names() {
        let (u, p1) = (Profile::p1_unique(), Profile::p1_encrypted());
        assert_eq!(
            (u.create, u.update, u.delete, u.query, u.doc_bytes, u.rate),
            (
                p1.create,
                p1.update,
                p1.delete,
                p1.query,
                p1.doc_bytes,
                p1.rate
            )
        );
        assert_eq!(u.collection, p1.collection);
        assert_eq!(u.encrypt_fields, p1.encrypt_fields);
        assert_eq!(u.se_field, p1.se_field);
        assert!(u.unique_names && !p1.unique_names);
        assert!(u.is_encrypted() && !u.is_acp());
        assert_eq!(Profile::by_name("p1-unique"), Some(u.clone()));
        let back: Profile = serde_json::from_value(serde_json::to_value(&u).unwrap()).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn old_manifest_profile_has_no_acp() {
        let old = r#"{"name":"p1-encrypted","create":30,"update":40,"delete":5,"query":25,"doc_bytes":1200,
                      "rate":3.0,"collection":"Vault","encrypt_fields":["secret","pin"],"se_field":"name"}"#;
        let p: Profile = serde_json::from_str(old).unwrap();
        assert!(p.acp.is_none() && !p.is_acp());
    }

    #[test]
    fn p2_acp_shape() {
        let p = Profile::p2_acp();
        assert_eq!(p.collection, "User");
        assert_eq!(
            p.acp,
            Some(AcpProfile {
                protected_pct: 60,
                grant_pct: 30
            })
        );
        assert!(p.is_acp() && !p.is_encrypted());
        assert_eq!(Profile::by_name("p2-acp"), Some(p.clone()));
        let back: Profile = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn planned_op_actor_defaults_to_none() {
        let v = serde_json::json!({"index":0,"virtual_ts_ms":0,"node":0,"kind":"create","slot":0,"payload":"{}"});
        let op: PlannedOp = serde_json::from_value(v).unwrap();
        assert_eq!(op.actor, None);
        assert_eq!(
            serde_json::to_value(Actor::Reader).unwrap(),
            serde_json::json!("reader")
        );
        assert_eq!(
            serde_json::to_value(OpKind::Grant).unwrap(),
            serde_json::json!("grant")
        );
    }

    fn plan_p2(seed: u64, n: usize) -> Vec<PlannedOp> {
        Generator::new(seed, Profile::p2_acp(), 4).take(n).collect()
    }

    #[test]
    fn p2_actors_and_grants() {
        let ops = plan_p2(5, 3000);
        let mut owner: std::collections::HashMap<usize, Actor> = Default::default();
        let mut create_node: std::collections::HashMap<usize, usize> = Default::default();
        let mut granted = std::collections::HashSet::new();
        let (mut prot, mut pub_, mut grants, mut queries) = (0, 0, 0, 0);
        for op in &ops {
            match op.kind {
                OpKind::Create => {
                    let a = op.actor.expect("create has an actor");
                    assert!(matches!(a, Actor::Owner | Actor::Anon));
                    if a == Actor::Owner {
                        prot += 1
                    } else {
                        pub_ += 1
                    }
                    owner.insert(op.slot.unwrap(), a);
                    create_node.insert(op.slot.unwrap(), op.node);
                    assert!(op.payload.as_deref().unwrap().starts_with("{name: \""));
                }
                OpKind::Update | OpKind::Delete => {
                    assert_eq!(op.actor, Some(owner[&op.slot.unwrap()]), "op {}", op.index);
                }
                OpKind::Grant => {
                    grants += 1;
                    let s = op.slot.unwrap();
                    assert_eq!(owner[&s], Actor::Owner, "grants only on protected docs");
                    assert!(granted.insert(s), "slot {s} granted twice");
                    assert_eq!(op.actor, Some(Actor::Owner));
                    assert_eq!(op.node, create_node[&s], "grant on the origin node");
                }
                OpKind::Query => {
                    queries += 1;
                    assert!(op.slot.is_some() && op.actor.is_none() && op.payload.is_none());
                }
            }
        }
        let share = prot as f64 / (prot + pub_) as f64;
        assert!((0.5..0.7).contains(&share), "protected share {share}");
        assert!(grants > 20 && queries > 100);
    }

    #[test]
    fn p0_and_p1_have_no_actor() {
        assert!(plan(42, 300)
            .iter()
            .all(|o| o.actor.is_none() && o.kind != OpKind::Grant));
        assert!(plan_p1_frozen_input().iter().all(|o| o.actor.is_none()));
    }
}
