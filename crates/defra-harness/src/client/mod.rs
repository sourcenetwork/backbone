use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{ContextCompat, Result, WrapErr};
use serde_json::Value;

use crate::divergences::{self, NodeKind};

/// CLI-based client for DefraDB.
///
/// Executes commands against a running node using the `client` subcommand tree.
/// `NodeKind` discriminates between Go and Rust implementations so every
/// behavioral difference is an explicit match arm rather than a silent fallback.
pub struct DefraClient {
    binary_path: PathBuf,
    url: String,
    kind: NodeKind,
}

impl DefraClient {
    pub fn new(binary_path: impl Into<PathBuf>, url: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            binary_path: binary_path.into(),
            url: url.into(),
            kind,
        }
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    fn exec(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(&self.binary_path)
            .arg("--url")
            .arg(&self.url)
            .args(args)
            .output()
            .wrap_err_with(|| {
                format!(
                    "failed to exec: {} --url {} {}",
                    self.binary_path.display(),
                    self.url,
                    args.join(" ")
                )
            })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(eyre::eyre!(
                "command failed (exit {}): stderr={}, stdout={}",
                output.status,
                stderr.trim(),
                stdout.trim()
            ))
        }
    }

    fn exec_with_identity(&self, hex_key: &str, args: &[&str]) -> Result<String> {
        let mut full_args = vec!["client", "-i", hex_key];
        let skip = if args.first() == Some(&"client") {
            1
        } else {
            0
        };
        full_args.extend(&args[skip..]);
        self.exec(&full_args)
    }

    // ---- Query output normalization ----

    /// Parse query output, handling the Go/Rust format divergence.
    ///
    /// Both Go and Rust wrap output in `{"data": ...}`.
    /// Go also prefixes with a "Request Results" header line.
    fn parse_query_output(&self, out: &str) -> Result<Value> {
        // Go CLI prefixes output with "------ Request Results ------\n"
        let json_str = out.find('{').map(|i| &out[i..]).unwrap_or(out);
        let val: Value = serde_json::from_str(json_str).wrap_err("failed to parse query output")?;
        if let Some(data) = val.get("data") {
            Ok(data.clone())
        } else {
            Ok(val)
        }
    }

    // ---- Schema operations ----

    /// Deploy a schema via `client schema add '<sdl>'`.
    pub fn schema_add(&self, sdl: &str) -> Result<Value> {
        let out = self.exec(&["client", "schema", "add", sdl])?;
        let json_str = out.find('{').map(|i| &out[i..]).unwrap_or(&out);
        serde_json::from_str(json_str).wrap_err("failed to parse schema_add output")
    }

    /// Execute a GraphQL query/mutation via `client query '<gql>'`.
    pub fn query(&self, gql: &str) -> Result<Value> {
        let out = self.exec(&["client", "query", gql])?;
        self.parse_query_output(&out)
    }

    // ---- Collection operations ----

    /// Create a document via `client collection create --name <n> '<json>'`.
    pub fn collection_create(&self, name: &str, doc: &str) -> Result<Value> {
        let out = self.exec(&["client", "collection", "create", "--name", name, doc])?;
        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(trimmed).wrap_err("failed to parse collection_create output")
    }

    /// Get a document via `client collection get --name <n> <id>`.
    pub fn collection_get(&self, name: &str, doc_id: &str) -> Result<Value> {
        let out = self.exec(&["client", "collection", "get", "--name", name, doc_id])?;
        serde_json::from_str(&out).wrap_err("failed to parse collection_get output")
    }

    /// Delete a document via `client collection delete --name <n> --docID <id>`.
    pub fn collection_delete(&self, name: &str, doc_id: &str) -> Result<String> {
        self.exec(&[
            "client",
            "collection",
            "delete",
            "--name",
            name,
            "--docID",
            doc_id,
        ])
    }

    /// List collections via `client collection list`.
    pub fn collection_list(&self) -> Result<Vec<String>> {
        let out = self.exec(&["client", "collection", "list"])?;
        Self::parse_collection_list(&out)
    }

    /// List document IDs via `client collection docIDs --name <n>`.
    ///
    /// Both Go and Rust output line-separated `{"docID": "..."}` objects.
    pub fn collection_doc_ids(&self, name: &str) -> Result<Vec<String>> {
        let subcmd = divergences::doc_ids_subcommand(self.kind);
        let out = self.exec(&["client", "collection", subcmd, "--name", name])?;
        let trimmed = out.trim();

        let doc_id_key = divergences::doc_id_key(self.kind);
        let mut ids = Vec::new();
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(obj) = serde_json::from_str::<Value>(line) {
                if let Some(id) = obj.get(doc_id_key).and_then(|v| v.as_str()) {
                    ids.push(id.to_string());
                }
            }
        }
        Ok(ids)
    }

    /// Truncate a collection via `client collection truncate --name <n>`.
    pub fn collection_truncate(&self, name: &str) -> Result<String> {
        self.exec(&["client", "collection", "truncate", "--name", name])
    }

    /// Update a document via `client collection update --name <n> --docID <id> --updater '<json>'`.
    pub fn collection_update(&self, name: &str, doc_id: &str, updater: &str) -> Result<String> {
        self.exec(&[
            "client",
            "collection",
            "update",
            "--name",
            name,
            "--docID",
            doc_id,
            "--updater",
            updater,
        ])
    }

    /// Describe a collection via `client collection describe --name <n>`.
    pub fn collection_describe(&self, name: &str) -> Result<Value> {
        let out = self.exec(&["client", "collection", "describe", "--name", name])?;
        serde_json::from_str(&out).wrap_err("failed to parse collection_describe output")
    }

    // ---- Schema operations ----

    /// List schema type names via GraphQL introspection.
    pub fn schema_describe(&self) -> Result<String> {
        let result = self.query(r#"{ __schema { types { name } } }"#)?;
        Ok(result.to_string())
    }

    // ---- Index operations ----

    /// Create an index.
    ///
    /// DIVERGENCE:
    /// - Rust: `client index create <collection> --fields <f>` (positional)
    /// - Go:   `client index create --collection <c> --fields <f>` (flag)
    pub fn index_create(
        &self,
        collection: &str,
        fields: &[&str],
        name: Option<&str>,
        unique: bool,
    ) -> Result<Value> {
        let fields_csv = fields.join(",");
        let use_flag = !divergences::index_uses_positional_args(self.kind);
        let out = self.build_index_create_args(collection, &fields_csv, name, unique, use_flag)?;
        serde_json::from_str(&out).wrap_err("failed to parse index_create output")
    }

    fn build_index_create_args(
        &self,
        collection: &str,
        fields_csv: &str,
        name: Option<&str>,
        unique: bool,
        use_flag: bool,
    ) -> Result<String> {
        let mut args = vec!["client", "index", "create"];
        if use_flag {
            args.push("--collection");
        }
        args.push(collection);
        args.push("--fields");
        args.push(fields_csv);
        if let Some(n) = name {
            args.push("--name");
            args.push(n);
        }
        if unique {
            args.push("--unique");
        }
        self.exec(&args)
    }

    /// List indexes.
    ///
    /// DIVERGENCE: Rust positional, Go `--collection` flag.
    pub fn index_list(&self, collection: Option<&str>) -> Result<Value> {
        let out = if let Some(c) = collection {
            if divergences::index_uses_positional_args(self.kind) {
                self.exec(&["client", "index", "list", c])?
            } else {
                self.exec(&["client", "index", "list", "--collection", c])?
            }
        } else {
            self.exec(&["client", "index", "list"])?
        };
        serde_json::from_str(&out).wrap_err("failed to parse index_list output")
    }

    /// Delete an index.
    ///
    /// DIVERGENCE: Rust positional, Go `--collection`/`--name` flags.
    pub fn index_delete(&self, collection: &str, name: &str) -> Result<String> {
        if divergences::index_uses_positional_args(self.kind) {
            self.exec(&["client", "index", "delete", collection, name])
        } else {
            self.exec(&[
                "client",
                "index",
                "delete",
                "--collection",
                collection,
                "--name",
                name,
            ])
        }
    }

    // ---- Transaction operations ----

    /// Create a transaction via `client tx create`.
    pub fn tx_create(&self) -> Result<String> {
        let out = self.exec(&["client", "tx", "create"])?;
        Self::parse_tx_id(&out)
    }

    /// Create a concurrent transaction via `client tx create --concurrent`.
    pub fn tx_create_concurrent(&self) -> Result<String> {
        let out = self.exec(&["client", "tx", "create", "--concurrent"])?;
        Self::parse_tx_id(&out)
    }

    fn parse_collection_list(output: &str) -> Result<Vec<String>> {
        let trimmed = output.trim();
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if let Some(arr) = val.as_array() {
                return Ok(arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect());
            }
        }
        Ok(trimmed
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    fn parse_tx_id(output: &str) -> Result<String> {
        let trimmed = output.trim();
        let val: Value =
            serde_json::from_str(trimmed).wrap_err("failed to parse tx create output as JSON")?;
        let id = val
            .get("id")
            .wrap_err("tx create output missing 'id' field")?;
        Ok(id.to_string())
    }

    /// Commit a transaction via `client tx commit <id>`.
    pub fn tx_commit(&self, tx_id: &str) -> Result<String> {
        self.exec(&["client", "tx", "commit", tx_id])
    }

    /// Discard a transaction via `client tx discard <id>`.
    pub fn tx_discard(&self, tx_id: &str) -> Result<String> {
        self.exec(&["client", "tx", "discard", tx_id])
    }

    /// Execute a GraphQL query inside a transaction.
    pub fn query_with_tx(&self, gql: &str, tx_id: &str) -> Result<Value> {
        let out = self.exec(&["client", "--tx", tx_id, "query", gql])?;
        self.parse_query_output(&out)
    }

    // ---- P2P operations ----

    /// Get P2P node info via `client p2p info`.
    pub fn p2p_info(&self) -> Result<Value> {
        let out = self.exec(&["client", "p2p", "info"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_info output")
    }

    /// Connect to peers via `client p2p connect <addr>...`.
    pub fn p2p_connect(&self, addrs: &[&str]) -> Result<String> {
        let mut args = vec!["client", "p2p", "connect"];
        args.extend(addrs);
        self.exec(&args)
    }

    /// Add P2P collections via `client p2p collection add <cols>`.
    pub fn p2p_collection_add(&self, collections: &[&str]) -> Result<String> {
        let cols = collections.join(",");
        self.exec(&["client", "p2p", "collection", "add", &cols])
    }

    /// Add a replicator via `client p2p replicator add -c <cols> <addr>`.
    pub fn p2p_replicator_set(&self, collections: &[&str], addr: &str) -> Result<String> {
        let cols = collections.join(",");
        self.exec(&["client", "p2p", "replicator", "add", "-c", &cols, addr])
    }

    /// List active peers via `client p2p active-peers`.
    pub fn p2p_active_peers(&self) -> Result<Value> {
        let out = self.exec(&["client", "p2p", "active-peers"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_active_peers output")
    }

    /// List P2P collections via `client p2p collection list`.
    pub fn p2p_collection_list(&self) -> Result<Value> {
        let out = self.exec(&["client", "p2p", "collection", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_collection_list output")
    }

    /// Delete P2P collections via `client p2p collection delete <cols>`.
    pub fn p2p_collection_delete(&self, collections: &[&str]) -> Result<String> {
        let cols = collections.join(",");
        self.exec(&["client", "p2p", "collection", "delete", &cols])
    }

    /// List replicators via `client p2p replicator list`.
    pub fn p2p_replicator_list(&self) -> Result<Value> {
        let out = self.exec(&["client", "p2p", "replicator", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_replicator_list output")
    }

    /// Delete a replicator via `client p2p replicator delete -c <cols> [peerID]`.
    pub fn p2p_replicator_delete(
        &self,
        collections: &[&str],
        peer_addr: Option<&str>,
    ) -> Result<String> {
        let cols = collections.join(",");
        let mut args = vec!["client", "p2p", "replicator", "delete", "-c", &cols];
        if let Some(addr) = peer_addr {
            args.push(addr);
        }
        self.exec(&args)
    }

    // ---- P2P Document operations ----

    /// Add documents to P2P subscription via `client p2p document add <id1> <id2>`.
    pub fn p2p_document_add(&self, doc_ids: &[&str]) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "add"];
        args.extend(doc_ids);
        self.exec(&args)
    }

    /// Remove documents from P2P subscription.
    pub fn p2p_document_delete(&self, doc_ids: &[&str]) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "delete"];
        args.extend(doc_ids);
        self.exec(&args)
    }

    /// List P2P document subscriptions.
    pub fn p2p_document_list(&self) -> Result<Value> {
        let out = self.exec(&["client", "p2p", "document", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_document_list output")
    }

    /// Sync documents via `client p2p document sync <collection> <docIDs...>`.
    pub fn p2p_document_sync(&self, collection: &str, doc_ids: &[&str]) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "sync", collection];
        args.extend(doc_ids);
        self.exec(&args)
    }

    /// Sync collection versions via `client p2p collection sync-versions <versionIDs...>`.
    pub fn p2p_collection_sync_versions(&self, version_ids: &[&str]) -> Result<String> {
        let mut args = vec!["client", "p2p", "collection", "sync-versions"];
        args.extend(version_ids);
        self.exec(&args)
    }

    /// Sync branchable collection via `client p2p collection sync-branchable <id>`.
    pub fn p2p_collection_sync_branchable(&self, collection_id: &str) -> Result<String> {
        self.exec(&[
            "client",
            "p2p",
            "collection",
            "sync-branchable",
            collection_id,
        ])
    }

    // ---- Identity-aware query operations ----

    /// Execute a GraphQL query with an identity.
    pub fn query_with_identity(&self, gql: &str, hex_key: &str) -> Result<Value> {
        let out = self.exec(&["client", "-i", hex_key, "query", gql])?;
        self.parse_query_output(&out)
    }

    /// Deploy a schema with identity.
    pub fn schema_add_with_identity(&self, sdl: &str, hex_key: &str) -> Result<Value> {
        let out = self.exec(&["client", "-i", hex_key, "schema", "add", sdl])?;
        let json_str = out.find('{').map(|i| &out[i..]).unwrap_or(&out);
        serde_json::from_str(json_str).wrap_err("failed to parse schema_add output")
    }

    // ---- ACP Document operations ----

    /// Add an ACP policy.
    pub fn acp_policy_add(&self, policy: &str, hex_key: &str) -> Result<Value> {
        let out = self.exec(&[
            "client", "-i", hex_key, "acp", "document", "policy", "add", policy,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_policy_add output")
    }

    /// Add an ACP document relationship.
    pub fn acp_relationship_add(
        &self,
        collection: &str,
        doc_id: &str,
        relation: &str,
        actor_did: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec(&[
            "client",
            "-i",
            hex_key,
            "acp",
            "document",
            "relationship",
            "add",
            "-c",
            collection,
            "--docID",
            doc_id,
            "-r",
            relation,
            "-a",
            actor_did,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_relationship_add output")
    }

    /// Delete an ACP document relationship.
    pub fn acp_relationship_delete(
        &self,
        collection: &str,
        doc_id: &str,
        relation: &str,
        actor_did: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec(&[
            "client",
            "-i",
            hex_key,
            "acp",
            "document",
            "relationship",
            "delete",
            "-c",
            collection,
            "--docID",
            doc_id,
            "-r",
            relation,
            "-a",
            actor_did,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_relationship_delete output")
    }

    // ---- ACP Node (NAC) operations ----

    /// Add an ACP node relationship.
    pub fn acp_node_relationship_add(
        &self,
        relation: &str,
        actor_did: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec(&[
            "client",
            "-i",
            hex_key,
            "acp",
            "node",
            "relationship",
            "add",
            "-r",
            relation,
            "-a",
            actor_did,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_node_relationship_add output")
    }

    /// Delete an ACP node relationship.
    pub fn acp_node_relationship_delete(
        &self,
        relation: &str,
        actor_did: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec(&[
            "client",
            "-i",
            hex_key,
            "acp",
            "node",
            "relationship",
            "delete",
            "-r",
            relation,
            "-a",
            actor_did,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_node_relationship_delete output")
    }

    /// Get ACP node status.
    pub fn acp_node_status(&self) -> Result<Value> {
        let out = self.exec(&["client", "acp", "node", "status"])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_node_status output")
    }

    /// Disable ACP node.
    pub fn acp_node_disable(&self) -> Result<Value> {
        let out = self.exec(&["client", "acp", "node", "disable"])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_node_disable output")
    }

    /// Re-enable ACP node.
    pub fn acp_node_reenable(&self) -> Result<Value> {
        let out = self.exec(&["client", "acp", "node", "re-enable"])?;
        serde_json::from_str(&out).wrap_err("failed to parse acp_node_reenable output")
    }

    // ---- Encrypted Index operations ----

    /// Add an encrypted index.
    ///
    /// DIVERGENCE:
    /// - Rust: `client encrypted-index add <collection> <field>` (positional)
    /// - Go:   `client encrypted-index add --collection <c> --field <f>` (flags)
    pub fn encrypted_index_add(&self, collection: &str, field: &str) -> Result<Value> {
        let out = if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec(&["client", "encrypted-index", "add", collection, field])?
        } else {
            self.exec(&[
                "client",
                "encrypted-index",
                "add",
                "--collection",
                collection,
                "--field",
                field,
            ])?
        };
        serde_json::from_str(&out).wrap_err("failed to parse encrypted_index_add output")
    }

    /// Delete an encrypted index.
    ///
    /// DIVERGENCE: Rust positional, Go flags.
    pub fn encrypted_index_delete(&self, collection: &str, field: &str) -> Result<String> {
        if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec(&["client", "encrypted-index", "delete", collection, field])
        } else {
            self.exec(&[
                "client",
                "encrypted-index",
                "delete",
                "--collection",
                collection,
                "--field",
                field,
            ])
        }
    }

    /// List encrypted indexes.
    ///
    /// DIVERGENCE: Rust positional, Go flags.
    pub fn encrypted_index_list(&self, collection: &str) -> Result<Value> {
        let out = if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec(&["client", "encrypted-index", "list", collection])?
        } else {
            self.exec(&[
                "client",
                "encrypted-index",
                "list",
                "--collection",
                collection,
            ])?
        };
        serde_json::from_str(&out).wrap_err("failed to parse encrypted_index_list output")
    }

    // ---- Node/Block operations ----

    /// Get node identity.
    pub fn node_identity(&self) -> Result<Value> {
        let out = self.exec(&["client", "node-identity"])?;
        let trimmed = out.trim();
        serde_json::from_str(trimmed).or_else(|_| Ok(Value::String(trimmed.to_string())))
    }

    /// Verify a block signature.
    pub fn block_verify_signature(
        &self,
        public_key: &str,
        cid: &str,
        key_type: Option<&str>,
    ) -> Result<String> {
        let mut args = vec!["client", "block", "verify-signature", public_key, cid];
        if let Some(kt) = key_type {
            args.push("--key-type");
            args.push(kt);
        }
        self.exec(&args)
    }

    // ---- Lens operations ----

    /// Add a lens migration.
    pub fn lens_add(&self, config: &str) -> Result<Value> {
        let out = self.exec(&["client", "lens", "add", config])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_add output")
    }

    /// List lens migrations.
    pub fn lens_list(&self) -> Result<Value> {
        let out = self.exec(&["client", "lens", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_list output")
    }

    /// Set a lens migration between schema versions.
    pub fn lens_set(&self, src: &str, dst: &str, config: &str) -> Result<Value> {
        let out = self.exec(&["client", "lens", "set", src, dst, config])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_set output")
    }

    /// Reload lens migrations.
    pub fn lens_reload(&self) -> Result<String> {
        self.exec(&["client", "lens", "reload"])
    }

    // ---- Backup operations ----

    /// Export backup.
    pub fn backup_export(&self, file: &str, collections: &[&str], pretty: bool) -> Result<String> {
        let mut args = vec!["client", "backup", "export", file];
        for c in collections {
            args.push("-c");
            args.push(c);
        }
        if pretty {
            args.push("--pretty");
        }
        self.exec(&args)
    }

    /// Import backup.
    pub fn backup_import(&self, file: &str) -> Result<String> {
        self.exec(&["client", "backup", "import", file])
    }

    // ---- Collection management ----

    /// Patch a collection schema.
    pub fn collection_patch(&self, patch: &str) -> Result<String> {
        self.exec(&["client", "collection", "patch", patch])
    }

    /// Set active collection version.
    pub fn collection_set_active(&self, version_id: &str) -> Result<String> {
        self.exec(&["client", "collection", "set-active", version_id])
    }

    /// Purge the database.
    pub fn purge(&self) -> Result<String> {
        self.exec(&["client", "purge", "--force"])
    }

    /// Get collection version info including VersionID.
    ///
    /// DIVERGENCE: Rust has REST endpoint, Go uses CLI only.
    pub fn collection_describe_version(&self, name: &str) -> Result<Value> {
        match self.kind {
            NodeKind::Rust => {
                let url = format!("{}/api/v0/collections/{}/describe", self.url, name);
                let output = Command::new("curl")
                    .arg("-s")
                    .arg("-f")
                    .arg(&url)
                    .output()
                    .wrap_err_with(|| format!("failed to curl {}", url))?;

                if output.status.success() {
                    let body = String::from_utf8_lossy(&output.stdout);
                    if let Ok(val) = serde_json::from_str::<Value>(body.trim()) {
                        return Ok(val);
                    }
                }
                // Fall back to CLI
                let out = self.exec(&["client", "collection", "describe", "--name", name])?;
                serde_json::from_str(&out).wrap_err("failed to parse collection describe output")
            }
            NodeKind::Go => {
                let out = self.exec(&["client", "collection", "describe", "--name", name])?;
                serde_json::from_str(&out).wrap_err("failed to parse collection describe output")
            }
        }
    }

    /// Get collection version info using an identity (for NAC-enabled nodes).
    pub fn collection_describe_version_with_identity(
        &self,
        name: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec_with_identity(
            hex_key,
            &["client", "collection", "describe", "--name", name],
        )?;
        let val: Value =
            serde_json::from_str(&out).wrap_err("failed to parse collection describe output")?;
        if val.get("CollectionID").is_none() && val.get("VersionID").is_none() {
            if let Some(id) = val.get("ID").and_then(|v| v.as_str()) {
                let mut out_val = val.clone();
                out_val["CollectionID"] = serde_json::Value::String(id.to_string());
                if let Some(ver) = val
                    .get("SchemaVersionID")
                    .and_then(|v| v.as_str())
                    .or_else(|| val.get("VersionID").and_then(|v| v.as_str()))
                {
                    out_val["VersionID"] = serde_json::Value::String(ver.to_string());
                }
                return Ok(out_val);
            }
        }
        Ok(val)
    }

    // ---- View operations ----

    /// Add a view.
    pub fn view_add(&self, gql_query: &str, sdl: &str) -> Result<Value> {
        let out = self.exec(&["client", "view", "add", "--query", gql_query, "--sdl", sdl])?;
        serde_json::from_str(&out).wrap_err("failed to parse view_add output")
    }

    /// Add a view with a lens transform CID.
    pub fn view_add_with_lens(&self, gql_query: &str, sdl: &str, lens_cid: &str) -> Result<Value> {
        let out = self.exec(&[
            "client",
            "view",
            "add",
            "--query",
            gql_query,
            "--sdl",
            sdl,
            "--lens-cid",
            lens_cid,
        ])?;
        serde_json::from_str(&out).wrap_err("failed to parse view_add output")
    }

    /// Refresh views.
    pub fn view_refresh(&self, name: Option<&str>) -> Result<Value> {
        let out = if let Some(n) = name {
            self.exec(&["client", "view", "refresh", "--name", n])?
        } else {
            self.exec(&["client", "view", "refresh"])?
        };
        serde_json::from_str(&out).wrap_err("failed to parse view_refresh output")
    }

    // ---- Dump operations ----

    /// Dump database contents.
    pub fn dump(&self) -> Result<Value> {
        let out = self.exec(&["client", "dump"])?;
        serde_json::from_str(&out).wrap_err("failed to parse dump output")
    }

    // ---- Identity-aware variants (NAC testing) ----

    pub fn p2p_info_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "p2p", "info"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_info output")
    }

    pub fn p2p_active_peers_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "p2p", "active-peers"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_active_peers output")
    }

    pub fn encrypted_index_add_with_identity(
        &self,
        collection: &str,
        field: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec_with_identity(
                hex_key,
                &["client", "encrypted-index", "add", collection, field],
            )?
        } else {
            self.exec_with_identity(
                hex_key,
                &[
                    "client",
                    "encrypted-index",
                    "add",
                    "--collection",
                    collection,
                    "--field",
                    field,
                ],
            )?
        };
        serde_json::from_str(&out).wrap_err("failed to parse encrypted_index_add output")
    }

    pub fn encrypted_index_list_with_identity(
        &self,
        collection: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec_with_identity(hex_key, &["client", "encrypted-index", "list", collection])?
        } else {
            self.exec_with_identity(
                hex_key,
                &[
                    "client",
                    "encrypted-index",
                    "list",
                    "--collection",
                    collection,
                ],
            )?
        };
        serde_json::from_str(&out).wrap_err("failed to parse encrypted_index_list output")
    }

    pub fn encrypted_index_delete_with_identity(
        &self,
        collection: &str,
        field: &str,
        hex_key: &str,
    ) -> Result<String> {
        if divergences::encrypted_index_uses_positional_args(self.kind) {
            self.exec_with_identity(
                hex_key,
                &["client", "encrypted-index", "delete", collection, field],
            )
        } else {
            self.exec_with_identity(
                hex_key,
                &[
                    "client",
                    "encrypted-index",
                    "delete",
                    "--collection",
                    collection,
                    "--field",
                    field,
                ],
            )
        }
    }

    pub fn lens_add_with_identity(&self, config: &str, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "lens", "add", config])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_add output")
    }

    pub fn lens_list_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "lens", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_list output")
    }

    pub fn lens_set_with_identity(
        &self,
        src: &str,
        dst: &str,
        config: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "lens", "set", src, dst, config])?;
        serde_json::from_str(&out).wrap_err("failed to parse lens_set output")
    }

    pub fn view_add_with_identity(
        &self,
        gql_query: &str,
        sdl: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec_with_identity(
            hex_key,
            &["client", "view", "add", "--query", gql_query, "--sdl", sdl],
        )?;
        serde_json::from_str(&out).wrap_err("failed to parse view_add output")
    }

    pub fn view_refresh_with_identity(&self, name: Option<&str>, hex_key: &str) -> Result<Value> {
        let out = if let Some(n) = name {
            self.exec_with_identity(hex_key, &["client", "view", "refresh", "--name", n])?
        } else {
            self.exec_with_identity(hex_key, &["client", "view", "refresh"])?
        };
        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_str(trimmed).wrap_err("failed to parse view_refresh output")
    }

    pub fn p2p_document_sync_with_identity(
        &self,
        collection: &str,
        doc_ids: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "sync", collection];
        args.extend(doc_ids);
        self.exec_with_identity(hex_key, &args)
    }

    pub fn p2p_collection_sync_versions_with_identity(
        &self,
        version_ids: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let mut args = vec!["client", "p2p", "collection", "sync-versions"];
        args.extend(version_ids);
        self.exec_with_identity(hex_key, &args)
    }

    pub fn p2p_collection_sync_branchable_with_identity(
        &self,
        collection_id: &str,
        hex_key: &str,
    ) -> Result<String> {
        self.exec_with_identity(
            hex_key,
            &[
                "client",
                "p2p",
                "collection",
                "sync-branchable",
                collection_id,
            ],
        )
    }

    // ---- Identity-aware collection operations ----

    pub fn collection_list_with_identity(&self, hex_key: &str) -> Result<Vec<String>> {
        let out = self.exec_with_identity(hex_key, &["client", "collection", "list"])?;
        Self::parse_collection_list(&out)
    }

    pub fn collection_describe_with_identity(&self, name: &str, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(
            hex_key,
            &["client", "collection", "describe", "--name", name],
        )?;
        serde_json::from_str(&out).wrap_err("failed to parse collection_describe output")
    }

    pub fn collection_create_with_identity(
        &self,
        name: &str,
        doc: &str,
        hex_key: &str,
    ) -> Result<Value> {
        let out = self.exec_with_identity(
            hex_key,
            &["client", "collection", "create", "--name", name, doc],
        )?;
        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(trimmed).wrap_err("failed to parse collection_create output")
    }

    pub fn collection_delete_with_identity(
        &self,
        name: &str,
        doc_id: &str,
        hex_key: &str,
    ) -> Result<String> {
        self.exec_with_identity(
            hex_key,
            &[
                "client",
                "collection",
                "delete",
                "--name",
                name,
                "--docID",
                doc_id,
            ],
        )
    }

    pub fn collection_update_with_identity(
        &self,
        name: &str,
        doc_id: &str,
        updater: &str,
        hex_key: &str,
    ) -> Result<String> {
        self.exec_with_identity(
            hex_key,
            &[
                "client",
                "collection",
                "update",
                "--name",
                name,
                "--docID",
                doc_id,
                "--updater",
                updater,
            ],
        )
    }

    pub fn collection_truncate_with_identity(&self, name: &str, hex_key: &str) -> Result<String> {
        self.exec_with_identity(
            hex_key,
            &["client", "collection", "truncate", "--name", name],
        )
    }

    pub fn collection_patch_with_identity(&self, patch: &str, hex_key: &str) -> Result<String> {
        self.exec_with_identity(hex_key, &["client", "collection", "patch", patch])
    }

    // ---- Identity-aware index operations ----

    pub fn index_create_with_identity(
        &self,
        collection: &str,
        fields: &[&str],
        name: Option<&str>,
        unique: bool,
        hex_key: &str,
    ) -> Result<Value> {
        let fields_csv = fields.join(",");
        let use_flag = !divergences::index_uses_positional_args(self.kind);
        let mut args = vec!["client", "index", "create"];
        if use_flag {
            args.push("--collection");
        }
        args.push(collection);
        args.push("--fields");
        args.push(&fields_csv);
        if let Some(n) = name {
            args.push("--name");
            args.push(n);
        }
        if unique {
            args.push("--unique");
        }
        let out = self.exec_with_identity(hex_key, &args)?;
        serde_json::from_str(&out).wrap_err("failed to parse index_create output")
    }

    pub fn index_list_with_identity(
        &self,
        collection: Option<&str>,
        hex_key: &str,
    ) -> Result<Value> {
        let out = if let Some(c) = collection {
            if divergences::index_uses_positional_args(self.kind) {
                self.exec_with_identity(hex_key, &["client", "index", "list", c])?
            } else {
                self.exec_with_identity(hex_key, &["client", "index", "list", "--collection", c])?
            }
        } else {
            self.exec_with_identity(hex_key, &["client", "index", "list"])?
        };
        serde_json::from_str(&out).wrap_err("failed to parse index_list output")
    }

    pub fn index_delete_with_identity(
        &self,
        collection: &str,
        name: &str,
        hex_key: &str,
    ) -> Result<String> {
        if divergences::index_uses_positional_args(self.kind) {
            self.exec_with_identity(hex_key, &["client", "index", "delete", collection, name])
        } else {
            self.exec_with_identity(
                hex_key,
                &[
                    "client",
                    "index",
                    "delete",
                    "--collection",
                    collection,
                    "--name",
                    name,
                ],
            )
        }
    }

    // ---- Identity-aware P2P operations ----

    pub fn p2p_connect_with_identity(&self, addrs: &[&str], hex_key: &str) -> Result<String> {
        let mut args = vec!["client", "p2p", "connect"];
        args.extend(addrs);
        self.exec_with_identity(hex_key, &args)
    }

    pub fn p2p_collection_add_with_identity(
        &self,
        collections: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let cols = collections.join(",");
        self.exec_with_identity(hex_key, &["client", "p2p", "collection", "add", &cols])
    }

    pub fn p2p_collection_list_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "p2p", "collection", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_collection_list output")
    }

    pub fn p2p_collection_delete_with_identity(
        &self,
        collections: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let cols = collections.join(",");
        self.exec_with_identity(hex_key, &["client", "p2p", "collection", "delete", &cols])
    }

    pub fn p2p_document_add_with_identity(
        &self,
        doc_ids: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "add"];
        args.extend(doc_ids);
        self.exec_with_identity(hex_key, &args)
    }

    pub fn p2p_document_list_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "p2p", "document", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_document_list output")
    }

    pub fn p2p_document_delete_with_identity(
        &self,
        doc_ids: &[&str],
        hex_key: &str,
    ) -> Result<String> {
        let mut args = vec!["client", "p2p", "document", "delete"];
        args.extend(doc_ids);
        self.exec_with_identity(hex_key, &args)
    }

    pub fn p2p_replicator_set_with_identity(
        &self,
        collections: &[&str],
        addr: &str,
        hex_key: &str,
    ) -> Result<String> {
        let cols = collections.join(",");
        self.exec_with_identity(
            hex_key,
            &["client", "p2p", "replicator", "add", "-c", &cols, addr],
        )
    }

    pub fn p2p_replicator_list_with_identity(&self, hex_key: &str) -> Result<Value> {
        let out = self.exec_with_identity(hex_key, &["client", "p2p", "replicator", "list"])?;
        serde_json::from_str(&out).wrap_err("failed to parse p2p_replicator_list output")
    }

    pub fn p2p_replicator_delete_with_identity(
        &self,
        collections: &[&str],
        peer_addr: Option<&str>,
        hex_key: &str,
    ) -> Result<String> {
        let cols = collections.join(",");
        let mut args = vec!["client", "p2p", "replicator", "delete", "-c", &cols];
        if let Some(addr) = peer_addr {
            args.push(addr);
        }
        self.exec_with_identity(hex_key, &args)
    }
}
