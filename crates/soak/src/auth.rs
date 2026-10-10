//! Bearer tokens for identity-scoped HTTP requests (copy of the integration
//! tests' `auth_token`, tools/integration-test/tests/acp/events_sse.rs).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};

use crate::generator::Actor;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub key_hex: String,
    pub did: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identities {
    pub owner: Identity,
    pub reader: Identity,
}

/// A 15-minute bearer token for `key_hex`, audience = the API host with port.
pub fn auth_token(key_hex: &str, api_url: &str) -> Result<String> {
    token(key_hex, host_port(api_url))
}

/// A 15-minute actor token for the P2P management channel, audience = the
/// target node's peer id (copy of the integration tests' `mint_manage_token`,
/// tools/integration-test/tests/manage_relay_common.rs).
pub fn manage_token(key_hex: &str, target_peer_id: &str) -> Result<String> {
    token(key_hex, target_peer_id)
}

fn token(key_hex: &str, audience: &str) -> Result<String> {
    let key = hex::decode(key_hex).wrap_err("identity hex")?;
    let key_type = match key.len() {
        32 => crypto::KeyType::Secp256k1,
        64 => crypto::KeyType::Ed25519,
        n => eyre::bail!("unsupported identity length {n}"),
    };
    let raw = identity::RawIdentity::from_bytes(key_type, &key).wrap_err("raw identity")?;
    let token = identity::new_token(
        &raw,
        Duration::from_secs(15 * 60),
        Some(audience.to_string()),
        None,
    )
    .wrap_err("mint token")?;
    String::from_utf8(token).wrap_err("token utf-8")
}

/// `api_url` without its scheme: the token audience and the CLI `--url` both
/// want `host:port` (the CLI prepends its own scheme).
pub fn host_port(api_url: &str) -> &str {
    api_url
        .strip_prefix("https://")
        .or_else(|| api_url.strip_prefix("http://"))
        .unwrap_or(api_url)
}

/// Tokens per (actor, node url), re-minted after 10 minutes (they expire at 15).
pub struct TokenCache {
    ids: Identities,
    tokens: HashMap<(Actor, String), (String, Instant)>,
}

impl TokenCache {
    pub fn new(ids: Identities) -> Self {
        Self {
            ids,
            tokens: HashMap::new(),
        }
    }

    pub fn identities(&self) -> &Identities {
        &self.ids
    }

    pub fn bearer(&mut self, actor: Actor, api_url: &str) -> Result<Option<String>> {
        let key = match actor {
            Actor::Anon => return Ok(None),
            Actor::Owner => &self.ids.owner.key_hex,
            Actor::Reader => &self.ids.reader.key_hex,
        };
        let k = (actor, api_url.to_string());
        if let Some((tok, minted)) = self.tokens.get(&k) {
            if minted.elapsed() < Duration::from_secs(600) {
                return Ok(Some(tok.clone()));
            }
        }
        let tok = auth_token(key, api_url)?;
        self.tokens.insert(k, (tok.clone(), Instant::now()));
        Ok(Some(tok))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn token_is_a_jwt_with_host_port_audience() {
        let tok = auth_token(KEY, "http://127.0.0.1:55110").unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        assert_eq!(parts.len(), 3, "{tok}");
        let claims = base64_url_decode(parts[1]);
        assert!(claims.contains("\"aud\":[\"127.0.0.1:55110\"]"), "{claims}");
    }

    #[test]
    fn manage_token_audience_is_the_target_peer_id() {
        let tok = manage_token(KEY, "12D3KooWTarget").unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        assert_eq!(parts.len(), 3, "{tok}");
        let claims = base64_url_decode(parts[1]);
        assert!(claims.contains("\"aud\":[\"12D3KooWTarget\"]"), "{claims}");
    }

    #[test]
    fn host_port_strips_scheme() {
        assert_eq!(host_port("http://127.0.0.1:5"), "127.0.0.1:5");
        assert_eq!(host_port("127.0.0.1:5"), "127.0.0.1:5");
    }

    #[test]
    fn cache_returns_none_for_anon_and_reuses_tokens() {
        let ids = Identities {
            owner: Identity {
                key_hex: KEY.into(),
                did: "did:key:owner".into(),
            },
            reader: Identity {
                key_hex: KEY.into(),
                did: "did:key:reader".into(),
            },
        };
        let mut c = TokenCache::new(ids);
        assert_eq!(
            c.bearer(crate::generator::Actor::Anon, "http://a:1")
                .unwrap(),
            None
        );
        let t1 = c
            .bearer(crate::generator::Actor::Owner, "http://a:1")
            .unwrap()
            .unwrap();
        let t2 = c
            .bearer(crate::generator::Actor::Owner, "http://a:1")
            .unwrap()
            .unwrap();
        assert_eq!(t1, t2);
        assert_ne!(
            t1,
            c.bearer(crate::generator::Actor::Owner, "http://b:2")
                .unwrap()
                .unwrap()
        );
    }

    fn base64_url_decode(s: &str) -> String {
        let mut s = s.replace('-', "+").replace('_', "/");
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        // minimal decoder to avoid a base64 dep in tests
        let table: Vec<u8> = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .chain([b'+', b'/'])
            .collect();
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for ch in s.bytes() {
            if ch == b'=' {
                break;
            }
            let v = table.iter().position(|t| *t == ch).unwrap() as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}
