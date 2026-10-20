// SPDX-License-Identifier: AGPL-3.0-only
//! Wutong Server — WTP-Federation / WTP-Service HTTPS binding (WTP-STD-001 §8), work in progress.
//!
//! Implemented: `GET /_wutong/v0.1/meta`, `POST /_wutong/v0.1/objects` with RFC 9530
//! `Content-Digest` verification, strict parsing, schema + semantic validation and a
//! structured `wutong.receipt`. **Receipts and node_meta are not yet signed** (needs the node
//! key store), and TLS termination is expected in front of the server for now.

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use wutong_core::types::{ErrorCode, WtpError, err};

/// Static node identity/configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Node principal URN.
    pub node_id: String,
    /// Operator principal URN.
    pub operator_id: String,
    /// Public HTTPS base URL.
    pub base_url: String,
    /// Max accepted envelope size.
    pub max_envelope_bytes: usize,
}

/// Build the router.
pub fn router(cfg: NodeConfig) -> Router {
    Router::new()
        .route("/_wutong/v0.1/meta", get(meta))
        .route("/_wutong/v0.1/objects", post(objects))
        .with_state(Arc::new(cfg))
}

fn uuid_like(seed: &[u8]) -> String {
    // deterministic UUIDv7-shaped id derived from content (placeholder until a UUIDv7 generator lands)
    let h = hex(&Sha256::digest(seed));
    format!(
        "urn:uuid:{}-{}-7{}-8{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_ts() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    wutong_core::types::Timestamp::from_unix_seconds(t).to_string()
}

async fn meta(State(cfg): State<Arc<NodeConfig>>) -> Json<Value> {
    let p = |s: &str| format!("/_wutong/v0.1/{s}");
    Json(json!({
        "protocol": "wutong/0.1",
        "kind": "wutong.node_meta",
        "id": uuid_like(cfg.node_id.as_bytes()),
        "occurred_at": now_ts(),
        "payload": {
            "node_id": cfg.node_id,
            "operator_id": cfg.operator_id,
            "implementation": concat!("wutong-server/", env!("CARGO_PKG_VERSION")),
            "supported_profiles": ["core"],
            "supported_encodings": ["application/wtp+json"],
            "max_envelope_bytes": cfg.max_envelope_bytes,
            "endpoints": {"base_url": cfg.base_url, "meta_path": p("meta"), "objects_path": p("objects"),
                "revisions_path": p("revisions"), "resolve_path": p("resolve"), "subscriptions_path": p("subscriptions"),
                "invocations_path": p("invocations"), "sync_path": p("sync")}
        }
    }))
}

/// Verify RFC 9530 `Content-Digest: sha-256=:<base64>:`.
pub fn verify_content_digest(headers: &HeaderMap, body: &[u8]) -> Result<(), WtpError> {
    let expected = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    );
    match headers.get("content-digest").and_then(|v| v.to_str().ok()) {
        Some(v) if v.split(',').any(|p| p.trim() == expected) => Ok(()),
        _ => Err(err(
            ErrorCode::Signature,
            "missing or mismatching Content-Digest",
        )),
    }
}

fn receipt(cfg: &NodeConfig, body: &[u8], request_id: Option<&str>, e: Option<&WtpError>) -> Value {
    let request_digest = wutong_core::wire::strict::parse(body)
        .ok()
        .and_then(|mut v| {
            v.as_object_mut()?.remove("proof");
            wutong_core::wire::canonical_digest(&v).ok()
        })
        .map(|d| d.to_string())
        .unwrap_or_else(|| wutong_core::wire::sha256_digest(body).to_string());
    let mut payload = json!({
        "receipt_id": uuid_like(&[body, b"receipt"].concat()),
        "request_id": request_id.map(str::to_owned).unwrap_or_else(|| uuid_like(body)),
        "request_digest": request_digest,
        "responder_id": cfg.node_id,
        "status": if e.is_some() { "rejected" } else { "accepted" },
    });
    if let Some(e) = e {
        payload["error_code"] = json!(e.code.as_str());
    }
    json!({"protocol": "wutong/0.1", "kind": "wutong.receipt", "id": uuid_like(&[body, b"envelope"].concat()), "occurred_at": now_ts(), "payload": payload})
}

async fn objects(
    State(cfg): State<Arc<NodeConfig>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let res = (|| {
        if body.len() > cfg.max_envelope_bytes {
            return Err(err(ErrorCode::Schema, "envelope too large"));
        }
        verify_content_digest(&headers, &body)?;
        let env = wutong_core::parse_and_validate(&body)?;
        use wutong_core::types::Kind;
        if !matches!(env.kind(), Kind::Object | Kind::Publication) {
            return Err(err(
                ErrorCode::Schema,
                "objects endpoint accepts wutong.object or wutong.publication",
            ));
        }
        if env.proof.is_none() {
            return Err(err(ErrorCode::Signature, "signed envelope required"));
        }
        // TODO(#key-registry): resolve key binding and verify signature + replay ledger.
        Ok(env.id.to_string())
    })();
    match res {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(receipt(&cfg, &body, Some(&id), None)),
        ),
        Err(e) => (
            StatusCode::from_u16(e.code.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
            Json(receipt(&cfg, &body, None, Some(&e))),
        ),
    }
}
