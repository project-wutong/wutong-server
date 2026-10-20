// SPDX-License-Identifier: AGPL-3.0-only
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn cfg() -> wutong_server::NodeConfig {
    wutong_server::NodeConfig {
        node_id: "urn:uuid:019a1111-1111-7111-8111-0000000008fd".into(),
        operator_id: "urn:uuid:019a1111-1111-7111-8111-0000000008fe".into(),
        base_url: "https://node.wutong.example".into(),
        max_envelope_bytes: 1 << 20,
    }
}

async fn call(req: Request<Body>) -> (StatusCode, Value) {
    let res = wutong_server::router(cfg()).oneshot(req).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn meta_is_schema_valid_node_meta() {
    let (s, v) = call(
        Request::get("/_wutong/v0.1/meta")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bytes = serde_json::to_vec(&v).unwrap();
    let env = wutong_core::parse_and_validate(&bytes).unwrap();
    assert_eq!(env.kind(), wutong_core::types::Kind::NodeMeta);
}

const SIGNED: &str = r#"{"protocol":"wutong/0.1","kind":"wutong.object","id":"urn:uuid:019a1111-1111-7111-8111-000000002713","occurred_at":"2026-10-18T10:00:00Z","payload":{"object_id":"urn:uuid:019a1111-1111-7111-8111-00000000012d","space_id":"urn:uuid:019a1111-1111-7111-8111-00000000012e","owner_id":"urn:uuid:019a1111-1111-7111-8111-00000000012f","object_type":"document","content_digest":"sha256:47ad8cc78b24bcb0b6e13b2657e96f1c915055f3f872d3c2c92b25343a6ff5b6","media_type":"text/markdown","byte_length":0},"auth":{"signer_id":"urn:uuid:019a1111-1111-7111-8111-000000000001","key_id":"local-key-01","issued_at":"2026-10-18T10:00:00Z","nonce":"AAAAAAAAAAAAAAAAAAAAAAAA"},"proof":{"alg":"Ed25519","sig":"91bbF7H1wMhm5Pif0c6nG6uvkwf02UX3wbX54wsBbB2-KYPl63TLqCKke2LGYakkrDCW4Fzq93_LYB4mkhFjCQ"}}"#;

fn post(body: &str, digest: bool) -> Request<Body> {
    let mut b =
        Request::post("/_wutong/v0.1/objects").header("content-type", "application/wtp+json");
    if digest {
        let d = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body.as_bytes()));
        b = b.header("content-digest", format!("sha-256=:{d}:"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test]
async fn objects_accepts_signed_object_with_digest() {
    let (s, v) = call(post(SIGNED, true)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["payload"]["status"], "accepted");
    let bytes = serde_json::to_vec(&v).unwrap();
    wutong_core::parse_and_validate(&bytes).unwrap();
}

#[tokio::test]
async fn objects_rejects_missing_digest_and_bad_json() {
    let (s, v) = call(post(SIGNED, false)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["payload"]["error_code"], "ERR_SIGNATURE");
    let (s, v) = call(post(r#"{"a":1,"a":2}"#, true)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["payload"]["error_code"], "ERR_SCHEMA");
}
