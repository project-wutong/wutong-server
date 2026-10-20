// SPDX-License-Identifier: AGPL-3.0-only
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("WUTONG_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let cfg = wutong_server::NodeConfig {
        node_id: std::env::var("WUTONG_NODE_ID")
            .unwrap_or_else(|_| "urn:uuid:019a1111-1111-7111-8111-0000000008fd".into()),
        operator_id: std::env::var("WUTONG_OPERATOR_ID")
            .unwrap_or_else(|_| "urn:uuid:019a1111-1111-7111-8111-0000000008fe".into()),
        base_url: std::env::var("WUTONG_BASE_URL")
            .unwrap_or_else(|_| "https://node.invalid".into()),
        max_envelope_bytes: 1_048_576,
    };
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("wutong-server listening on {addr} (put a TLS terminator in front)");
    axum::serve(listener, wutong_server::router(cfg)).await
}
