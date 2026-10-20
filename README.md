# Wutong Server · 梧桐服务器

[![CI](https://github.com/project-wutong/wutong-server/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-server/actions/workflows/ci.yml)
Rust 2024 · `AGPL-3.0-only`（注意 AGPL §13：修改后对网络用户提供服务须提供对应源码）

## 中文

**可选**的自托管无头服务器（PROTO-001：协议不强制任何官方服务器）。可组合角色：Sync Relay、Federation 网关、
Service Host（Builder 部署目标）、Adapter Gateway、Agent Worker。实现 WTP-STD-001 §8 的 HTTPS 绑定：

- [x] `GET /_wutong/v0.1/meta`（`wutong.node_meta`，待签名）
- [x] `POST /_wutong/v0.1/objects`：RFC 9530 `Content-Digest`、严格解析、Schema + 语义校验、结构化 `wutong.receipt`
- [ ] 节点密钥与签名回执、KeyRegistry、持久化防重放账本
- [ ] `revisions` / `resolve` / `subscriptions` / `invocations` / `sync`、SSRF 出站策略、速率限制

## English

Optional self-hosted headless node implementing the WTP federation/service HTTPS binding.
Early stage: see the issue tracker and the "Wutong Roadmap" project.
