# Zagros native multi-core Node architecture

## Components

* **Master control plane:** existing Zagros users, subscriptions, encrypted credentials, native-node inventory and signed proxy endpoints under `/api/zagros/nodes`.
* **Node data plane:** `python -m app.node_agent`; it runs only core adapters and persists identity/core state. It does not run the dashboard, admin DB, or subscription service.
* **Transport:** TLS with explicit leaf-certificate SHA-256 pinning at bootstrap. Every post-registration request is HMAC-SHA256 signed over method, path, timestamp, nonce and body. Nonces persist across restarts and requests outside the time window are rejected.
* **Core plugins:** `BaseCoreDriver` + `CoreManager`; node composition injects `_runtime_mode=node`. The allowlist is Xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther and PPTP. No shell/RPC endpoint exists.

## API

Node agent (TLS only): `POST /v1/register`; signed `GET /v1/heartbeat`, `/v1/health`, `/v1/cores`, `/v1/cores/{id}`, `/version`, `/logs`; `POST /v1/cores/{id}/lifecycle`; `PUT /v1/cores/{id}/inbounds`; `POST /v1/revoke`.

Master admin proxy: `GET /api/zagros/nodes`; `POST /nodes/register`; `POST /nodes/{id}/heartbeat`; `POST /nodes/{id}/cores/{core}/lifecycle`; `GET .../logs`; `PUT .../inbounds`; `DELETE /nodes/{id}`.

## Installation

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros-node.sh)" -- install --name node-1
```

Read registration material locally with `sudo zagros-node node info` and register it in Master. Delete `/opt/zagros-node/registration-token` after successful registration. Manual mode: install `node/docker-compose.yml`, create a mode-0600 `.env`, mount an operator certificate/key at the documented paths, and set only the SHA-256 bootstrap-token hash.

Local image: `docker build -f node/Dockerfile --build-arg ZAGROS_VERSION=v1.0.0-alpha.8.9 -t zagros-node:local .`, then set `ZAGROS_NODE_IMAGE=zagros-node:local`.

Published image: `ghcr.io/zagrosgm/zagros-node` (`alpha`, release, and `sha-*` tags).

## Persistence and rollback

`/var/lib/zagros-node` contains mode-0600 TLS, encrypted identity, replay and desired-state files; `/var/lib/zagros/cores` contains independent core data. `uninstall` preserves both; `uninstall --destroy-data` explicitly destroys them. Roll back by setting `ZAGROS_NODE_IMAGE` to the previous release and running `zagros-node update`.

## Known limitations

Alpha 8.9's native UI uses a Node page with per-node lifecycle dialogs rather than tabs on the Master Cores page. User-to-native-node assignment and automatic callback registration are not yet implemented; registration is deliberately two-step and certificate-pinned. Host networking and NET_ADMIN/NET_RAW are required by several data-plane cores; SYS_ADMIN is currently required by isolated SoftEther namespaces. PPTP is legacy/insecure and must remain an explicit operator choice.
