# Changelog

All notable changes to Zagros are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Zagros is a hard-fork re-engineering of the [Marzban](https://github.com/Gozargah/Marzban)
panel (v0.8.4, AGPL-3.0). Versioning restarts at `1.0.0-alpha.x` for the new
multi-core platform line.

---

## [1.0.0-alpha.2] — 2026-08-05

**Status: ALPHA.** Suitable for evaluation and lab testing. Not recommended for
production unless you fully understand the limitations listed below.

### Features

* **Multi-core driver platform** — 8 core drivers behind one `BaseCoreDriver`
  contract; all control decisions are **capability-driven** (no core name
  checks anywhere in managers). Adding a new core = adding one folder under
  `app/cores/drivers/`, zero changes elsewhere.
  | Driver | Management surface | Install |
  |---|---|---|
  | xray (XTLS/Xray-core) | Stats API + gRPC HandlerService, hot reload | self-install (official `Xray-linux-64.zip` + geoip/geosite assets) |
  | sing-box (SagerNet) | Clash API / experimental v2ray_api | self-install (pinned 1.12.4, schema 1.12) |
  | Hysteria 2 (apernet/hysteria) | official Traffic Stats API (`/traffic`, `/online`, `/kick`, `/dump/streams`), Masquerade, ACL | self-install (pinned, direct-asset fallback) |
  | TUIC v5 (EAimTY/tuic) | config-only (honest: **no stats API exists upstream**) | self-install |
  | OpenVPN | Management Interface (client-list/-kill/bytecount) + mini-CA PKI | system package (privileged) |
  | WireGuard | kernel/`wg`, per-peer handshake stats | system (privileged) |
  | SSH tunnel | system accounts + session probe | system (privileged) |
  | SoftEther (L2TP/IPsec) | `vpncmd` RPC (Hub/User/Session/IPsec) | system (privileged) |
* **Unified quota** — a single usage counter per user across *all* cores with
  persistent baselines (exactly-once accounting across core restarts).
* **Unified Device & Session managers** — global per-user device limits and
  live cross-core session history.
* **Central Routing / Outbound / Policy engines** — capability-driven rule
  application with honest per-core reports; unsupported rules are reported,
  never silently dropped.
* **Cross-core chaining** — chain traffic across heterogeneous cores
  (e.g. sing-box → WireGuard) through native listeners.
* **Zagros Subscription Portal** — driver-agnostic subscription page rendering
  whatever each driver declares (share links, QRs, `.ovpn`/`.conf` downloads,
  credential fields). Two client modes: **Subscription Link** and
  **Application Login**.
* **Zagros App backend (Client API)** — users authenticate with username /
  app-password only; configs leave the server exclusively through **sealed
  delivery** (X25519 + HKDF-SHA256 + AES-256-GCM; pure-Python fallback with
  verified test vectors).
* **Config Studio** (`/zagros/studio`) — graphical config management per core:
  inbound wizard, generic JSON-tree editor generating RFC 6902 patches,
  schema-validated preview → unified diff → apply, Advanced raw-JSON mode,
  fa/en + dark/light.
* **Operations dashboard** (`/zagros/dashboard`) — live KPIs, per-core usage,
  core/node health, sparkline; honest offline "demo data" badge when the API
  is unreachable.
* **Modern persistence (P3)** — SQLAlchemy 2 + Alembic; encrypted credentials
  at rest (AES-256-GCM with row-bound AAD); idempotent Marzban → Zagros
  migration with dry-run report and rollback (`alembic upgrade head`).
* **Self-installing cores** — hardened GitHub-release installer
  (`User-Agent`, optional `GITHUB_TOKEN` — raises rate limit 60→5000/h —,
  direct-asset and pinned-tag fallbacks); uninstall safety marker
  (`.zagros-installed`) so foreign binaries are never removed.
* **Backup & Restore runbook** — SQLite WAL-aware backup
  (`PRAGMA wal_checkpoint(TRUNCATE)` + pooled-connection disposal), verified
  by E2E (backup → mutate → restore).

### Improvements

* sing-box driver migrated to the **1.12 config schema**; deprecated legacy
  DNS outbound removed; built-in DNS interception via
  `{protocol: "dns", action: "hijack-dns"}` route rule.
* `OutboundKind.DNS` on sing-box now honestly reports *unsupported* instead of
  emitting config a modern sing-box rejects.
* Inbounds with zero enabled users are skipped with a clear log line instead
  of crashing the core at boot.
* Dockerfile: dropped the build-time xray install script — **no core binary is
  baked into the image**; every driver self-installs at runtime (fixes a
  broken reference and an xray special case).
* `.gitignore` hardened: dashboard build output, driver bootstrap secrets,
  runtime data, local env files.
* Repository URLs and OCI image tags aligned to the real GitHub org
  (`ZagrosGM/Zagros`).
* Dashboard `package.json`/`package-lock.json` version aligned with
  `app.__version__`.

### Refactor

* TLS self-signed certificate generation deduplicated into
  `app/cores/pki.py::ensure_self_signed_cert` (was duplicated in hysteria2 and
  tuic backends; idempotent, `chmod 600`). OpenVPN keeps its own mini-CA —
  genuinely different logic, intentionally untouched.
* Crypto modules restructured into dual-backend dispatch (fast library path +
  audited pure-Python path) with identical golden-vector tests on both.
* Driver architecture formally re-reviewed: taxonomy and per-driver verdicts
  documented in `docs/DRIVER-TAXONOMY.md`; verified **zero** runtime import
  cycles across 76 platform modules (3 documented intentional static edges).
* Senior-architecture sweep: coupling, duplicate logic, smells and
  over-engineering addressed (see `docs/MULTICORE-ARCHITECTURE.md` §16).

### Security

* **(CRITICAL, fixed)** All `/api/zagros/*` management endpoints were
  reachable without authentication → split into a sudo-admin router guarded by
  `Admin.check_sudo_admin`, fail-**closed** (503) when the dependency system
  is unavailable — never fail-open. Client/portal endpoints stay public by
  design. Covered by `tests/adminapi/test_router_auth.py`.
* Subscription-token rotation now invalidates previously issued portal links
  (server-side `jti` pinning via Settings KV store; fail-closed on missing
  record).
* CORS default tightened from `*` + credentials to same-origin (empty list).
* Verified with tests: client tokens are HS256-only with typed scopes
  (`access`/`sub`); legacy JWT algorithm pinned (`algorithms=["HS256"]`);
  app passwords stored only as scrypt hashes; connect tokens are one-time,
  30-second, SHA-256-hashed; X25519 rejects non-contributory public keys on
  both crypto backends; no `eval`/`exec` anywhere; portal HTML uses
  `html.escape` at every interpolation point.
* Full write-up in `docs/SECURITY-REVIEW.md`.

### Performance

* AES-256-GCM roundtrip (1.4 KB payload): **21.9 ms → 0.005 ms (~4000×)** via
  dual-backend dispatch (`cryptography` when available, audited pure-Python
  fallback otherwise). Both paths pinned to identical golden vectors.
* X25519 shared-secret: fast library path **0.077 ms/op** (was tens of ms);
  pure fallback kept and tested.
* Measured: share-url generation (vless+reality) 5.2 µs, RFC 6902 patch on a
  large config 2.45 ms, scrypt ~48 ms (intentional work factor).

### Bug Fixes

All found by running the drivers against **real upstream binaries** — never
mocks (full details in `docs/REAL-BINARY-NOTES.md`):

* hysteria2: stats config key must be `trafficStats:` (camelCase); `traffic:`
  is silently ignored by the core.
* hysteria2: core config decoder treats `.` in map keys as nested paths →
  driver sanitizes core-side account names with a collision-checked reverse
  map for traffic/online/kick.
* hysteria2 & tuic: cores refuse to boot with an empty user map → drivers boot
  fresh installs with a persisted random bootstrap credential
  (`.bootstrap-secret`, mode 0600), replaced by the first real account.
* tuic: server ≤1.0.0 aborts on explicit IPv4 listen (dual-stack socket
  error) → `dual_stack` is now only enabled for wildcard listen addresses.
* hysteria2, tuic, sing-box: process argv captured the pre-install binary
  path → process handle is rebuilt after binary install.
* sing-box: removed legacy `{"type":"dns"}` special outbound (removed upstream
  in 1.13); stats inbound tag list aligned to rendered inbounds.
* xray: declared `SELF_INSTALL` capability with no implementation →
  implemented official-zip install/update/uninstall with uninstall-marker
  safety.
* Backup of a live SQLite (WAL mode) could silently copy a stale main file →
  runbook + helpers checkpoint and isolate connections first.
* Test fixtures updated to real-server semantics (sanitized names,
  `trafficStats:`, sing-box 1.12 rule counts).
* Release-blocker: Dockerfile referenced a non-existent scripts repository —
  removed; image-tag org names fixed.

### Known Limitations

* **Privileged cores** (wireguard, openvpn, softether, ssh) require root/CAP_
  NET_ADMIN at runtime; their full real-binary E2E is only scheduled for a
  privileged container (environment report is emitted honestly instead).
* xray *start* E2E needs the full panel runtime and is currently a documented
  skip; its install/update/uninstall/uninstall-safety paths are E2E-tested.
* TUIC exposes **no usage accounting or online tracking upstream** — Zagros
  reports TUIC traffic as *unaccounted* rather than fabricating numbers.
  hysteria2/tuic core-side account names are sanitized (`[A-Za-z0-9_-]`), a
  core-imposed constraint.
* The tuic upstream repository (EAimTY/tuic) is **archived**; the driver is
  kept as a thin, honestly-labelled option and is flagged in its metadata.
* Chain/Policy dedicated wizards land post-alpha; until then they are edited
  via Studio's generic tree editor (no hand-JSON required).
* Legacy `/api/admin/token` (upstream surface) has no rate limit yet —
  registered accepted risk, scheduled next release.
* OCI images are **not yet published** to Docker Hub / GHCR: the workflows
  require `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` repository secrets. Until
  then, build the image locally from source (see README → Docker).
* Admin tokens for the internal UIs are stored in browser localStorage;
  master key comes from `ZAGROS_SECRET_KEY` (env file). KMS/HSM key
  management is on the roadmap.
* Multi-node (Marzban-node) interop is not covered by real-node E2E yet.

### Roadmap (next milestones)

* Chain & Policy dedicated Studio wizards (P5); no-JSON coverage for 100% of
  routine operations.
* Rate limiting on the legacy admin token endpoint; security headers sweep.
* Privileged-core E2E inside a root container; multi-node real E2E.
* Published OCI images (Docker Hub + GHCR) once registry secrets are
  configured; signed release artifacts.
* KMS/HSM support for the master key; optional hardware-backed sealed
  delivery.
* Beta line (`1.0.0-beta.1`) after the above exit criteria are met.
