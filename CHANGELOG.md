# Changelog

All notable changes to Zagros are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Zagros is a hard-fork re-engineering of the [Marzban](https://github.com/Gozargah/Marzban)
panel (v0.8.4, AGPL-3.0). Versioning restarts at `1.0.0-alpha.x` for the new
multi-core platform line.

---

## [1.0.0-alpha.3] — 2026-08-05

**Status: ALPHA.** P6 delivers the Marzban-style one-command operations
experience (installer + management CLI + automated release pipeline) for the
Zagros platform — with its own implementation — and fixes several boot- and
image-blocking defects discovered while hardening it.

### Added

* **`zagros-scripts` repository — one-command installer & management CLI.**
  * `sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ZagrosGM/zagros-scripts/main/zagros.sh)" -- install [--database sqlite|mysql|mariadb|postgresql]`
    — installs Docker when missing, renders a self-contained compose stack
    (host networking; managed MySQL 8.4 / MariaDB 11.5 / PostgreSQL 17 on
    request, with the second `zagros_legacy` database auto-provisioned),
    generates secrets server-side, pulls the GHCR image, waits for health,
    verifies schema, installs the CLI.
  * `zagros` CLI (self-contained, dependency-light: docker, compose, curl,
    jq, openssl, tar) with 33+ commands: `install update restart stop start
    up down status logs doctor health version backup backup-service restore
    migrate rollback uninstall repair shell config reset-admin create-admin
    update-core install-core uninstall-core list-cores reload reload-core
    sync clean prune` (+ `help`).
  * **Update** = automatic pre-backup → tag/digest resolution against live
    GHCR → pull → `alembic upgrade head` → health gate → **automatic
    rollback to the previous image/backup on failure** (`last-update.json`
    audit trail). Manual `zagros rollback [--to <tag>]`.
  * **Backup** = database (hot-consistent SQLite API / `mysqldump` /
    `pg_dump -Fc`) + configuration + certificates + driver metadata +
    runtime config + keys (+ logs with `--logs`) in one `manifest.meta` +
    SHA-256 `manifest.json` archive; every exclusion (core binaries,
    assets) is recorded. **Restore** verifies engine match + checksums,
    takes a safety snapshot, applies, re-migrates, health-checks and
    auto-rolls back on failure.
  * **Doctor** reports Docker / containers / database & migration / cores /
    nodes / certificates / disk / memory / CPU / network / DNS / panel port /
    firewall / GHCR digest / release currency with exit-code semantics and
    a pure-JSON `--json` mode. **Repair** applies safe automatic fixes
    (dirs, env keys, image, container recreation, schema) and refuses to
    invent a lost `ZAGROS_SECRET_KEY` over an existing database.
  * Core commands are capability-driven through the in-container bridge —
    no core name is special anywhere (`install-core xray|sing-box|
    hysteria2|tuic|wireguard|openvpn|...`, `update-core`, `list-cores`
    with state/enabled/health/version/capabilities).
  * A Docker-emulating harness (`tests/`) drives the **real** CLI through
    142 end-to-end assertions (install → backup → restore → update →
    failure rollback → doctor/repair → uninstall/purge) on machines
    without a Docker daemon; CI runs shellcheck + these tests.
* **In-container ops bridge `app.platform.hostctl`** — one-JSON-line
  contract (`{"ok": …, <payload>}` / `{"ok": false, error, code}`) with
  explicit exit codes (0/1/2 usage/3 PANEL_OWNED/4 NOT_FOUND): `version
  health db-check db-backup-sqlite cores-list cores-install
  cores-uninstall cores-update cores-start/-stop/-restart
  cores-enable/-disable cores-logs nodes-list sync admin-list admin-create
  admin-reset`. It composes existing platform services only — no new HTTP
  surface, no panel feature.
* **`0002_legacy_schema` migration** — creates the legacy (upstream) schema
  on the legacy engine from `SQLALCHEMY_DATABASE_URL`, finishing the
  split-database design: the P3 platform stack and the legacy stack keep
  their `admins`/`users`/`nodes` tables in **separate databases**
  (`ZAGROS_DATABASE_URL` vs `SQLALCHEMY_DATABASE_URL`) so same-named tables
  with different shapes never collide.
* **Unified release workflow** (`.github/workflows/release.yml`): every
  `v*` tag (stable / `-alpha` / `-beta` / `-rc`) runs tests → multi-arch
  docker build (amd64 + arm64) → push to **GHCR only**
  (`ghcr.io/zagrosgm/zagros`) → GitHub Release (prerelease flag follows the
  tag channel; `latest` floats on stable only). The old Docker Hub /
  `build.yml` + `build-dev.yml` workflows are removed.
* **Self-contained Dockerfile dashboard stage** — the React dashboard is
  built inside the image (`npm ci` + vite build + `404.html`), so CI and
  local `docker build` produce identical assets.

### Fixed (blockers shipped in alpha.2, found by P6 hardening)

* `PlatformRuntime` crashed on every construction: `CoreManager(...)` was
  called with a nonexistent `state_store=` keyword.
* Cold imports of the application blew up: the lazy app bootstrap re-entered
  itself through legacy modules (`ImportError: partially initialized module`).
  The builder now pre-seeds `app`/`scheduler` before importing them.
* `requirements.txt` was not even parseable by pip (`SQLAlchemy>=2.0<3` —
  missing comma breaks all installs and image builds); `GRPC>=1.76.0`
  referenced a nonexistent package (now `grpcio>=1.60`); added missing pins
  (`protobuf`, `PyJWT`, `jdatetime`, `rpyc`, `PyMySQL`, `psycopg[binary]`
  for the installer DB paths, `bcrypt>=4.2,<5` — passlib 1.7.x hard-fails
  hash/verify with bcrypt 5.x, verified empirically; and removed a duplicate
  `cryptography` line).
* `XRayCore` ran `xray version` at singleton construction →
  `FileNotFoundError` on any host without a pre-installed binary. It now
  tolerates a missing binary (version `None` until the core self-installs).
* Legacy tables were never created, which broke admin creation and every
  legacy CRUD path.
* CLI correctness bugs caught by the new harness (each with a regression
  assertion): compose image tag was never interpolated (install pinned a
  literal placeholder and `update` could never switch tags);
  `reset-admin`/`update-core` returned exit code 1 on success;
  `restore` aborted silently on manifests without an optional field;
  `doctor --json` mixed human logs into stdout and the jq transform dropped
  all but one check; `uninstall` missed its root guard; `update --version`
  now accepts bare `x.y.z` (normalized to `v…`); CLI file installation
  created its destination directory.
* **Full-project audit fixes (this release, all verified live):**
  * Startup crashed on newer Starlette: `app.routes` entries may be
    `_IncludedRouter` objects without `.path` — the subscription-path guard
    now walks the route tree defensively.
  * A missing dashboard bundle aborted the whole panel
    (`FileNotFoundError: build/index.html`). Non-DEBUG deployments now log a
    warning, keep the API fully up, and answer `/dashboard*` with an honest
    `503` JSON until assets exist (the Docker image ships the bundle built
    in-image).
  * The legacy schema was created **without the upstream singleton rows**
    (`system`, `tls`, `jwt`), so the very first API login crashed in
    `get_jwt_secret_key`. `0002_legacy_schema` now seeds them exactly like
    the upstream migrations did (deployment-random 64-hex JWT key,
    self-signed TLS pair, zeroed traffic counters) and never rotates or
    overwrites them on re-runs (regression-tested).
  * The Marzban→Zagros importer **silently dropped five per-host
    attributes** (`inbound_tag`, `allowinsecure`, `is_disabled`,
    `mux_enable`, `random_user_agent`): the plan built them, the apply path
    never persisted them. New `core_hosts.extras` JSON column (model +
    migration `0003_core_host_extras` with `{}` backfill) + the importer
    now writes them on insert and update (regression-tested).
  * `hostctl db-backup-sqlite` hand-rolled its SQLite URL parse; operator
    typos (e.g. 5-slash `sqlite://///…`) produced a confusing
    `invalid uri authority` error. It now parses with SQLAlchemy
    `make_url` and normalizes the path (both forms regression-tested).
  * `doctor`'s GHCR egress probe used HEAD against `/v2/`, which the
    registry answers with 405 — a healthy system was reported WARN. The
    check now compares status codes (200/401/405 = reachable).
  * Lint sweep: unused imports/variables removed from runtime code (the
    frozen upstream Alembic scripts under `app/db/migrations/` are
    historical artifacts and intentionally untouched); the two inherited
    `TODO` comments in legacy code were resolved into documented
    design/known-limitation notes — no `TODO`/`FIXME` markers remain in
    product code.
  * New regression coverage: 3 Alembic-revision tests (seed presence,
    no-rotation on re-seed, `0003` upgrade path + backfill) and host
    `extras` persistence assertions, 3 certificate-identity tests, and
    two CI-found fixes: `websocket-client` restored to requirements
    (masked locally by a preinstalled package; the in-container Alembic
    subprocess hard-fails without it) and the `distutils`-based
    subscription version-gating replaced with a stdlib-free comparator
    (`distutils` is gone on Python ≥ 3.12). Suite totals:
    **250 passed / 7 skipped** (verified twice: system Python and a
    fresh venv with CI-identical dependency resolution); E2E real-binary
    **6 passed / 1 skipped**; CLI harness **142 assertions green**.

### Changed

* All images are published **exclusively to GHCR**; Docker Hub references
  are gone from CI and docs.
* README: the supported installation path is the one-command installer;
  manual and development flows are clearly marked as such.
* **Full rebranding sweep (final Marzban-era remnants removed):**
  * New original brand assets: the Zagros mountain mark replaces the
    inherited logo in `app/dashboard/src/assets/logo.svg`, the complete
    favicon set (`favicon.ico`, 16/32/180/192/512 px PNGs, mstile,
    `safari-pinned-tab.svg`), and `site.webmanifest` now names the app
    "Zagros" (its icon paths were also wrong and are fixed).
  * Panel-generated TLS certificates now use `CN=Zagros`; node connections
    derive the expected TLS identity **from the peer certificate actually
    served by the node** (`ssl_target_name_for_cert`), so legacy
    Marzban-era node certs (`CN=Gozargah`) keep working without a single
    hardcoded brand name anywhere.
  * Panel-namespaced artifacts renamed `mz-*` → `zg-*` (SSH unix accounts,
    hysteria2/TUIC/SSH chain users, WireGuard chain peer comments, xray &
    sing-box chain inbound/outbound tags, xray base outbounds
    `zg-direct`/`zg-block`/`zg-dns`). All are Zagros-generated, so no
    migration concern exists.
  * `CONTRIBUTING.md` rewritten end-to-end for Zagros (forking, branch
    naming, coding style, commit convention, PR rules, driver development
    guide, multi-core architecture rules, testing, documentation, security
    policy, review process); `cli/README.md` and `app/dashboard/README.md`
    rebadged; dashboard README had a stale upstream clone URL.
  * README gained Community (Telegram channel/group, GitHub repos) and
    Contributors sections; the same Community block was added to the
    Persian/Russian/Chinese READMEs.
  * Remaining Marzban mentions exist only where they belong: `LICENSE`,
    provenance/attribution notes, migration code & docs (the importer
    reads Marzban v0.8.x databases by design), historical design/analysis
    documents, and changelog history.

[1.0.0-alpha.3]: https://github.com/ZagrosGM/Zagros/releases/tag/v1.0.0-alpha.3

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
