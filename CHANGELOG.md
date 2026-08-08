# Changelog

All notable changes to Zagros are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Zagros is a hard-fork re-engineering of the [Marzban](https://github.com/Gozargah/Marzban)
panel (v0.8.4, AGPL-3.0). Versioning restarts at `1.0.0-alpha.x` for the new
multi-core platform line.

---

## [1.0.0-alpha.7.3] — 2026-08-08 — CI hermeticity fix (functionally identical to alpha.7.2)

Un-breaks the release pipeline: the alpha.7.2 tag run failed in the `Test`
job on a clean GitHub runner (8 failed / 591 passed of 599). Investigation
pinned BOTH root causes to test code — production code reproduced clean in a
CI-identical environment. No functional delta vs `1.0.0-alpha.7.2`.

### Fixed — test suite hermeticity
- `tests/portal/test_host_settings_service.py`: relied on an undeclared
  pytest-asyncio install (bare `async def test_` + `pytest.mark.asyncio`)
  while the repo pins no such plugin — CI installs `requirements.txt +
  pytest` only, and the suite-wide convention is sync tests driving
  coroutines via `asyncio.run()`. All 7 tests converted to that convention
  (identical bodies and assertions); deterministic on any runner now.
- `tests/cores/test_softether_driver.py::test_install_reports_every_failed_stage`:
  the fixture left `_INSTALL_ROOT` at the real `/usr/local/softether`, so
  `_install_from_github`'s real `makedirs` both polluted the host and made
  the outcome depend on ambient permissions (writable locally, `EACCES` on
  CI runners). Redirected to `tmp_path`; every stage now fails only from
  the injected fault.

### Verified before tagging
- Full suite in a CI-identical venv (`requirements.txt` + pytest only):
  **599 passed / 7 skipped / 0 failed**; both failures reproduced
  byte-identically pre-fix.
- CLI suite **237/0**; `tsc --noEmit` + vite build clean; 21-check real
  browser e2e against a real panel boot: PASSED.
- Docker release path reviewed stage-by-stage (COPY paths, `npm ci` lock,
  fresh-env `pip install -r requirements.txt`, alembic-head boot).

## [1.0.0-alpha.7.2] — 2026-08-08 — Multi-core consolidation, host settings, portal UX

Field-driven batch: core architecture consolidation, hardened installers and
preflight diagnostics, a real per-core subscription portal, Marzban-parity
Host Settings, and a wave of dashboard fixes verified end-to-end in a real
browser against a real panel boot.

### Changed — core architecture (items 1, 14)

* **Hysteria2 and TUIC no longer exist as standalone cores.** They are
  inbound protocols on the sing-box core (`hysteria2`, `tuic` listeners),
  exactly where upstream keeps them; the panel now hosts six engines:
  xray, sing-box, wireguard, openvpn, ssh, softether.
  - `app/cores/consolidation.py` migrates existing deployments: granter
    mappings, inbound entries and core-access flags are re-keyed to
    `sing-box` via `alembic` revision `0007_core_consolidation` — verified
    end-to-end against a real alpha.7.1 database in a subprocess.
* **Legacy xray subscription removed entirely.** The subscription surface is
  the unified portal only; "Legacy Subscription" no longer exists in UI or
  API vocabulary.

### Added — Host Settings (item 13, Marzban-parity, independent implementation)

* New main-menu **Host Settings** page: per-core, per-inbound host entries
  with the full Marzban field set — Remark, Address, Host, SNI, Port, TLS,
  ALPN, Fingerprint, Fragment, Noise, MUX, AllowInsecure, RandomUserAgent,
  Wildcard, MultipleHost/MultipleSNI, variable expansion
  (`{SERVER_IP}`,`{PROTOCOL}`,`{TRANSPORT}`,`{USERNAME}`, salt `*`),
  priority ordering and per-user traffic overrides.
* Engine: `app/portal/hostengine.py` expands delivery sections through the
  host store (tag-exact matching; tagless sections expand only when the
  mapping is unambiguous — the engine never guesses). xray is deliberately
  skipped there (its legacy hosts table stays the single source for the
  built-in engine — no double expansion).
* Storage: `core_hosts` table gains `inbound_tag` (`0008_core_host_inbound_tag`),
  widened SNI/host columns, ordered `list_grouped`, tag-scoped `replace_tags`.
* Admin API: `GET/PUT /zagros/cores/{id}/hosts` (xray path maps to the legacy
  hosts table + live catalog reload; engine cores validate against the real
  inbound catalog — 404 unknown core/tag, 422 invalid port/security/ALPN/
  fingerprint).

### Added — subscription portal per-core UX (item 15)

* xray/sing-box: one QR-able share **link per granted inbound**; every
  section names its `inbound_tag` for the Host Settings engine.
* OpenVPN: downloadable `.ovpn` **file per listener** + username/password +
  server & security facts (transport, data ciphers, tls-crypt line, CA
  SHA-256 fingerprint derived from the real CA DER).
* WireGuard: QR-able `.conf` + address, server public key, endpoint, DNS,
  MTU, Allowed IPs, keepalive, peer identity and the preshared key when the
  operator enabled PSKs (secret; honestly absent otherwise).
* SSH: host/port/username/password per granted listener.
* SoftEther: one section **per compat transport** — L2TP/IPsec (+PSK),
  SSTP, PPTP and the OpenVPN clone with full connection facts; a missing
  advertise-host, an unset IPsec PSK or a disabled hub feature surfaces as
  an honest NOTE artifact instead of failing the whole delivery.

### Added — dashboard (items 6, 11, 12, 16)

* **Inbound wizard UX**: 4-step schema-driven stepper (protocol → transport
  → security → details & review) now with **Simple/Advanced modes**, per-field
  validation (required/int/port/tag-uniqueness), an authoritative
  **server-side preview** (new `POST /zagros/studio/{core}/wizard/preview`
  dry-runs the exact create patch and shows the unified diff), and
  **import-from-share-link** (new `POST /zagros/cores/{core}/wizard/import`
  parses vless/vmess/trojan/ss/hysteria2/tuic links onto THIS core's
  blueprint — never guesses a cell, honestly reports unmapped values).
* User/core-access picker is now a **tree**: all cores listed with
  tri-state checkboxes; a per-core ⋯ menu selects individual inbounds;
  everything is selected by default.
* **Username Generate button** in the user dialog: letters+digits,
  configurable length (4–32), up to 8 API-verified uniqueness attempts.
* The ⋯ row menus (Users/Admins/Templates) are portal-mounted floating
  menus that never render behind the page and close on
  Escape/outside-click/scroll; subscription **Copy works on plain-HTTP**
  deployments (Clipboard API → textarea fallback).
* Fixed a real click-blocking overflow: the username generate row could
  overlap the status select — the row now uses grid tracks (caught by the
  browser gate).

### Fixed — installer & diagnostics (items 2–5)

* SoftEther installs via a real 3-stage chain (package manager → pinned
  GitHub release binary → full source compile) with no hardcoded version.
* sing-box health check no longer reports Error while the core is Running
  (state precedence fixed at the source).
* OpenVPN preflight diagnoses the TUN device, NET_ADMIN, Docker
  capabilities and kernel module with host-specific fix hints; WireGuard
  "Operation not permitted" gets the same netdiag treatment.

### Fixed — provisioning & wizard integrity (items 7–10)

* "the wizard blueprint could not be loaded" eliminated: blueprints are
  generated dynamically per call and the `singbox`/`sing-box` id mismatch
  is aliased at the single canonical map.
* OpenVPN and SSH are multi-inbound like xray (multiple listeners with
  distinct tags and ports, applied additively) with port/subnet conflict
  validation.
* WireGuard inbounds can be authored while the core is stopped (keys
  materialize offline and publish on the next start).
* No provisioning may fail on missing credentials: SSH/OpenVPN/SoftEther
  mint secure random passwords server-side (manual always possible).

### Verification (item 17 gate, all green)

* Python suite **599 passed / 7 skipped / 0 failed** (real-binary sing-box
  checks self-skip when the pinned binary is absent).
* CLI suite **237 passed / 0 failed** against the faithful docker double.
* Dashboard `tsc --noEmit` clean; production build green.
* Repo browser-smoke (Playwright): anonymous load → login → user create →
  90 s soak → all 18 pages → overlay regression → 3× reload → logout/login.
* Targeted alpha.7.2 browser verification (21 checks): wizard
  import→preview→create→listed, mode toggle, per-field validation, tree
  picker, username generate (shape + configurable length), ⋯ menu portal
  placement + Escape, subscription copy feedback, subscription portal
  links + QR + 200, Host Settings page, zero page errors.

---

Hotfix release. Every issue reported against `alpha.7` was fixed **at the
root** — no workarounds, no hidden errors, fully backward compatible.

### Fixed — OS-level driver bring-up (items 1–4)

* **sing-box stats now actually work.** Upstream sing-box binaries ship
  without the v2ray stats API, so the driver's stats backend could never
  activate. Zagros now carries a pinned, checksum-verified vendor pipeline:
  `.github/workflows/vendor-singbox.yml` builds sing-box from source at a
  tag with the v2ray API enabled (amd64/arm64), publishes
  `sing-box-<version>-v2rayapi-linux-<arch>.tar.gz` + `sha256sums.txt` as a
  `vendor-singbox-<version>` release, and `app/cores/github_install.py`
  downloads the asset, verifies the SHA-256 (lines 105-126/177-196) and
  installs it atomically. The stats readiness path (`_stats_ready`,
  `app/platform` sing-box stats wiring) is covered by new tests.
* **OpenVPN starts on stock hosts.** `openvpn` preflight now checks for the
  TUN device and NET_ADMIN capability with actionable errors, and the
  installer compose template grants `cap_add: [NET_ADMIN]` and
  `devices: [/dev/net/tun:/dev/net/tun]` to the service.
* **WireGuard pulls its own toolchain.** Host dependencies
  (`wireguard-tools`/`wg`, `wg-quick`, `iproute2`, `iptables`) are checked
  and ensured by the driver (`_ensure_host_tools`) instead of failing
  cryptically mid-apply.
* **SSH driver bring-up chain is complete.** The driver walks the full
  `ensure_service` chain (install check → unit enable → start → verify) and
  refuses to drop a config that would take sshd off port 22 without an
  explicit guard, so enabling the SSH core can no longer lock
  administrators out of the host.

### Added — Studio wizard completion for every core (item 5)

* **No driver may answer "use Advanced Mode" anymore.** The wizard
  blueprint matrix now covers all 8 cores end-to-end (xray full transport
  × security matrix empirically validated against Xray 26.3.27 — 54/54
  cells; sing-box 26/26 cells against sing-box 1.12.4; hysteria2, TUIC,
  OpenVPN, WireGuard, SSH field sets). Single-listener engines
  (tuic/hysteria2/wireguard/openvpn/ssh) declare
  `CoreMetadata.studio_max_inbounds = 1` so the wizard replaces
  `/inbounds/0` instead of appending; other cores keep unlimited appends.
* **User-facing inbounds catalog stays in sync** with what the cores
  actually expose, and the dashboard wizards render `file` (upload +
  textarea fallback), `textarea` and `bool` field kinds natively
  (`Inbounds.tsx`). The banned "use Advanced Mode" message is gone — a
  retry banner appears on transient failures instead.

### Fixed — subscription & portal (items 6–8)

* **Dashboard subscription UI matches the backend auth modes**
  (`Subscriptions.tsx` canonical ids) and users list rows gained a
  copy-subscription-link button with a real tooltip
  (`ui.tsx::Tooltip`, hover/focus, `role="tooltip"`).
* **Access Mode = Application no longer 422s.** Root cause: portal
  settings accepted arbitrary strings for the subscription path/prefix and
  propagated them un-normalized, so `application_login` vs `app_login`
  style values from older payloads failed validation deep in the router.
  Fixed in `app/portal/models.py`: `ClientAuthMode` alias validator,
  `subscription_path` / `subscription_url_prefix` normalization (slashes
  stripped, regex-validated, garbage rejected with a clear `ValueError` →
  HTTP 422 with a *descriptive* detail), applied at both stores
  (in-memory + SQL). The router now serves the canonical
  `/zagros/sub/{token}` plus the settings-defined path
  (`/zagros/{sub_path}/{token}`, fail-closed 404), and
  `issue-subscription-token` returns the resolved `path`/`url` so clients
  never guess. Portal pages personalize with `app_name`.

### Fixed — core runtime hotfixes

* **Cold boot no longer crashes the xray job** on a fresh database:
  `app/jobs/0_xray_core.py` called `include_db_users()` unconditionally, so
  `sqlite3.OperationalError: no such table: users` killed startup before
  migrations finished. The job now probes the schema (`_schema_has_users`)
  and falls back to a file-only startup config with a CRITICAL log line
  instead of dying. New regression tests: `tests/jobs/test_xray_core_boot.py`.
* **sing-box `mixed` inbound keeps its users.** The native-entry
  translator dropped accounts for `mixed` inbounds (tuple only listed
  socks/http/naive); `mixed` was validated against the real 1.12.4 binary
  (`sing-box check`) with users present.
* **sing-box translator accepts socks + users and mixed + users**
  (empirically confirmed valid by `sing-box check`).
* **xray self-signed certificates are no longer re-minted on every
  apply** — `_materialize_certificate` reuses the existing on-disk pair
  per tag, removing cert churn and restart ripples.
* **WireGuard driver no longer raises `NameError`** on its log path
  (`logging` import added; the same latent bug class was fixed earlier in
  the SSH driver).

### Tests & verification

* Full Python suite: **490 passed, 7 skipped** (was 426), including new
  coverage: `tests/cores/test_alpha71_os_drivers.py`,
  `tests/platform/test_alpha71_singbox_stats.py`,
  `tests/platform/test_alpha71_studio_flow.py` (27),
  `tests/cores/test_alpha71_studio_drivers.py` (35),
  `tests/portal/test_item8_portal_settings.py` (9),
  `tests/jobs/test_xray_core_boot.py` (2).
* CLI suite (zagros-scripts): **237 passed**, including new assertions for
  compose NET_ADMIN + `/dev/net/tun`.
* Browser E2E (Playwright, real Chromium): login → user create → 300 s
  soak across 18 dashboard pages with reloads → logout/login — **passed**.
* Empirical binary validation: Xray 26.3.27 `xray run -test` (54/54
  wizard cells) and sing-box 1.12.4 `sing-box check` (26/26 cells).

---

## [1.0.0-alpha.7] — 2026-08-06 — Multi-core platform-user architecture (phase 1+2) + admin governance

### Added — multi-core platform-user architecture (Master Prompt phases 1+2)

* **ONE dashboard user holds protocols from ANY cores.** `core_access`
  (`{core_id: [inbound tags]}`) on users AND user-templates: create/modify
  applies a per-core grant diff through real driver provision/deprovision
  calls; template selection merges its grant map into the form; editing
  revokes removed inbounds only. Picker UI lists every core's inbounds
  grouped (xray group is the built-in legacy proxies surface).
* **The built-in xray is now a protected platform core.** Attached at
  runtime boot (the legacy Marzban engine, marked `builtin: true` in
  `GET /api/zagros/cores`): the bridge's per-user xray mirror rows finally
  materialize into the portal/subscription, the manager refuses
  uninstall/disable for built-ins (start/stop/restart stay legal — same as
  the legacy "restart core"), the dashboard hides destructive actions and
  shows a "built-in" badge, and the usage recorder skips built-in ids so
  xray traffic is never double-counted.
* **Unified shared quota across cores (spec §1).** `app/platform/usage_recorder.py`:
  every usage-capable core reports per-account deltas (drivers convert
  cumulative counters via DeltaTracker/SessionUsageTracker) → folded into
  exactly ONE counter set: legacy `used_traffic` (master), platform quota
  store, usage journal and persistent baselines (exactly-once across panel
  restarts, handed back via `restore_usage_baselines`).
* **Race-proof persistence.** Proven by the concurrent-pass test: a naive
  get-then-write previously lost quota increments or crashed on
  `usage_baselines`/`settings` UNIQUE keys. `SQLQuotaStore.add` now
  increments in one atomic SQL statement with retry-on-conflict insert;
  baseline and KV upserts retry into the UPDATE branch.
* **Global Device Limit (spec §3) + unified online (spec §4).** Legacy
  `users.device_limit` (+`device_limit_disabled` revive marker, alembic
  `0006`): a 30s reconciler counts each user's devices as the IP-union of
  every core (IP-blind cores like xray's stats API contribute one presence
  per online account — documented lower bound) and the 4th device on a
  3-device plan is rejected: user → `limited` on ALL cores; only users the
  reconciler itself limited are revived (quota-limited/expired users never
  resurrected). The same pass touches `online_at` on both stores when any
  core reports the user online.
* **Multi-format multi-core subscription (spec §7/§8).**
  `/zagros/sub/{token}` now negotiates by UA (and `?format=` override):
  clash/clash-meta/Stash → mihomo YAML, sing-box/SFA/SFI/SFM → complete
  sing-box 1.8+ JSON, v2rayNG/Streisand/Nekobox/Shadowrocket → the
  Marzban-convention base64 link list. Exact-duplicate links collapse,
  names stay unique, and anything a format cannot express is listed in
  YAML comments / notes — never fabricated.
* **Marzban-parity link rendering.** The platform xray delivery resolves
  the SAME template variables the legacy `/sub/` generator uses
  (`{SERVER_IP}/{USERNAME}/{DATA_USAGE}/{DAYS_LEFT}…` + `*` salting +
  per-protocol `{PROTOCOL}/{TRANSPORT}`) — the multi-core portal link and
  the legacy link for the same user are byte-identical in verification.
* Subscription tokens can be issued **by username**
  (`POST /api/zagros/users/by-username/{username}/subscription-token`);
  rotation invalidates older links immediately (fail-closed jti).

### Fixed — multi-core architecture follow-ups

* **Pydantic-v2 migration regression (Marzban parity).** `always=True` was
  dropped from the legacy `inbounds` validator at the v1→v2 port, so an
  API-created user without explicit `inbounds` silently ended with EVERY
  inbound excluded (empty subscription). `UserCreate.inbounds` now runs
  its default through the validator (`validate_default=True`): omitted →
  all inbounds of the selected protocols, exactly like v1. `UserModify`
  untouched on purpose (omission must mean "no change").
* Legacy subscription copy actions in the dashboard read a non-existent
  `sub_url`; they now use `subscription_url` (made absolute against the
  serving origin) — the edit dialog shows the legacy link again next to
  the new multi-core portal link section.
* The multi-core inbound catalog no longer lists xray twice (legacy
  running-config group wins; manager-attached entry suppressed).


### Added — admin governance (transaction-safe, race-tested)

* Admins gain four governance caps: **max_users** (user creation hard-fails
  with a Real 403 past the cap), **expire_at** (an expired admin can neither
  obtain a token nor use an existing JWT — both die with 401
  "Admin account expired"), **traffic_alloc_limit** (cap on the sum of the
  admin's users' `data_limit` — enforced on create AND on update), and
  **traffic_consume_limit** (cap on real consumed traffic — crossing it
  suspends ALL of the admin's users; raising/removing the cap revives exactly
  the users the reconciler suspended, manual disables never touched).
* All cap checks run under a dialect-correct row lock
  (`SELECT … FOR UPDATE` on PostgreSQL/MySQL, a same-value write lock on
  SQLite) inside the same transaction as the write — proven by a 9-thread
  race test that can never exceed the cap.
* A scheduler review loop re-enforces the consumption cap every tick (with
  dangling-flag repair when a cap is removed) and syncs the running core once
  per pass; the admin-modify endpoint enforces immediately and pushes
  suspend/revive transitions into xray best-effort (a core that cannot
  restart no longer 500s the request — the scheduler retries).
* `GET /api/admins` attaches live aggregates per admin: `users_count`,
  `users_allocated_traffic`, `users_lifetime_usage` (live usage + reset
  usage-log history), `created_at`.
* `zagros-cli admin create/update` exposes all four caps
  (`--max-users/--expire-at/--traffic-alloc-limit-gb/--traffic-consume-limit-gb`,
  interactive prompts for update) and `admin list` renders them.
* New idempotent alembic revision `0004_admin_governance` (legacy engine,
  MySQL TINYINT variant handled, full downgrade).

### Added — schema-driven outbounds + Import URL

* New `GET /api/zagros/outbounds/schema` endpoint: a full JSON-Schema per
  outbound kind (all 16 kinds) with `x-group` (basic/auth/transport/security)
  and `x-widget` hints. Every transport (tcp/kcp/ws/http/grpc/quic/
  httpupgrade/splithttp) and security (none/tls/reality incl. sni, alpn,
  fingerprint, reality keys) is described — the UI renders its form FROM the
  schema, nothing hardcoded.
* New `POST /api/zagros/utils/parse-share-url`: paste a
  vless/vmess/trojan/ss(+2022)/hysteria2(hy2)/tuic link and every field is
  extracted (address, port, uuid/password, flow, transport incl. ws path +
  headers, grpc service, httpupgrade, splithttp/xhttp, security, sni, alpn,
  fingerprint, reality pbk/sid/spx, ss2022 psk, hysteria2 obfs + port
  hopping). Bogus links return an honest 422 naming the supported schemes.
* OpenVPN outbound: complete credential form (`.ovpn` upload or
  username/password + CA/cert/key PEMs, proto/cipher/auth) and re-export —
  `GET /api/zagros/outbounds/export?name=…` downloads a synthesized `.ovpn`.
* WireGuard (private/peer/preshared keys, local address, DNS, MTU,
  keepalive), SSH, hysteria2 (obfs, port-hopping), TUIC (congestion, UDP
  relay), VMess (alter-id/cipher) profiles completed the same way; `core`
  outbounds chain another Zagros core.

### Fixed

* **Outbound name validation rejected uppercase and several legal characters
  —** regex widened to `^[A-Za-z0-9][A-Za-z0-9\-_.]{1,63}$`; covered by tests.
* **New-User dialog left the lower half of the page un-blacked and let the
  body scroll behind it** — the overlay layer was rendered `absolute inset-0`
  INSIDE a scrollable container. Rewritten: backdrop and dialog portal to
  `document.body` as fixed full-viewport sibling layers with a ref-counted
  body scroll lock (scrollbar-width compensated). Verified in a real browser
  on desktop, mobile (390px) and tablet (820px) viewports.
* Admin modify with governance transitions no longer 500s when the legacy
  xray binary is absent/restarting — core sync after governance changes is
  best-effort with scheduler retry (regression test included).

### Changed — dashboard (one proprietary Zagros panel)

* **Management nav group**: Users, **Admins** and **Templates** are main-menu
  pages (no longer buried in Settings); Settings keeps panel info + the
  advanced-mode gate only.
* New **Admins** page: per-admin rows with sudo marker, expired badge,
  users-vs-cap and lifetime-usage-vs-cap progress, allocation line, row menu
  (edit, disable/activate all users, reset usage counter, delete non-sudo)
  and a wide dialog with the governance section.
* New **Templates** page: card CRUD over `/api/user_template` with a
  per-protocol inbound picker (multi-tag), name prefix/suffix,
  data-limit/expire in GB/days.
* **User dialog**: create mode toggle — pick a *template* (pre-fills limit,
  expire and inbound selection) or *manual* (per-protocol inbound chips with
  ports); the subscription-owned access/auth fields were removed from the
  user form (users inherit their subscription — one source of truth).
* **Outbounds** page rewritten on top of the driver schema: grouped
  endpoint/credentials/transport/security rendering, conditional
  transport/security field visibility, Import URL block for URL-based kinds,
  `.ovpn` upload and per-card Export download.
* **Cores** page: install dialog with **Simple** (auto latest / pick a
  release from `GET /api/zagros/cores/{id}/versions` — GitHub-managed drivers
  only, others answer an honest 404 / start-after-install) and **Advanced**
  (full schema) modes; cards show version/status/CPU/RAM/binary/config paths;
  Reinstall keeps stored settings server-side via
  `POST /api/zagros/cores/{id}/reinstall`.
* **Config Studio**: visual tree editor (collapsible typed nodes, inline
  scalar editors, add/remove/convert) is now the default; raw document and
  patch ops are marked pro modes. All three funnel into the same
  validate/diff/apply pipeline.

### Backend — driver release management

* Driver metadata carries `release_repo` for GitHub-managed cores
  (XTLS/Xray-core, SagerNet/sing-box, apernet/hysteria, EAimTY/tuic);
  `fetch_recent_releases()` lists exact tags; xray and hysteria2 installers
  honor a `release_version` setting pinned as an exact `(tag, asset)` pair.
* `uninstall_core` no longer eats the operator's stored settings on reinstall
  — the reinstall endpoint snapshots settings and restores the running state.

### Tests

* `tests/adminapi/test_admin_governance.py` — 11 tests incl. race safety and
  the core-sync-failure regression; `tests/cores/test_shareurl.py` — 9 tests
  across every importable scheme; `tests/cores/test_release_pinning.py` — 3
  tests; platform API suite extended (schema completeness, parse endpoint,
  ovpn export roundtrip, versions honesty, reinstall).
* Phase-2 test surface (all new and green): `tests/platform/test_builtin_xray.py`
  (5), `test_device_limits.py` (4 — IP-union, 4th-device rejection + revival,
  quota/expiry guards, xray presence), `test_sub_formats.py` (5),
  `test_usage_recorder.py` incl. the concurrent-pass race test,
  `tests/adminapi/test_user_core_access.py` (11) and the alembic `0006`
  pre-existing-database test — **final suite: 375 passed / 7 skipped / 0
  failed** (run twice on the exact release commit: 172 s, 161 s).
* Real-browser smoke (`zagros-scripts/tests/browser-smoke.mjs`) now covers
  **18 pages** plus NEW hard gates: modal backdrop covers the viewport with
  body scroll locked (and releases on close), and the outbound dialog exposes
  the Import URL block. Login, 15 s soak, 3× reload, logout→login: PASS —
  re-run against the release-state server (fresh DB, migration `0006`
  applied).
* CLI suite: **235/235 passed**.
* Local E2E on a fresh booted server (current code, new database, admin
  created via env): user create with `device_limit` → 200; built-in core
  listed with `builtin: true`; uninstall/disable of the built-in xray →
  400 with clear messages; portal link for an active user renders the
  base64 share list (v2rayNG UA), a valid mihomo YAML (clash-verge UA),
  and a complete sing-box 1.8+ JSON (SFI UA) — the portal `ss://` link is
  byte-identical to the legacy `/sub/{jwt}` link for the same user;
  `device_limit` roundtrip 5 → clear → `-1` rejected with 422.

### Added — dynamic inbound wizard (field feedback)

* **The wizard is no longer a fixed list.** `GET /api/zagros/cores/{id}/wizard-schema`
  serves a per-engine blueprint (protocols × transports × securities × typed
  fields) and the dashboard renders a real stepper — Core → Protocol →
  Transport → Security → only the settings valid for THAT combination
  (xhttp exists only for Xray, REALITY generates its X25519 keypair at the
  panel, sing-box additionally hosts Hysteria2 and TUIC as protocols, …).
* **Studio changes now materialize.** Applied documents push into the core
  itself: sing-box adopts studio listeners as its inbound truth (users stay
  platform-driven, unmappable wizard fields fail loudly instead of being
  silently dropped), tuic adopts its single listener (cardinality enforced),
  engines without a live bridge reply with an honest `materialized: false`
  notice instead of pretending.

### Fixed — field feedback from the alpha.7 VPS report

* **`apt-get install` failed on fresh hosts/containers** ("Unable to locate
  package wireguard-tools / openvpn", "openssh-server has no installation
  candidate"): the images ship EMPTY apt lists. WireGuard/OpenVPN/OpenSSH
  installers now run `apt-get update` first (ordering covered by tests).
* **Hysteria2 install crashed** with `'LocalHysteria2Backend' object has no
  attribute 'settings'` — the backend now keeps the settings dict it
  receives (pinned-version path included).
* **SoftEther "Install Core" did nothing** — the driver claimed no
  SELF_INSTALL and raised instead. It now installs for real (apt
  `softether-vpnserver` where shipped, otherwise the official GitHub
  release tarball with `vpnserver`+`vpncmd`+`hamcore.se2` laid out under
  `/usr/local/softether` and symlinked onto PATH), then starts the daemon
  and confirms hub reachability.
* **Xray Start failed** with `ENOENT /usr/local/bin/xray`: the image ships
  no baked-in core binaries, so start/restart now self-installs the binary
  first (pinned release honored) targeting exactly the path the backend
  will exec.
* **Sing-box Start FATALed** with "v2ray api is not included in this
  build": official builds dropped the tag in 1.12. The driver probes the
  actual binary once and renders the experimental stats block only when
  supported; otherwise it starts cleanly and reports the accounting
  degradation honestly in status (`HealthStatus.DEGRADED` + message).
* **Studio wizard 422ed on stopped cores** — an empty studio document made
  the patch's parent list missing. Seeds now come from the drivers
  themselves (`export_config_document()` on xray/sing-box/tuic — pure
  renders that work while stopped), and the wizard creates a missing
  inbound-list parent instead of 422ing.
* **TUIC Studio was refused** ("no studio_inbounds_path declared") — the
  driver now exposes its listener to the studio (single-entry semantics).

### Fixed — hardening found while shipping alpha.7

* **A consumer that forgets `stop()` could hang process shutdown forever.**
  The xray core wrapper spawned its log-capture and lifecycle-callback
  threads as non-daemons; they block in `readline()` for the lifetime of the
  xray process, so any host process (CI test runner, CLI, future worker) that
  starts xray and exits without an explicit `stop()` pinned
  `threading._shutdown` indefinitely. These threads are daemons now —
  log capture and one-shot callbacks must never hold the interpreter hostage
  (root-caused on GitHub-hosted runners via faulthandler dump at
  `app/xray/core.py`).
* **The unit/integration suite no longer performs real binary downloads.**
  Because the driver now self-heals a missing xray binary on start, an
  app-booting test on a networked machine would fetch ~30 MB from GitHub and
  launch a real daemon. Tests that boot the app (adminapi/platform) now run
  with the installer blocked; the pin-resolution logic keeps RAW-installer
  coverage in `tests/cores/test_release_pinning.py`, and the self-heal
  contract stays pinned by `tests/platform/test_alpha7_fixes.py`. Real
  installs remain covered by the real-binary E2E suite.

### Known limitations

* **Real-VPS multi-core E2E still needs the community.** Every Phase-2 gate
  that can run off a VPS is green here (unit/integration, CLI, real-browser,
  fresh-boot local E2E, driver contract tests), but xray + sing-box +
  WireGuard + SoftEther serving *real traffic on a real server* has not been
  exercised yet. A turnkey workflow exists for exactly this
  (`zagros-scripts/.github/workflows/e2e.yml`); help running it on real
  hardware is tracked on the roadmap and in a pinned issue.
* **PPTP/SSTP/L2TP are served through the SoftEther core** (same platform
  contract as every other protocol: unified quota/device-limit/subscription)
  — code-complete and integration-tested, live-verification pending with the
  rest of the real-VPS E2E.
* **TUIC accounts no usage** by design: the protocol exposes no per-user
  counters, so TUIC traffic honestly cannot be measured; it is delivered but
  not quota-accounted.
* Device counting is an explicit union: distinct client IPs where a core
  sees them, plus one presence per online account for IP-blind cores (xray)
  — a documented lower bound, never an invention.

---

## [1.0.0-alpha.6] — 2026-08-06 — Dashboard stability + full uninstall hardening

### Fixed — panel went white seconds after load (Blocker #1)

* **Root cause (verified in a real headless-browser repro against a live app,
  not guessed):** the SPA's `Snapshot` type declared fields the backend has
  never sent — `totals.users / totals.online_users / version / uptime_seconds`,
  while `/api/zagros/dashboard/snapshot` returns flat fields
  (`users_total`, `users_online`, …). The first render of **Overview** hit
  `undefined.online_users`, and with **no ErrorBoundary anywhere** in the tree
  React unmounted the entire app — white screen on every load and every
  refresh. Types now mirror the backend contract exactly; Overview reads the
  real fields (version comes from `/api/system`).
* **Structural guarantee:** new global `ErrorBoundary` (main.tsx) plus a
  per-page boundary around the router `<Outlet/>` (keyed by pathname). A crash
  in one page can never white-screen the panel again — the shell stays alive
  and a recovery card (reload / back to overview + technical detail) is shown.
  Verified live: a real render error was caught and the rest of the panel
  kept working.
* `AppLayout` no longer calls `navigate("/login")` during render (illegal in
  React Router v6 — the unauthenticated redirect now happens in an effect).
* Users table no longer renders the raw `admin` value (the API returns an
  admin **object**, which React refuses to render — error #31); owner cell
  handles `{username}` objects and plain strings.
* Fixed `GET /api/user_template` path (was wrongly requested plural
  `/api/user_templates` → 404 on the Settings page). Verified zero HTTP ≥ 400
  across all 16 pages.
* Added `online_users` to the `SystemStats` type (present since Marzban,
  missing from the SPA's contract).
* Live bandwidth chart no longer emits an invalid SVG path for an
  empty/degenerate series (baseline line instead).
* **Contract guard added:** `tests/platform/test_snapshot_contract.py` pins
  the SPA↔backend snapshot/panel-info agreement at HTTP and Pydantic-model
  level — a breaking rename (another invented/removed field) now fails CI
  instead of white-screening the panel again. The real-browser smoke
  (Playwright: login, 5-min soak, all 16 pages, reloads, logout/login, zero
  console/pageerror) is wired into the real-VPS E2E workflow
  (zagros-scripts `tests/browser-smoke.mjs`).

### Changed — `zagros uninstall` is now a full uninstall (Blocker #2)

* **There is no `--purge` anymore.** The single `zagros uninstall` command
  destroys everything Zagros created and then verifies the system is clean:
  containers (`zagros`, `zagros-db`, any `zagros-*`), panel images
  (`ghcr.io/zagrosgm/zagros:*`), DB images the installer provisioned
  (`mysql`/`mariadb`/`postgres`), named volumes `zagros-*`, networks
  `zagros-*`, `/opt/zagros` (compose, `.env`, state), `/var/lib/zagros`
  (SQLite file, MySQL/PostgreSQL data dirs, cores, certificates, TLS keys,
  runtime data, logs, backups, CLI cache), `/etc/zagros` leftovers and the CLI
  binary itself. External databases the installer did not provision are
  untouched by design. (CLI change in the `zagros-scripts` repo.)
* A **removal summary** (counts of containers / images / volumes / networks /
  databases / configurations / certificates / runtime data / logs / backups)
  is printed **before** anything is deleted and asks for confirmation.
* After deletion an automatic **verification sweep** re-checks
  `docker ps -a`, `docker images`, `docker volume ls`, `docker network ls` and
  the three directories; any leftover is force-removed and re-checked, and an
  incomplete uninstall fails loudly instead of claiming success.

### Verification (all run for real, no claimed greens)

* Headless-Chromium scenario against the real FastAPI app: fresh visit →
  login via the UI form → all 16 pages with per-page **full reload**, SPA
  navigation chain, logout/login cycle, 6× refresh storm, UI-driven user
  creation (dialog → POST → persists), theme & RTL/LTR toggles, command
  palette, and a **5-minute continuous soak (36 navigation+reload cycles)** —
  **0 page errors, 0 HTTP ≥ 400**, white screen gone.
* Panel Python suite: **294 passed / 7 skipped** (unchanged).
* CLI suite: **222 assertions passed** (new full-uninstall coverage: docker
  objects + stray volumes/networks + leftover files + `/etc` + reinstall).
* ShellCheck v0.10.0 clean on `zagros`, `zagros.sh`, `tests/test_cli.sh`.
* Real-VPS E2E workflow extended to the full checklist: install → admin →
  login → create user → install sing-box (+xray best-effort) → dashboard
  probes → refresh storm → 5-minute watch → backup → restore → full uninstall
  → spotless-system verification (docker ps/images/volumes/networks,
  systemctl, crontab, /opt /var/lib /etc /usr/local/bin) → **reinstall on the
  wiped system** → 200 again.

---

## [1.0.0-alpha.5] — 2026-08-05

**Status: ALPHA.** **The single-panel milestone** — the two-panel architecture
is gone for good. Exactly one management interface exists now: the new
Zagros dashboard at `/dashboard/`, a React 18 SPA designed and written from
scratch (860+ KB → ~210 KB initial gzip with per-page lazy chunks).

### Added

- **Unified Zagros dashboard (new, from scratch).** Replaces the inherited
  Marzban React/Chakra application entirely: custom design-token system
  (dark + light), full RTL (فارسی) and LTR with instant switch, command
  palette (⌘/Ctrl+K), skeleton loading, empty states, toast system, modern
  dialogs/drawers, glass topbar, hand-rolled SVG live charts (no chart lib),
  memoized pages, route-level code splitting and a virtualized users table.
- **Cores page** — complete in-panel lifecycle over `/api/zagros`:
  catalog (driver registry), schema-driven install (no hardcoded settings
  forms), start/stop/restart/enable/disable/update/uninstall(-purge),
  live status/metrics cards and a streaming logs drawer. No CLI needed for
  daily core operations.
- **Routing page** — graphical Rule Builder (matchers as chip fields:
  inbounds/domains/geosite/country/CIDR/ports/protocol/network/process;
  actions incl. route-to-outbound), drag & drop reordering with automatic
  priority renumbering, dry **preview** per core and one-click **deploy**.
- **Outbounds, Inbounds, DNS, Certificates pages** — outbound cards with
  health latency tests (real TCP dials), clone/edit/enable; protocol-shape
  inbound wizard (Reality/VLESS/VMess/Trojan/SS2022/Hysteria2/TUIC/WireGuard)
  rendered against the studio service; structured DNS resolver editor with
  health hints and templates; certificate inventory with *validated* PEM
  import (key-pair match enforced), self-signed generation and delete.
  ACME is explicitly labeled Roadmap.
- **Sessions / Devices / Nodes / Subscriptions / Settings pages** — live
  core sessions plus app sign-in (refresh-token) revoke, device inventory
  with forget, node CRUD + reconnect, portal identity & access-mode settings,
  admins CRUD and the **Advanced Mode** gate.
- **Advanced Mode (in-panel Config Studio)** — the only place JSON is shown:
  raw per-core document editing or RFC-6902 patch-builder with schema
  validation + unified diff preview before apply.
- **Users page** — advanced filters (status/owner), bulk enable/disable/
  delete, inline status toggle, create/edit dialog covering data limit /
  expiry / protocols (from live inbounds) / access mode (**Subscription
  link vs Application login**: app username + Telegram ID) / note, quick
  actions (copy sub link, revoke subscription, reset usage).
- **Backend admin API (`/api/zagros`)** powering all of the above: cores
  registry+lifecycle, routing rules CRUD/validate/dry-preview/deploy,
  outbounds CRUD + manager sync + real connection test + deploy, sessions +
  app sessions + devices inventory, certificate scan/import/self-signed/delete,
  panel info. Routing model gained inbound-tag matching with xray
  (`inboundTag`) and sing-box (`inbound`) translations.

### Removed

- **The inherited Marzban dashboard** (`app/dashboard` React/Chakra SPA,
  ~2.7 MB vendor bundle) — deleted and rewritten, per the one-panel rule.
- **Standalone `/zagros/dashboard` and `/zagros/studio` HTML pages** and the
  repo-root `ui/` directory — Config Studio is now Advanced Mode *inside*
  the single dashboard; no second management surface exists.
- JSON-forced operator flows — JSON appears only inside Advanced Mode.

### Fixed

- Certificate name regex (a dash inside the character class was parsed as a
  range), certificate scan managed-layout naming and per-name dedupe.
- Outbound manager sync is now a true rebuild (idempotent across saves).
- `GET /api/zagros/cores/{id}` returns 404 for unknown cores instead of 500.

---

## [1.0.0-alpha.4] — 2026-08-05

**Status: ALPHA.** Complete redesign of the configuration system:
`.env`-first (Marzban parity, but better), nothing hardcoded in the image,
and the real root cause of the `UVICORN_HOST=0.0.0.0`-not-applied bug fixed
and proven with a live bind test.

### Fixed

- **`UVICORN_HOST` is now honored verbatim — the 127.0.0.1 trap is gone.**
  Root cause (upstream Marzban behavior): when no TLS files were configured,
  `main.py` printed a warning and then *silently overwrote* the bind host
  with `127.0.0.1`, ignoring the operator's `UVICORN_HOST` entirely. Zagros
  replaces that silent security decision with a loud, detailed warning —
  the configured host is applied in every mode. Verified live:
  `ss -lntp` shows `0.0.0.0:8000` with `UVICORN_HOST=0.0.0.0` and no TLS.
- `DEBUG=true` no longer overrides the bind host/UDS (it now only controls
  reload + log level, as its name implies).
- `.env` loading no longer depends on the process working directory.
  `app.env_loader` resolves `<project-root>/.env` from the package location,
  so `alembic upgrade head`, the panel, and `hostctl` all see the same file
  regardless of CWD.

### Added

- **`.env` as the single configuration source of truth** (new module
  `app.env_loader`, used by `config.py`, Alembic's env, the platform
  runtime, and hostctl). Precedence: real process environment (tests/CI
  only) > `.env` file > built-in defaults. Docker deployments only MOUNT
  the file — edit `.env`, then `zagros restart` applies everything, exactly
  like Marzban.
- **Automatic legacy migration**: an existing `zagros.env` next to the
  config location is migrated to `.env` on first boot (kept as
  `zagros.env.migrated` for audit). The host CLI performs the same
  migration before any command.
- **`TLS_MODE`** (`auto` default / `on` / `off`): `auto` enables TLS when
  both `UVICORN_SSL_CERTFILE`/`UVICORN_SSL_KEYFILE` are set; `on` *requires*
  TLS and refuses to boot without it; `off` forces plain HTTP for reverse
  proxy setups. A half-configured TLS pair now fails fast with a clear
  message instead of silently binding plain HTTP. Optional
  `UVICORN_SSL_CA_CERTFILE` is forwarded to uvicorn (`ssl_ca_certs`).
- **Identity settings**: `DOMAIN`, `PANEL_BASE_URL`, `APP_BASE_URL`.
  When only `DOMAIN` is set, panel/app base URLs *and* absolute
  subscription links are derived automatically.
- **Canonical subscription settings**: `SUBSCRIPTION_URL_PREFIX`,
  `SUBSCRIPTION_PATH`, `SUBSCRIPTION_TEMPLATE`. Legacy names
  (`XRAY_SUBSCRIPTION_URL_PREFIX`, `XRAY_SUBSCRIPTION_PATH`,
  `SUBSCRIPTION_PAGE_TEMPLATE`) stay accepted as fallbacks — existing
  deployments boot unchanged.
- **`TRUSTED_HOSTS`**: opt-in HTTP Host-header allow-list
  (`TrustedHostMiddleware`); empty default installs no middleware.
- Complete grouped `.env.example` in Marzban style covering every setting
  (identity, bind/TLS, database, security, subscription, drivers, nodes,
  Telegram, webhooks, jobs; SMTP/OAuth documented honestly as reserved).

### Changed

- The repository's sample `docker-compose.yml` now mounts `./.env` into the
  container (`/code/.env`) instead of injecting it via `env_file:`, matching
  the installer-generated deployment, and points at the GHCR image.

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
    CI-found fixes: `websocket-client`, `typer` and `python-dateutil`
    restored to requirements plus an explicit `protobuf` pin (all were
    masked locally by preinstalled site packages); the
    `distutils`-based subscription version-gating replaced with a
    stdlib-free comparator (`distutils` is gone on Python ≥ 3.12);
    Dockerfile copies `chakra.config.ts` before `npm ci` (the
    `gen:theme-typings` postinstall hook requires it); the lazy app builder
    no longer constructs the FastAPI app when legacy modules touch
    `from app import scheduler` at import time (`_ensure_scheduler` is now
    an independent, single, process-wide instance) — this closes the
    circular-import landmine that broke `zagros-cli` inside fresh
    environments. Dashboard build verified end-to-end locally
    (`tsc && vite build` green). Suite totals:
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
