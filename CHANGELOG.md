# Changelog

All notable changes to Zagros are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Zagros is a hard-fork re-engineering of the [Marzban](https://github.com/Gozargah/Marzban)
panel (v0.8.4, AGPL-3.0). Versioning restarts at `1.0.0-alpha.x` for the new
multi-core platform line.

---

## [1.0.0-alpha.9.4.4] — 2026-09-01 — one bad name must not cost 338 users

Importing 3x-ui on top of Marzban failed with a UNIQUE violation and a 500.
The username column is NOCASE-unique, so the 3x-ui client `Admin` (which
normalises to `admin`) is the same name as the Marzban user `Admin` — but the
duplicate check compared names case-sensitively, and the INSERT was inside one
batch commit, so the single rejected row took the whole import down with it.

### Fixed

* Usernames are compared the way the database compares them (case-insensitive),
  against both the existing rows and the batch being imported.
* Each user is committed on its own: a name that cannot be stored costs that
  one user and is reported, instead of aborting the other three hundred.
* An unrecognised data-limit reset strategy falls back to `no_reset` rather
  than failing the insert.

---

## [1.0.0-alpha.9.4.3] — 2026-09-01 — the user list stays reachable

9.4.2 put imported users into the panel's user list. Verifying that live
showed the list then answered `500`: proxy settings arrive from a JSON *text*
column, so they are a string, and the response model rejects a row whose
settings are `'{"id": ...}'` instead of `{"id": ...}`. The import succeeded
and the user list became unreachable — worse than before, because now it had
338 users in it.

### Fixed

* Proxy settings are parsed into a mapping before they are stored, so
  `/api/users` can serve the rows it now contains.

---

## [1.0.0-alpha.9.4.2] — 2026-09-01 — Imported users now appear in the panel

9.4.1 made restores run end to end. What it did not catch: they ran against
the wrong half of the panel's storage.

The panel keeps users where Marzban kept them — the legacy store — and that
is what ``/api/users`` and every user-facing feature reads. The migration
pipeline wrote the *platform* store instead. So a Marzban restore reported
``users_migrated: 338``, wrote 338 rows, and the user list did not change.
The operator saw "successful" and got nodes.

### Fixed

* **Imported users are written to the panel's user list.** Each imported user
  becomes a real panel user carrying its data limit, used traffic, expiry,
  device limit, status and proxies — so it can be listed, edited and served.
  Hosts and nodes were never the problem; the users were.
* **3x-ui clients keep their protocol.** Newer 3x-ui exports link clients to
  inbounds through ``client_inbounds``, not a column on ``clients``. Reading
  the link the old way left every client protocol-less, so users imported
  with no configuration at all.
* **One configuration per protocol.** A client attached to three inbounds
  produced three identical rows; it now produces one, as the model expects.
* **Unsupported protocols are named.** The panel's store holds vmess, vless,
  trojan and shadowsocks. A client on anything else is imported as a user and
  reported, instead of being dropped without a word.

### Notes

* Inbound definitions, outbound rules and routing belong to a core's own
  configuration, not to a panel's user database, so they are not part of a
  migration. Marzban's inbound **host** rows are imported (71 in the sample
  backup).

---

## [1.0.0-alpha.9.4.1] — 2026-08-31 — Restores that accept what operators actually have

9.4 shipped backup and restore, and the first real archives an operator tried
showed how narrow "restore" had been: three uploads, three refusals, and one
of them was our own. Every failure came from assuming the upload would look
like the archive we write.

### Fixed

* **Other formats are accepted.** Marzban's own backup is a **zip holding a
  MySQL dump** (`db_backup.sql`), not a database file; 3x-ui exports are often
  a **bare `x-ui.db`**. Uploads are now classified by their bytes rather than
  their name, so a zip, a bare database or a `.sql` dump all restore. The SQL
  dump is replayed into a throwaway database first (MySQL string escapes and
  `ENUM('a','b')` translated), so Marzban's 338 users import with their
  traffic, hosts and admin intact.
* **Restores no longer die on a running binary.** Unpacking panel data over a
  core that is executing raises `Text file busy`, which used to abort the
  restore half way through — leaving the panel worse than before. An in-use
  file is now skipped and named in the report; everything else still lands.
* **Refusals are answered, not crashed.** "No database found in this archive"
  reached the operator as an opaque `request failed (500)`. Every refusal is
  now one exception family the API translates into a message that says what to
  do.
* **Imported admins can sign in.** Hashes from Marzban and Pasarguard were
  stored behind a `legacy:` prefix that nothing on the login path understood,
  so every imported admin was quietly locked out. Those hashes are bcrypt —
  the same scheme we use — and are now kept as-is, so the admin keeps the
  password they already had. Sources we genuinely cannot verify (3x-ui) still
  get a fresh password, shown once.
* **A second import is a no-op again.** Marzban routinely carries a dozen
  hosts sharing remark and address; the idempotency check assumed one row and
  crashed on the second run.
* **Cross-engine restore.** A panel running MySQL cannot adopt a SQLite file,
  so in that case the archive's rows are imported through the migration
  pipeline instead of the file being copied — and the report says which
  happened.
* **Change version is offered for the master's xray.** The button was hidden
  behind the same flag that forbids *uninstalling* the panel's built-in
  engine; version updates were never blocked.
* **The SSH accounting message named a command that does not exist on a
  node.** It now says the collector has to run on the host that runs the core,
  and `install-node.sh` installs it — previously only the panel's installer
  did, so a node's SSH core was permanently degraded.

### Notes

* Fixes to the host CLI and node installer ship in `zagros-scripts`; an
  existing node picks up the SSH accounting collector when its installer is
  re-run.

---

## [1.0.0-alpha.9.4] — 2026-08-31 — Settings becomes a real section: backup, restore, security

Settings was one page with three cards, and the two things an operator reaches
for after a bad evening — "do I have a backup?" and "can I get it back?" — were
not in it at all. Backups lived on the host behind a CLI command, and there was
no way to come back from another panel.

Settings is now three sections: **General** (unchanged), **Security**, and
**Backup & Restore**.

### Added

* **Backups on demand and on a schedule.** One button archives the database,
  configuration, certificates, core state and templates into a single
  `tar.gz`. The same archive can be produced hourly, daily, weekly or on a
  custom cron and delivered to a Telegram chat; the bot token is stored
  encrypted and never sent back to the browser. Copies beyond the retention
  count are pruned.
* **Restore, from this panel or another one.** An archive is uploaded,
  inspected and only then applied — preview first, so nothing is written
  before the operator has seen what it contains. Archives from **Marzban**,
  **Pasarguard** and **3x-ui** are imported rather than restored: users,
  their traffic and device limits, hosts rebuilt from inbounds, and admins.
* **The panel restarts itself after a restore.** A restore replaces the
  database under a running container, so it is only finished once the panel
  comes back up. The panel cannot restart itself, so it asks the host agent to
  do it, and reports honestly when no agent is installed instead of implying
  the work is done.
* **Security section.** An operator can change their own username and
  password (verified against the current one), see client sessions and revoke
  any of them, and set the admin token lifetime from the panel.

### Fixed

* Two backups started in the same second overwrote each other silently: the
  archive name had one-second resolution. Names are now unique.

### Notes

* Passwords from 3x-ui and Pasarguard are stored in formats Zagros cannot
  verify, so imported admins are issued a fresh random password which the
  restore report shows exactly once. Importing a panel you cannot read the
  logs of is a lockout waiting to happen otherwise.

---

## [1.0.0-alpha.9.3] — 2026-08-30 — The admin API no longer depends on import order

A latent one, found while verifying 9.2: `app.models.admin` and `app.db` import
each other, so the admin model is only importable once the DB package has been
initialised. The sudo dependency behind every admin endpoint was resolved at
import time inside a silent `except Exception`, so whichever module Python
happened to import first decided whether the admin API served real requests or
answered 503 — with no log line and no failing test to explain it.

### Fixed

* **The import order no longer decides whether the admin API exists.** The DB
  package is imported before the admin model, which always breaks the cycle.
  It still fails *closed* when the stack genuinely is unavailable; the
  difference is that the reason is now logged instead of swallowed.
* One test-file ordering that produced 36 failures now produces 63 passes —
  the full suite was always green, which is exactly why nothing caught this
  sooner.

---

## [1.0.0-alpha.9.2] — 2026-08-30 — A new user connects, the counters are honest, and the page is yours

Three things reported from real use: a user created *after* the last sync was
handed a config that looked right and never connected, the Overview's *Online
now* tile counted everybody seen in the last 24 hours, and serving your own
subscription page needed shell access to the server.

### Fixed

* **A newly created user never reached the node.** Accounts were only ever
  pushed to a node by an explicit *sync*, so a node kept serving the account
  list it was last handed: users who already existed connected, a user created
  afterwards did not — and the config they were given pointed at the node, so
  it looked correct while failing. Accounts now travel on one shared path that
  every user-mutating operation uses (create, modify, remove, delete, expiry,
  device-limit cut-off, and the two bulk admin operations), with a 30s sweep
  that re-asserts until the agent confirms. Each push is digested per core so
  a node already in sync is skipped, and every node is re-asserted every 20
  minutes so an agent restart heals by itself. Verified live: a new user
  connected through the node with no manual sync.
* **"Online now" counted the last 24 hours, not this moment.** The tile read a
  field that counted every user seen in the past day — on a live panel it
  showed 4 of 5 while nobody was connected, and it could never agree with the
  presence dots on the Users page. The tile now reads the same multi-core
  presence pass those dots do; where presence is unavailable it falls back to
  the 90s rollup, and shows a dash when nothing answered — never a fabricated
  zero, never the 24h figure.

### Added

* **Your own subscription page.** Upload an HTML template in
  *Subscriptions → subscription page template* and pick it; *download starter*
  hands you a working template to edit. Marzban needed an environment
  variable and shell access for the same thing. Names are sanitised into one
  flat managed directory, the setting stores a file *name* and never a path,
  values are escaped as they render, and — the rule that matters — a template
  that is missing or broken serves the built-in page and logs why, so a
  subscriber never pays for an operator's typo.

### Changed

* The legacy `/api/system` `online_users` field now uses the 90s window the
  platform already used for presence, so any other consumer of it stops
  mistaking "seen today" for "connected now".
* `GET /api/zagros/users/online` also returns `counts`, so an aggregate can no
  longer drift from the per-user states it summarises.

---

## [1.0.0-alpha.9.1] — 2026-08-30 — A node joins without being hand-held

Three ways a node used to need an operator to finish what the panel had
started. All three are now automatic.

### Added

* **Automatic node attachment.** A node that was added but not yet paired is
  re-checked on a 45s sweep: the agent is discovered on its info port and
  paired with the one-time token, so installing the agent on the server is the
  last manual step. Unpaired nodes are retried on every sweep — there is no
  state to protect while waiting for the installer, so there is nothing to back
  off from.
* **Reconnect button** on every node card (paired or not) for the cases where
  waiting is not what you want.
* **Reconnect on boot.** Restarting the panel re-proves every native node's
  pairing in the background, so a restart no longer leaves the nodes page
  looking stale.
* A node whose heartbeat fails is told apart from one that was never paired:
  an agent that has been reinstalled says the token must be *rotated*, because
  the old one is spent, instead of asking you to re-run a dead command.

* **Change version** on any core, master or node: pick a published release —
  higher or lower — or pin a tag by hand. The list comes from the core's own
  upstream repository, the installed release is marked, and applying it keeps
  settings, data and accounts. Cores that the OS installs instead explain why
  they have no list rather than offering an empty picker.

### Changed

* The master's **upgrade** button is gone (change version says what it
  actually does), and a node's core card no longer offers per-core
  **settings** or **update** — a node is configured by sync, not by hand.
* The cores/catalog tabs sit in the same place for the master and for every
  node.
* The node installer command now points at **zagros-scripts**
  (`install-node.sh`), preferring the tag that matches this panel's version
  and falling back to `main` when that tag does not exist yet. The script and
  the `zagros-node` CLI no longer live in the agent repository.

### Fixed

* **Cores now start when they are installed.** Installing or updating a core on
  a node converges it immediately — configuration, then start — instead of
  leaving a core that cannot serve anything until someone presses *sync
  config*. The same convergence runs the moment a node pairs.
* Pairing no longer loses its own registration token when the agent was
  reinstalled: the token is stored under the identity the panel knew when it
  was issued, and is now found under either identity.
* Heartbeating healthy nodes is throttled (every 8th sweep) and failing nodes
  back off (45s → 90s → 3m → 5m), so a down node is not hammered and a healthy
  one is not polled to death.
* `update(version)` used to **ignore the version**: xray and sing-box read
  their release pin from settings and dropped the argument, so any version
  change silently reinstalled the release the core already had. Both now
  honour it (pptp already refused any other pin, correctly).

---

## [1.0.0-alpha.9] — 2026-08-29 — Multi-node: a node serves traffic the panel can meter

### Added

* **Nodes menu** in the dashboard: create → discover → pair (certificate-pinned
  fingerprint), a copy-paste installer command, a per-node **Cores** tab
  (settings, lifecycle, live logs), heartbeat with resource metrics, and an
  audit trail of privileged operations.
* **`ZagrosGM/zagros-node`**: a standalone node agent that supports *every*
  core — xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther and PPTP — not just
  Xray. The core drivers are vendored, so a node runs the same code the panel
  runs. Bootstrap/info on `:62051` (node id, certificate, SHA-256 pin), signed
  HTTPS control plane on `:62050`.
* **Server identity federation**: a node adopts the master's CA, server keys and
  IPsec PSK, so a config whose address points at the node keeps authenticating
  the same server instead of being handed a different PKI per node.
* **Account federation** to nodes: Xray through the config document, every
  other core through an explicit signed accounts push over the control plane.
* **Node telemetry**: `GET /v1/runtime/devices` and `GET /v1/runtime/usage`
  report a node's online sessions and per-account usage deltas. The panel folds
  them into the same pipelines its local cores feed — device/online view and
  quota — applying the node's `usage_coefficient` and keeping durable baselines
  so an agent restart cannot re-emit a whole cumulative counter.
* **Bandwidth enforcement on nodes**: shaping is host-local (`tc`/`nft` only
  affect the machine carrying the packets), so the panel hands each node the
  decision its own limiter would have built (`PUT /v1/bandwidth/limits`). A 60s
  job keeps nodes in step behind a digest gate, and `/bandwidth/reconcile`
  pushes to nodes too. Pushed limits survive an agent restart.

### Fixed

* A user connected through a node was reported **offline**, consumed **no
  quota** and was **never limited**: presence, usage and shaping were all
  derived from the panel's own cores only. Verified live — a 15.2 MB download
  through a node raised the user's usage by 16.4 MB, `online_at` tracked the
  session, and a 2 Mbps pushed limit measured 1.75 Mbps.
* Presence is keyed per node when a core reports no client IP, so two nodes
  serving the same account no longer collide into one device.
* A node-side accounting failure can no longer abort the local cores' pass, and
  a local failure can no longer discard node deltas: both are committed
  separately, each only once durable.
* Node agent: compatibility shims shadowed the vendored `app.platform.bandwidth`
  and crashed startup in a loop. A module the vendored tree ships is never
  shadowed now.
* Node agent: sing-box per-user accounting was dead — the image carried no
  `xray_api` and no `grpcio`/`protobuf`, and the driver reads counters over the
  StatsService gRPC dialect. Both now ship with the agent.
* Node agent: accounts lived only in the drivers' memory, so a restart silently
  disabled shaping (identities resolve from account settings) while serving,
  presence and usage all looked healthy. Accounts are cached under
  `<data_dir>/accounts/` and replayed at boot.

### Changed

* `app/platform/bandwidth.py` takes an injectable `desired_provider`, so the
  module can be driven where no user database exists — the node agent vendors
  it and has none.
* Node fan-out is isolated per node: one unreachable node is reported honestly
  and never distorts the others.

### Tests

* Full panel suite: **987 passed / 7 skipped**.
* New `tests/platform/test_node_telemetry.py` (7 tests) pins all three
  behaviours end to end: presence with and without a client IP, usage
  coefficient and zero-delta handling, quota folding, per-node push reporting.

---

## [1.0.0-alpha.8.8] — 2026-08-22 — Unified accounting and aggregate bandwidth enforcement

### Added

* Added one persistent per-user traffic total across Xray, sing-box, OpenVPN,
  WireGuard, SoftEther native, SSTP, L2TP/IPsec, raw L2TP, PPTP/ACCEL-PPP and
  SSH forwarding. Provider counters feed one journal/quota identity without
  double counting across reconnect, process generation changes or resets.
* Added `download_limit_mbps` and `upload_limit_mbps` to legacy and platform
  users. Both are strict non-negative integers in Mbps; `0` is Unlimited and
  remains the upgrade default for every existing user.
* Added real kernel datapath enforcement with one standalone global `tc police`
  action per User/direction. IPv4/IPv6, every Core, every connection and every
  process bind the same action index instead of receiving independent limits.
* Added stable identity adapters: canonical Xray/sing-box socket marks,
  OpenVPN/WireGuard/PPTP inner addresses, SSH Unix UID, and authenticated
  SoftEther routed-TAP/session identities.
* Added Alembic revision `0011_user_bandwidth_limits` with reversible schema
  metadata and data-preserving zero defaults.

### Fixed

* Closed the Xray/Shadowsocks IPv6 bypass: marked IPv6 freedom sockets now pass
  through IPv6 conntrack, upload and download classifiers bound to the same
  global bucket as IPv4. The same-endpoint regression fell from 208.194 Mbps
  to 4.758 Mbps with a configured 5 Mbps limit.
* Xray keeps immutable legacy account emails while resolving their marks to the
  canonical platform User ID. Newly created users whose legacy/platform IDs
  differ can no longer bypass or consume another User's action.
* Xray records the canonical identities in the exact running document, so user
  admission never treats a restart without a per-user mark as success.
* SoftEther SecureNAT identity loss is replaced by a routed TAP with durable,
  reassignment-safe DHCP/session mapping and fail-closed quarantine for unknown
  transports.
* SoftEther now reasserts `OpenVpnEnable no` when its compatibility listener is
  disabled. A stale persisted clone can no longer steal UDP/1194 during a real
  OpenVPN Core restart.
* Standalone tc actions are deleted in bounded delayed waves after their last
  binding is released, eliminating `ref=1/bind=0` objects on live 0/Unlimited
  transitions.
* The test suite now redirects limiter state through
  `ZAGROS_BANDWIDTH_STATE_PATH`; unprivileged CI no longer attempts to write
  `/var/lib/zagros`, while production keeps the mounted path as its default.
* Accounting shutdown flush, reset/generation handling, provider aliases,
  exactly-once baselines and cross-user attribution are restart-safe.

### Migration and compatibility

* Upgrade from alpha.8.7 preserves all user rows, credentials, usage totals,
  journal entries, Core state and accounting baselines.
* Existing users receive `0/0` bandwidth limits and are not shaped until an
  administrator explicitly sets a non-zero direction.
* API and dashboard expose both Mbps fields with `0 = Unlimited`; live updates
  replace kernel rates without requiring a user reconnect.

### Verification

* Full Python suite: **970 passed, 8 skipped, 0 failed**.
* Xray TCP and UDP passed upload/download over IPv4 and IPv6. At 5 Mbps,
  receiver results were 4.65–4.93 Mbps.
* Xray 1/2/4/8-connection download aggregates were 98.729/97.924/96.371/95.992
  Mbps at a 100 Mbps limit; upload aggregates were 44.805–46.844 Mbps at 50.
* Seven active Cores completed simultaneous upload payloads at an aggregate
  46.185 Mbps with a 50 Mbps User limit. Cross-user 10/100 Mbps isolation and
  an Unlimited user passed concurrently.
* Dynamic active-session updates tracked 50 → 20 → Unlimited → 20 → 100 Mbps;
  reconnect, Xray/OpenVPN Core restart, limiter reconcile and container
  recreation retained enforcement.

## [1.0.0-alpha.8.7] — 2026-08-20 — Final Phase 1–5 release

### Added

* Added independent PPP providers for L2TP/IPsec, raw L2TP, SSTP and PPTP.
  These are separate Linux client/server implementations, not SoftEther
  protocol aliases.
* Added independent PPTP outbound support and the ACCEL-PPP PPTP server with
  MS-CHAPv2, mandatory MPPE128, accounting, quota integration, lifecycle and
  scoped cleanup.
* Added secure outbound persistence with sealed credentials, API redaction and
  secret-free process arguments/diagnostics.
* Added provider-aware policy routing, disposable test domains, readiness
  verification, real interface/IPv4/route checks and real HTTPS verification.

### Fixed

* SoftEther `UserCreate` duplicate/error-66 handling is idempotent and
  retry-safe. Account replay uses parsed `vpncmd UserList /CSV` state and
  reconciles password/expiry without blind duplicate creation.
* SoftEther native client namespaces, VRFs, marks, routes, adapters, counters
  and cleanup converge correctly across restart/reconnect/recreation.
* SSTP command generation now matches the image's real `sstp-client 1.0.20`:
  unsupported `--ca-dir` is never emitted. System trust or supported
  `--ca-cert` is used while certificate and hostname validation remain active.
* Outbound Test now returns only `{status, rtt_ms}`. RTT is selected from a
  post-readiness real network measurement window after warm-up probes; setup,
  PPP-ready, first, p95 and HTTPS durations are internal only.
* Failed measurements fail closed and never display stale or fabricated RTT.

### Security and compatibility decisions

* PPTP server and client control is fixed to **TCP/1723** plus GRE. The
  unmodified reference client does not support custom PPTP ports; no patched
  client, proxy, REDIRECT or DNAT workaround is included.
* SoftEther PPTP remains unsupported. No SoftEther PPTP server/client feature
  is fabricated.
* Raw L2TP is explicitly legacy/insecure and endpoint-dependent. It does not
  become healthy without a real raw-L2TP endpoint.
* Deprecated SoftEther outbound aliases are absent from the public catalog:
  `softether_l2tp`, `softether_l2tp_raw`, `softether_sstp` and
  `softether_pptp`.
* No `--no-verify`, `--cert-warn`, insecure TLS, secret-bearing argv, Docker
  socket, unrelated routing architecture change or unnecessary migration was
  introduced.

### Verification

* Full Python suite: **945 passed, 8 skipped**.
* Phase 5 targeted tests: **67 passed**.
* Real VPS SSTP, L2TP/IPsec and independent PPTP tests passed with real PPP,
  IPv4, route and HTTPS checks. Raw L2TP failed closed when the available
  endpoint did not provide raw L2TP.
* Browser E2E passed for the configured SSTP and L2TP/IPsec outbound cards with
  zero console/page errors and only `healthy · RTT X ms` displayed.
* Dashboard TypeScript/Vite, shell syntax, routing, accounting, quota,
  lifecycle, security and negative-provider coverage passed in the release
  cycle.

## [1.0.0-alpha.8.6] — 2026-08-18 — Runtime-verified routing capability matrix

### Fixed

* Built-in Xray routing-source discovery now merges the legacy inbound cache
  with persisted Studio inbounds by stable tag. A live Studio-created Xray
  listener can no longer disappear from routing source resolution or be
  misclassified as an unknown policy-TUN source.
* Routed SoftEther hubs now own exact, subnet-scoped Linux `FORWARD` accept
  rules in addition to their TAP/gateway lifecycle. Creation, rollback,
  deletion and restart convergence are symmetric, so Docker's host
  `FORWARD DROP` policy no longer black-holes authenticated SoftEther traffic.
* Routing target capability data now separates outer carrier, payload network,
  dataplane and valid source cores. UI discovery and API preflight share that
  contract: SSH is application-TCP only for explicit Xray/sing-box TCP rules,
  while service/TUN sources reject it before mutation.
* SSH outbound accounting is explicitly unsupported because one shared
  dynamic-forward process cannot attribute multiplexed bytes to source users.
  The capability API publishes that architecture reason; SSH inbound accounts
  continue to use the persistent host collector without stale host-agent
  warnings when its snapshot is healthy.
* SoftEther server and client capabilities are direction-specific and grounded
  in the live `vpncmd Help` command inventory and binary version. PPTP and the
  unimplemented native/L2TP/SSTP client dataplanes remain unsupported instead
  of being fabricated from server-side protocol labels; OpenVPN compatibility
  maps to the real OpenVPN client implementation.

### Verification

* Real VPS matrix: **26/26 supported source→target cells passed real traffic**
  across Xray, sing-box, OpenVPN, WireGuard, SSH and a dedicated disposable
  SoftEther Hub/TAP/user. Every pass reached the expected public egress and
  increased the selected target's runtime counter.
* Nine unsupported paths were rejected by the real API with HTTP 422 before
  mutation. OpenVPN→SoftEther passed TLS, authentication, `PUSH_REPLY`, address
  and route assignment, traffic, manual reconnect, SoftEther restart,
  automatic reconnect and resumed traffic.
* SSH host accounting remained monotonic across Panel restart. Browser E2E,
  863-test Panel pytest, scripts pytest, the 267-assertion CLI harness,
  TypeScript, Vite, ShellCheck 0.10.0, shell syntax, npm/pip audits, `pip check`
  and `git diff --check` passed. Disposable VPS state was removed and clean
  production state survived a fresh container recreation.

## [1.0.0-alpha.8.5] — 2026-08-17 — Isolated SoftEther source routing

### Fixed

* Added a production-managed SoftEther Virtual Hub lifecycle with server-admin
  hub selection, per-hub user/TAP/subnet identity, encrypted-credential-free
  persistence, routing-only source inventory, reference-safe deletion, and
  symmetric rollback/cleanup.
* Policy routing now converges multiple SoftEther hubs independently. The
  primary hub's transport tags remain one shared L2 identity, while a managed
  isolated hub can carry its own deterministic source rule without touching
  `DEFAULT`.
* Added an explicit `policy_core=xray` runtime. Kernel/TUN sources enter a
  private sing-box adapter and then a real Xray SOCKS/outbound process, so an
  Xray target is no longer a relabelled sing-box-only policy gateway.
* Restored transparent redirect ingress for SSH-source traffic targeting the
  Xray policy runtime and transactional rollback when nft deployment fails.
* Sealed Client API delivery now forwards public-host context to sing-box,
  WireGuard, OpenVPN, and SSH config builders. Shadowsocks fragments no longer
  contain invalid TLS/transport keys, and sealed OpenVPN configs include their
  one-time protected username/password fields.
* Managed-hub CSV parsing strips vpncmd's server-scope Hub-selection preamble,
  allowing real per-user session/accounting evidence without changing hub
  authentication or exposing credentials.

### Verification target

* Real disposable hub, dedicated user, dedicated routed TAP/subnet, complete
  6×6 capability-aware matrix, restart/reinstall persistence, browser E2E,
  security/dependency gates, and complete cleanup before release authorization.

## [1.0.0-alpha.8.4] — 2026-08-16 — Outbound routing and capability hardening

### Fixed

* Routing target discovery is now context-aware instead of applying one global
  TUN filter. Managed SSH outbounds are offered for native Xray/sing-box rules
  explicitly limited to TCP, while service/kernel sources and UDP-capable rules
  continue to reject SSH because OpenSSH dynamic forwarding has no generic TUN.
* Xray Host Settings canonicalize non-TLS enum fields before legacy
  `ProxyHost` validation. `security=none`, empty ALPN, and empty fingerprint now
  survive Save, reload, None → TLS → None toggles, and older nullable payloads.
* SSH core health now follows the live host-accounting heartbeat in both
  directions. A successful `zagros install-host-agent` clears a cached warning
  on the next status refresh without restarting the core or Panel; a later
  missing, invalid, unreadable, or stale snapshot reports its exact cause.
* `zagros install-host-agent` verifies that the collector service produced a
  fresh, versioned accounting snapshot before reporting production success.
* The Routing page no longer renders global yellow architecture banners.
  Capability constraints remain enforced at target selection and API preflight,
  and rule priority is labelled explicitly instead of appearing as an
  unexplained `#N` warning.

### Capability decision

* SoftEther client-labelled L2TP/IPsec, raw L2TP, SSTP, PPTP, and native
  outbounds remain unsupported by design: the installed core owns vpnserver,
  not the required client daemons/TAP lifecycle. SoftEther OpenVPN-compatible
  endpoints use the fully supported standard OpenVPN outbound. Per-protocol
  runtime, TCP/UDP, TUN, credential, and lifecycle requirements are documented
  and remain driven by the shared capability contract rather than a UI label.

## [1.0.0-alpha.8.3] — 2026-08-16 — Capability, listener, subscription and node architecture

### Fixed

* Dashboard dependency remediation upgrades React Router to 7.18.2 and the
  Vite toolchain to Vite 8.2.1 / plugin-react 6.0.5, then refreshes vulnerable
  transitive nanoid and picomatch locks. The release lock now produces
  `npm audit` with zero high, moderate, low or critical findings; a static
  lock-floor regression prevents the audited ranges from silently returning.
* Python dependency remediation raises aiohttp to 3.14.3+ and Pillow to
  12.3.0+, and removes the unused `jose`/`python-jose` remnants that pulled a
  no-fixed-version `ecdsa` advisory. A fresh requirements audit now reports
  zero known vulnerabilities and the direct PyJWT implementation is pinned by
  a regression contract.
* SoftEther routed-TAP restart recovery now rebuilds the persisted local
  bridge, deletes a stale Panel-owned TAP, and restores its Linux gateway/IP
  state. A real daemon restart previously recreated an apparently-UP but
  unnumbered or unbridged TAP: clients authenticated while DHCP/ARP and policy
  traffic black-holed until the whole Panel restarted.
* SoftEther `vpncmd` authentication and secret-bearing commands now travel
  through an anonymous stdin pipe rather than process arguments. Administrator
  passwords, user passwords and IPsec PSKs are no longer readable from process
  listings or `/proc/<pid>/cmdline`; newline protocol injection is rejected and
  output/error redaction remains as defence in depth.
* SSH outbounds are no longer forced into a sing-box TUN. The shared outbound
  contract distinguishes application proxy, native renderer, kernel routing
  and TUN capability; invalid SSH policy-TUN rules fail before mutation while
  Xray's real native SSH outbound remains available.
* Panel Network Apply detects live TCP ownership in both the API and root host
  agent. A SoftEther SSTP listener on 443 returns an explicit non-destructive
  conflict; TLS health probes now verify certificate identity instead of
  using `curl -k`. Successful browser transitions probe the new origin before
  navigating; failures remain on the old URL and surface rollback state.
* Subscription origin/path generation now comes from SQL portal settings for
  copied links, QR and format URLs. Configurable canonical links use
  `/<path>/<token>`, legacy aliases remain valid, and an optional dedicated
  HTTP/TLS listener exposes subscription routes without exposing admin APIs.
* Core versions use one stopped-or-running adapter contract. SSH and SoftEther
  probes were added, WireGuard no longer returns its project URL as a version,
  and unknown versions carry a reason instead of rendering blank.
* SoftEther PPTP is visible as an explicit unsupported wizard capability; the
  real 4.44 runtime has no `PptpGet`/`PptpEnable` command. SoftEther outbound
  families use the same structured availability matrix rather than a UI-only
  deny-list.

### Added

* Canonical five-state cross-core capability matrix for Xray, sing-box,
  OpenVPN, WireGuard, SSH and SoftEther.
* Native Zagros Node Agent: certificate-pinned HTTPS registration, one-time
  hash-only bootstrap token, encrypted panel signing credentials, HMAC request
  signing, replay protection, allowlisted core lifecycle/inbound operations,
  bounded logs/timeouts, encrypted node core settings, resource metrics and
  root-private authenticated-operation audit records. The legacy Marzban Xray-only node path remains
  migration compatibility rather than being renamed.
* `zagros-node` installer/lifecycle CLI and Node architecture documentation.

## [1.0.0-alpha.8.2] — 2026-08-14 — Cross-core routing and safe host networking

Runtime-verified follow-up to `alpha.8.1`. This release replaces UI-only
outbound selection with one persistent Linux policy-routing plane and closes
the Panel Network, SoftEther architecture and L2TP/IPsec pre-release blockers
on a real Ubuntu VPS.

### Fixed — real cross-core outbound routing

* Every materialized OpenVPN, WireGuard and sing-box proxy outbound now owns a
  stable SQL-backed routing table and fwmark, an isolated egress interface,
  symmetric conntrack return marking and an atomic nftables classifier.
* OpenVPN and WireGuard outbound clients run inside dedicated VRFs, preventing
  overlap with inbound tunnel subnets and keeping connected VPN routes out of
  the host main table. WireGuard outer UDP has an explicit main-table bypass.
* Xray and sing-box route through per-domain local SOCKS gateways, so their
  native rules never target an outbound that exists only as saved UI state.
  Repeated Xray deploys now replace the exact managed outbound set instead of
  accumulating arbitrary tags.
* OpenVPN, WireGuard and routed SoftEther clients are classified from their
  real source subnets. SSH dynamic-forward traffic is classified by the real
  `zg-*` account UID and transparently redirected into the selected
  VRF-bound gateway.
* Policy processes, interfaces, nftables rules and runtime files have
  symmetric teardown. Failed or unmaterialized outbounds fail closed instead
  of silently returning the master VPS address.

### Fixed — persistence across lifecycle operations

* Alembic revision `0009_policy_routing_domains` adds stable outbound
  table/fwmark identities while preserving the existing KV documents as the
  compatibility source of truth. Legacy rules receive deterministic
  `priority` and `enabled` defaults without destructive migration.
* Boot reconciliation now restores outbounds and routing rules after the
  service cores are ready. Its secret-free report includes
  `routing_deferred`, allowing update/repair to fail closed when policy replay
  does not converge.
* Routing was re-verified after container recreation, repair and host reboot;
  no deferred Studio, account or routing work remained.

### Fixed — SoftEther routing and capability honesty

* SoftEther now exposes a routed host TAP while retaining SecureNAT only for
  address assignment. Client traffic is visible to the kernel policy plane,
  and direct Virtual NAT is restored when no SoftEther policy is active.
* L2TP, SSTP and native sessions in one SoftEther instance share one Virtual
  Hub/TAP dataplane. Distinct per-transport egress decisions are therefore
  rejected before persistence and deploy, with an explicit instruction to use
  separate SoftEther instances/Hubs when independent dataplanes are required.
* SoftEther client outbound families remain visible in the UI but disabled and
  marked unsupported. The installed server runtime does not pretend to provide
  a production client implementation.
* A real isolated L2TP/IPsec client passed IKEv1 PSK, NAT-T, ESP transport mode,
  xl2tpd/PPP authentication, tunnel ping, DNS and Internet egress through the
  selected WireGuard outbound. SSTP routing through all supported outbound
  families was also re-verified with real clients and kernel counters.

### Added — safe Panel Network Apply

* Settings → Panel Network now validates and persists domain, bind address,
  public port, managed TLS certificate, trusted proxies, HSTS and HTTPS
  redirect policy.
* A root-only systemd path agent applies the host `.env`, recreates the panel,
  probes the resulting HTTP/HTTPS endpoint and atomically reports success.
  The Docker socket is never mounted into the web container.
* The release bootstrap now supports `update`, refreshing the CLI, agent and
  compose healthcheck before the Panel image. This makes the feature available
  to existing `alpha.8.1` installations instead of only fresh hosts.
* Failed health checks restore the previous `.env` and service. Real VPS gates
  passed an HTTPS domain/port/certificate apply, a return to HTTP and a forced
  failure on an occupied port with successful rollback.
* HTTPS now fails closed unless a valid managed certificate is selected; the
  UI no longer claims that this apply path provisions ACME or a reverse proxy.

### Fixed — subscription network settings

* Structured public domain, scheme, port, certificate, QR base, subscription
  path and URL prefix settings now share one canonical URL builder.
* The default `/sub/<token>` contract and existing aliases remain valid.
  With no public domain configured, wildcard bind addresses are never
  advertised as public subscription URLs.

### Verification

* Panel suite: **790 passed, 7 skipped** after the final HTTPS fail-closed
  regression was added.
* Scripts pytest and the full CLI harness passed; ShellCheck 0.10.0, `bash -n`,
  TypeScript, the Vite production build, `git diff --check`, executable-mode,
  secret and generated-artifact gates passed.
* Real browser E2E passed create/edit/deploy/disable/reload routing flows,
  unsupported SoftEther visibility, Panel Network validation and Subscription
  URL generation while restoring the original rule set in cleanup.
* Real routing matrices passed Xray, sing-box, OpenVPN, WireGuard, SoftEther
  SSTP/L2TP and SSH inbound traffic through OpenVPN, WireGuard and sing-box
  proxy outbounds where each combination is architecturally supported.

## [1.0.0-alpha.8.1] — 2026-08-13 — Runtime and UI blocker closure

Runtime-verified follow-up to `alpha.8`. The four reported production blockers
were reproduced where possible and validated on a real Ubuntu VPS, real Docker,
a real browser, real VPN clients, image recreation, `zagros repair` and a host
reboot.

### Fixed — truthful SoftEther ports

* L2TP/IPsec and raw L2TP no longer pretend to support an arbitrary Wizard
  port. Their fixed protocol ports are represented honestly, the port field is
  disabled with an explanation, and legacy fake values are normalized to
  `1701` during Studio hydration. IPsec continues to use its standard
  UDP `500/4500` transport ports.
* SSTP preserves its selected custom port through Studio, daemon
  materialization, catalog, delivery and subscription output. The runtime now
  enables SSTP and creates the requested SoftEther TCP listener instead of
  silently relying on `443`.
* A real SSTP client established PPP and passed Internet traffic on a custom
  high TCP port before and after host reboot. The subscription portal exposed
  that real port and omitted the legacy fake L2TP port.

### Fixed — protocol-aware outbound Test

* Hysteria2, TUIC and WireGuard no longer receive a misleading TCP connection
  attempt from the Test action. Their UDP endpoint now receives a DNS, route
  and socket preflight whose result explicitly states that protocol
  authentication occurs on deploy.
* OpenVPN Test reads both structured settings and uploaded `.ovpn` content,
  including its first `remote` endpoint and `proto`, so UDP profiles no longer
  fail with a false `ConnectionRefusedError`.
* Complete uploaded OpenVPN profiles no longer require a duplicate
  `settings.server` field. Existing TCP outbound protocols retain a real TCP
  dial test.

### Added — WireGuard outbound profile import

* The outbound editor now provides an `upload .conf` action backed by an
  authenticated strict parser endpoint.
* Client profiles import endpoint, private/public/preshared keys, local
  addresses, AllowedIPs, DNS, MTU and keepalive. Bracketed IPv6 endpoints are
  supported; malformed keys, addresses, endpoints and ambiguous multi-peer
  profiles fail closed.
* sing-box and Xray translation preserve imported list addresses, AllowedIPs,
  preshared key, MTU, keepalive and reserved values.

### Re-verified — WireGuard inbound runtime

* The reported missing WireGuard listener did not reproduce on the current
  runtime. Two real kernel interfaces exposed their configured UDP ports,
  peers and NAT rules; a profile decoded from the live subscription completed
  a fresh handshake, tunnel ping and Internet request before and after reboot.
* `wg show` remains authoritative for kernel-owned WireGuard listener state.
  No speculative inbound change was introduced.

### Verification

* Panel suite locally and on the VPS: **756 passed, 7 skipped**.
* CLI harness: **254 passed, 0 failed**; scripts pytest, TypeScript and Vite
  production build passed.
* Real browser E2E passed fixed L2TP display, custom SSTP editing, WireGuard
  `.conf` upload and the outbound Test flow with no console or page errors.
* Final boot reconciliation had no deferred Studio/account state; all six
  enabled cores were healthy and both persistent SQLite databases passed
  integrity checks.

## [1.0.0-alpha.8] — 2026-08-12 — Final runtime blocker closure

Runtime-verified blocker release based on the published `alpha.7.9` state. The
fixes below were reproduced and validated on a real Ubuntu VPS, real Docker,
real QUIC and WireGuard clients, a real L2TP/PPP session, image recreation,
`zagros update`, `zagros repair`, service restart and host reboot.

### Fixed — sing-box Hysteria2 and TUIC protocol runtime

* Hysteria2/TUIC no longer inherit the generic TLS wizard default
  `h2,http/1.1`. The production renderer converges both QUIC protocols to the
  required `h3` ALPN and delivery mirrors the repaired native TLS block.
* Existing Studio documents carrying the old HTTP ALPN are repaired at render
  time without a UI change or manual inbound recreation.
* Real clients passed `sing-box check`, TLS/auth negotiation and Internet
  traffic through both Hysteria2 and TUIC before and after update/reboot.

### Fixed — SoftEther live and exactly-once accounting

* Active L2TP/SSTP/native sessions are read from real `SessionGet` directional
  counters instead of waiting for delayed `UserGet` settlement at disconnect.
* `_SoftEtherUsageTracker` reconciles live SessionGet deltas with delayed
  UserGet catch-up. The same bytes are recorded once whether UserGet refreshes
  during the session, at disconnect, or after panel restart.
* A real raw-L2TP PPP client downloaded 52,428,800 bytes. The panel advanced by
  approximately 54.1 MB including protocol overhead while the session remained
  connected; delayed catch-up, disconnect and panel restart added no duplicate.

### Fixed — SoftEther upgrade/reboot account replay

* `vpncmd rc=2 Protocol error` during daemon/config warm-up now receives one
  quiet backoff and exact retry. Startup probes and deferred reconciliation are
  paced to avoid triggering SoftEther's localhost DoS guard.
* Persistent server startup waits through real `vpn_server.config`, SecureNAT
  and log initialization before account mutation. Passwords and grants replay
  automatically after image replacement and host reboot.
* Final boot reports are clean: every enabled core is `running / healthy` with
  empty Studio/account deferred sets.

### Re-verified — WireGuard runtime

* Both real kernel interfaces exposed their configured ListenPort through
  `wg show` and `ss`, completed fresh handshakes, pinged tunnel gateways and
  passed Internet traffic before and after update/reboot. No additional
  WireGuard production change was required in this cycle.

### Verification

* Panel suite locally and on the VPS: **745 passed, 7 skipped**.
* CLI harness: **254 passed, 0 failed**; scripts pytest, TypeScript, Vite and
  real browser E2E passed.
* Real L2TP, Hysteria2, TUIC and two WireGuard interfaces passed post-reboot
  runtime checks without reinstall.

## [1.0.0-alpha.7.9] — 2026-08-12 — Real WireGuard multi-inbound and blocker closure

Critical runtime-verified follow-up to `alpha.7.8`. This release removes the
single-interface assumption from the WireGuard core and includes the production
fixes proven during the P0 blocker cycle on a real Ubuntu VPS, real Docker,
real kernel interfaces, NAT, external clients, image recreation and host reboot.

### Fixed — WireGuard multi-inbound

* **Add Inbound now appends instead of replacing.** Every Studio entry owns a
  stable Linux interface, independent UDP `ListenPort`, non-overlapping tunnel
  subnet, forwarding/NAT lifecycle, persistent server key and config directory.
  Legacy flat settings migrate losslessly to the first `wireguard` listener.
* The driver reconciles the complete interface set atomically. Duplicate tags,
  interfaces or ports and overlapping subnets fail before mutation. A failed
  live apply restores the previous desired state and attempts to bring every
  former interface back.
* One account can be granted any subset of WireGuard inbounds. Its client
  identity is preserved while encrypted `inbound_addresses` stores a stable
  address per listener. Grant reconciliation persists newly generated addresses
  immediately, so the second profile survives container replacement and reboot.
* Delivery emits one QR/importable `.conf` per granted inbound with the correct
  address, endpoint, port and server public key. Multi-inbound file downloads
  retain the inbound tag in their filename, preventing browser overwrites.
* Usage sums the same peer identity across all granted kernel interfaces without
  double-counting, and online sessions report their `inbound_tag` and interface.
* Real runtime gate: `51830/udp` (`10.92.0.0/24`) and `51831/udp`
  (`10.93.0.0/24`) listened simultaneously; two isolated network namespaces
  handshook concurrently, pinged both tunnel gateways and each passed Internet
  traffic with HTTP 200. Both listeners, peers, NAT rules, encrypted addresses
  and profiles survived force-recreate, `zagros repair` and a real host reboot.

### Fixed — P0 lifecycle blockers

* **OpenVPN:** the management socket now returns to blocking mode after its
  connect timeout. The reader thread no longer dies during idle periods and
  strand clients forever after `PUSH_REQUEST`; real clients receive
  `PUSH_REPLY`, address, DNS, redirect routes and Internet traffic.
* **WireGuard stale state:** subnet/MTU changes perform a real `wg-quick`
  lifecycle; stale host-network interfaces and their duplicate firewall/NAT
  rules are removed before bring-up. Listener readiness is verified from the
  authoritative kernel `wg` API.
* Managed cores stop during graceful panel shutdown. Failed live materialization
  cannot leave CoreManager reporting a stale `RUNNING` state.
* An atomic `0600` runtime boot report records Studio/account deferred sets and
  the health of every enabled core. `zagros repair` now backs up first, repairs
  persistent state, force-recreates, migrates, waits for reconciliation and
  fails closed on any deferred account/listener or non-running core.

### Fixed — credential and subscription continuity

* Editing `core_access` preserves decrypted generated credentials and updates an
  existing account instead of recreating it. WireGuard keys/addresses and the
  passwords/UUIDs of OpenVPN, SSH, sing-box and SoftEther no longer rotate.
* Xray self-signed listener state is persisted and delivered with
  `allowInsecure`; VLESS gRPC `service_name` now survives outbound composition
  and sing-box/Clash subscription conversion.
* Existing subscription URLs and the original WireGuard profile remain valid
  through image replacement, repair and reboot; no unavailable section is
  emitted.

### Verification

* Panel suite: **739 passed, 7 skipped** after the alpha.7.9 regression set.
* CLI harness: **254 passed, 0 failed**; scripts pytest, TypeScript and Vite
  production build pass.
* Real VPS: all six enabled cores report `running / healthy` with empty
  `studio_deferred` and `account_deferred` after recreation and reboot.

## [1.0.0-alpha.7.8] — 2026-08-11 — Upgrade-safe core recovery, listener readiness, and OpenVPN auth completion

Critical post-`alpha.7.7` upgrade-fix release. The field symptoms — cores
falling out of RUNNING after an image update, manual Reinstall being required,
old subscriptions becoming unavailable, OpenVPN stopping at `PUSH_REQUEST`,
and QUIC/WireGuard listeners appearing absent — traced to process-local desired
state and core artifacts living across the wrong persistence boundary.

### Fixed — no-reinstall upgrade recovery

* **Every enabled core account is replayed from encrypted SQL on boot.** Fresh
  driver objects now receive their users, credentials, inbound grants and
  peers before Start whenever offline reconciliation is possible. Live-only
  engines are retried after their daemon starts. Credentials repaired from an
  older incomplete row are encrypted and persisted without churning unchanged
  ciphertext. Replay is serialized by the CoreManager lifecycle lock.
* **Studio hydration is two-phase.** Listener documents apply before Start;
  engines such as SoftEther that require a live control plane are deferred and
  retried after Start. A live daemon whose stored manager state is `ERROR` is
  immediately reconciled to `RUNNING`.
* **Old subscriptions stay resolvable after process/image replacement.** The
  upgrade suite checks encrypted SQL rehydration and byte-identical sing-box
  links; real SoftEther delivery was identical before and after daemon
  replacement.

### Fixed — sing-box Hysteria2 / TUIC

* A bare persisted `executable_path=sing-box` now resolves the already-installed
  binary under the mounted core `work_dir` instead of searching only the new
  container's PATH and demanding Reinstall. Install/update persists the
  resolved absolute path.
* Wizard → API → Studio → native config tests pin Hysteria2/TUIC `listen`,
  UDP port, users, TLS certificate/key, UUID/password and congestion control.
  Existing strict `sing-box check` and socket readiness remain fail-closed.
* Real sing-box 1.12.4 verification passed config validation, UDP bind, actual
  Hysteria2 and TUIC clients, traffic, per-user upload/download stats, and a
  second backend/process start from the persisted bare-path state.

### Fixed — OpenVPN PUSH_REQUEST deadlock

* The management auth callback is registered before listener sockets open and
  before the management reader thread can receive `CLIENT:CONNECT`. An eager
  reconnect can no longer arrive in the old callback-free race window.
* A complete auth request without a handler is now explicitly denied rather
  than silently removed; every session receives `client-auth`,
  `client-auth-nt`, or `client-deny`.
* Boot-time SQL replay ensures the auth callback has the persisted account
  map before Start. Real OpenVPN 2.6.14 passed `PUSH_REPLY`, address, DNS,
  redirect route, tunnel traffic and accounting both before and after a full
  driver/backend recreation, with `verb 6` diagnostics.

### Fixed — WireGuard listener truth

* Start and live `syncconf` now require the kernel WireGuard API to report the
  configured `ListenPort`; a mismatch fails and removes the partial interface.
  Status reports an existing interface with the wrong port as unhealthy.
* `wg show all dump` is authoritative. `ss` remains diagnostic because some
  kernels delay or omit kernel-owned WireGuard sockets even while real
  handshakes pass.
* Real namespace verification passed interface UP, `ListenPort`, `ss`, peer,
  preshared key, handshake, ping, traffic and accounting before and after
  recreation without Reinstall.

### Fixed — persistent SoftEther and Xray state

* SoftEther now installs under
  `/var/lib/zagros/cores/softether/runtime`, preserving `vpn_server.config`
  beside the daemon across image replacement. Missing runtime is repaired
  automatically from the mounted cache/package source. Stale PATH wrappers
  whose targets vanished are rejected. A fresh blank daemon can safely regain
  the persisted admin password only after blank authority is proven.
* Xray config, binary and geo assets now default to mounted paths under
  `/var/lib/zagros/cores/xray/`. The legacy singleton uses the shared installer
  when its binary is absent; SQL Studio state is re-applied after the built-in
  core is attached. Existing exact historical `/usr/local` defaults migrate,
  while operator-custom paths are preserved.
* The CLI backup retains SoftEther `vpn_server.config` while excluding its
  re-downloadable binaries. Fresh installs and updates write/migrate persistent
  Xray paths before container replacement.

### Verified before tagging

* Full Python suite: **728 passed / 7 environment-gated skipped / 0 failed**.
* `zagros-scripts` pytest gate: **1 passed**; it executes the complete Bash CLI
  harness, which finished with **0 failed**.
* TypeScript `tsc --noEmit` and production Vite build: **PASS** (2017 modules).
* Chromium fixture regression gate: **33 passed / 0 failed**.
* Real fresh-panel browser smoke: login, real API user creation, 18 pages,
  modal/scroll behavior, three reloads and logout/login all passed.
* Real runtime: Xray 26.3.27 config/self-install reuse; sing-box Hysteria2/TUIC
  clients+stats; OpenVPN 2.6.14 PUSH/tunnel/accounting; WireGuard namespace
  handshake/traffic; SoftEther persistent daemon/config/user/DHCP/tag.

### Environment limitations

* The sandbox has no Docker daemon, so the exact `docker compose` image-to-image
  command was represented by real process/backend recreation against mounted
  files and encrypted SQL rather than claimed as a Docker smoke.
* Full L2TP/IPsec PPP remains kernel-limited here by missing XFRM SAD and
  `l2tp_ppp`/`pppol2tp` support. Dynamic SSH forwarding downlink also remains
  outside `xt_owner`; bidirectional SFTP/SCP accounting is unchanged.

## [1.0.0-alpha.7.7] — 2026-08-11 — Listener readiness, non-Xray templates, SoftEther DHCP, public delivery, and SSH accounting

Post-`alpha.7.6` field-fix release. This cycle follows each reported failure
through the production schema, core lifecycle, generated config and real
runtime where the host kernel permits it. It does not treat fake cores as
runtime evidence.

### Fixed — users, studio lifecycle, and public delivery

* **Template users no longer fail HTTP 422 when they intentionally have no
  Xray proxy.** Creation now accepts either at least one Xray proxy or one
  non-empty `core_access` grant, while partial `UserModify` semantics remain
  unchanged. Template affixes are normalized and bounded in the dashboard so
  the generated username is valid before Save. The regression runs through
  the real HTTP, Pydantic, legacy DB, platform DB and core-provisioning path.
* **Studio apply is now a CoreManager lifecycle operation.** Apply, start,
  stop and restart share the per-core lock; driver-mutated settings such as
  ports, endpoints, listener sets and PSKs persist immediately. A corrected
  Studio document recovers a previously `ERROR` core whose process is not
  actually running instead of reporting success with no listener.
* **`{SERVER_IP}` no longer inherits historical loopback defaults for
  sing-box and WireGuard.** Client delivery resolves the explicit non-loopback
  core address, configured subscription hostname, actual public subscription
  request hostname, then a usable listener fallback. Intentional localhost
  advertising requires the explicit `allow_loopback_advertise` setting.

### Fixed — core runtimes

* **sing-box Hysteria2 and TUIC listeners bind before their first user grant.**
  Explicit QUIC inbounds remain rendered with `users: []`; start, restart,
  Studio apply and account republish wait for every expected TCP/UDP socket
  using `ss` and fail closed if the process exits or a socket never binds.
  TUIC users now carry the stable account `name` required by StatsService.
  Real Hysteria2 and TUIC clients passed traffic and produced non-zero
  per-user upload/download counters.
* **WireGuard Studio recovery and status are real.** A corrected inbound can
  recover the manager from `ERROR`, bring up the interface and persist the
  actual endpoint/port. `wg show all dump` values `off` and `(none)` now parse
  as zero keepalive instead of crashing. A real namespace peer completed a
  handshake, ping and traffic/accounting cycle.
* **OpenVPN PUSH behavior was re-verified against OpenVPN 2.6.** The released
  management-auth, server pool/topology, route/DNS pushes and certificate
  profile received `PUSH_REPLY`, an address, routes and DNS, initialized the
  tunnel and passed traffic. Regression assertions now pin the exact
  server-side push prerequisites.

### Fixed — SoftEther

* **Custom L2TP RAW Wizard tags are stable grant identities.** Server-wide
  feature tags persist in `feature_tags`; portal delivery compares grants to
  the real tag while still accepting canonical aliases for migration. Raw
  L2TP client output uses UDP 1701, username/password and an explicit
  unencrypted warning, and never asks for or leaks an IPsec PSK.
* **Remote-access hubs get a real IP-assignment path by default.** SoftEther
  apply idempotently enables SecureNAT and Virtual DHCP and validates the
  `DhcpGet` pool before accepting L2TP/IPsec, raw L2TP, SSTP, OpenVPN
  compatibility or native remote access. Operators using an external DHCP or
  local bridge can explicitly set `secure_nat=false`.
* **The live SoftEther PSK is authoritative.** PSK precedence is fresh Wizard
  input, live `IPsecGet`, then persisted state; the selected server value is
  persisted so the subscription and daemon cannot silently disagree.
* **PPTP remains absent by design.** SoftEther Server does not implement PPTP;
  stale client-renderer code was removed and the Wizard exposes only real
  SoftEther transports.

### Fixed — SSH accounting

* **Modern SCP/SFTP traffic is counted in both directions after OpenSSH
  decrypts it.** A binary-safe ForceCommand proxy measures stdin as uplink and
  stdout as downlink, then sends bounded cumulative events to a Unix datagram
  collector. `SO_PASSCRED` supplies kernel-authenticated sender UID; state is
  written atomically with root-only permissions and survives restarts.
* **Forwarding accounting no longer claims impossible bidirectional totals.**
  The `xt_owner` matcher is probed against the real kernel and contributes
  forwarding uplink only. SFTP and forwarding sources degrade independently,
  with actionable status rather than fabricated zeroes. Real OpenSSH and
  modern SCP passed byte-identical 1 MiB upload/download tests with non-zero
  usage records in both directions.

### Verified before tagging

* Full Python suite: **712 passed / 7 environment-gated skipped / 0 failed**.
* CLI suite: **244 passed / 0 failed**.
* TypeScript `tsc --noEmit` and production Vite build: **PASS**.
* Real Chromium regression gate: **33 passed / 0 failed**, including Template
  create/no-422, sing-box and WireGuard Host Settings, public subscription
  artifacts without loopback, and SoftEther RAW/L2TP/SSTP transport behavior.
* Real runtime: OpenVPN `PUSH_REPLY` + tunnel traffic; sing-box Hysteria2/TUIC
  UDP bind + clients + stats; WireGuard interface + handshake + traffic;
  SoftEther stable SecureNAT/DHCP pool + live PSK/tag; OpenSSH modern SCP/SFTP
  upload/download + accounting.

### Known limitations

* This sandbox kernel lacks XFRM SAD support and the `l2tp_ppp`/`pppol2tp`
  modules. IKE reached an established SA, and the real SoftEther DHCP pool was
  verified, but a complete L2TP/IPsec PPP client session could not finish in
  this environment.
* Dynamic SSH forwarding downlink is not attributable with `xt_owner`; only
  forwarding uplink plus bidirectional SFTP/SCP is currently reported.

## [1.0.0-alpha.7.6] — 2026-08-10 — Runtime networking, SoftEther installer, OpenVPN PKI, and dashboard fixes

Root-cause bug-fix cycle following `alpha.7.5`. This release replaces the
expensive SoftEther developer source-build path, fixes host/container
forwarding semantics for TUN cores, makes OpenVPN portal profiles connect in
real clients, and closes the reported subscription, Host Settings, wizard,
and Users UI regressions.

### Fixed — core runtime

* **SoftEther installation no longer compiles the complete 5.x developer
  tree on the normal Linux path.** Zagros now selects the newest official RTM
  release from `SoftEtherVPN_Stable`, downloads the architecture bundle and
  performs only its two final links from precompiled objects with one job.
  The installer has an inter-process `flock`, persistent cache, atomic
  `.part`/rename download and extraction, atomic live-root replacement,
  failure rollback, interrupted-build recovery, secret-free progress polling,
  and a bounded/niced source fallback. Real verification: fresh install in
  about 3.9 seconds, cached reinstall in about 0.35 seconds, and the bundled
  `vpncmd Check` passed every operation-environment check.
* **SoftEther protocol capability model corrected.** Server-level vpncmd
  commands now run in entire-server context rather than virtual-hub admin
  context. Native SoftEther, L2TP/IPsec, raw L2TP, SSTP and OpenVPN
  compatibility map to real commands; PPTP is explicitly refused because
  SoftEther does not implement it. A phantom default L2TP entry no longer
  makes SSTP/native creation demand a PSK. L2TP receives a CSPRNG-generated,
  visible/copyable/editable nine-character PSK; PSK/password values are
  redacted from every vpncmd error.
* **WireGuard forwarding and cleanup fixed.** `ip_forward` is verified before
  interface creation instead of being changed by a `PostUp` command after the
  interface is already half-up. Direct-host mode can apply the sysctl; the
  installer persists it on the Docker host because host-network containers
  cannot safely mutate host `/proc/sys`. FORWARD/MASQUERADE rules are scoped
  to the tunnel subnet, and start/stop/restart/failure paths clean interface
  and firewall state exactly.
* **OpenVPN portal profiles now import and connect without a client
  certificate.** The server intentionally uses username/password management
  authentication with `verify-client-cert none`; profiles now declare
  `setenv CLIENT_CERT 0` and `auth-nocache` while retaining the real CA,
  server trust and `tls-crypt` material. Generated server certificates carry
  matching keys, CA signatures, keyUsage `digitalSignature` and EKU
  `serverAuth`; historical Zagros certificates missing those extensions are
  migrated, and invalid operator chains are rejected. Per-listener,
  subnet-scoped forwarding/NAT hooks and exact teardown were added.

### Fixed — studio, subscriptions, and dashboard

* Xray gRPC `service_name` survives Wizard → API → persistence → renderer as
  the exact Xray `grpcSettings.serviceName`; the same field is pinned for
  sing-box. Both generated configs pass their real binary validators.
* Certificate controls render only for TLS. TLS → None clears local
  certificate state, and Xray/sing-box reject certificate material on a
  non-TLS listener server-side.
* Virtualized Users rows now measure their real dynamic height and have an
  intrinsic table width, eliminating badge/note/long-username overlap on
  desktop and mobile. Online, offline and unknown presence indicators always
  retain distinct DOM elements and tooltips.
* Template user creation accepts real non-Xray `core_access`, applies template
  username prefix/suffix and access exactly instead of merging manual
  preselection, and sends a complete creation payload. Manual creation remains
  independent.
* The obsolete Edit User “Multi-core subscription / Issue portal link” flow
  and its UI actions were removed.
* Newly generated, copied, QR and Telegram subscription URLs use canonical
  `/sub/<token>`. `/zagros/sub/<token>` remains a legacy server alias only.
* Host defaults are now `🛸 Zagros ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]`
  with `{SERVER_IP}` as Address for Xray and every applicable core. Inbound
  create/delete owns the associated Host lifecycle, second inbounds receive
  independent rows, exact old Marz defaults migrate safely, and each protocol
  exposes only fields it can apply (for example WireGuard has no TLS/ALPN/
  fingerprint controls).

### Verified before tagging

* Full Python suite: **699 passed / 7 environment-gated skipped / 0 failed**.
* CLI suite: **244 passed / 0 failed**.
* TypeScript `tsc --noEmit` and production Vite build: **PASS**.
* Real Chromium regression gate: **23 passed / 0 failed** (multiple users,
  mobile/desktop layout, manual/template users, all presence states, old UI
  absence, canonical `/sub/`, Host fields, TLS state, gRPC service name and
  SoftEther PSK/SSTP behavior).
* Real runtime: SoftEther stable daemon + SSTP/L2TP; WireGuard interface,
  peer, NAT, restart and failed-start cleanup; OpenVPN 2.6 profile import,
  CA/EKU verification, username/password auth, tunnel traffic, accounting,
  NAT and cleanup. Xray 26.3.27 and current sing-box accepted the generated
  gRPC configurations.
* Environment limitation: this sandbox had no Docker daemon, so the final
  host-network compose smoke remains a VPS deployment check; compose
  permissions/sysctl rendering is covered by the full CLI gate.

## [1.0.0-alpha.7.4] — 2026-08-08 — Field bug-fix batch + full regression audit

A 20-item field-driven fix batch against `alpha.7.3`, every item reproduced
from real field errors first, fixed at the root, and re-verified with real
binaries where the sandbox allows (actual SoftEther 5.2.5188 source build,
actual vendored sing-box 1.12.4 / 1.13.16 stats runs, real panel boot with a
24-check browser + API pass).

### Fixed — cores

* **SoftEther install chain, end to end.** Upstream
  `SoftEtherVPN/SoftEtherVPN` ships only Windows `.exe` binaries plus a source
  tarball per release — there is no Linux binary asset (and no such apt
  package as `softether-vpnserver`). The installer now discovers the official
  `SoftEtherVPN-*.tar.xz` release asset (fallback: tag archive), installs the
  full build dependency set (`pkg-config` + `libsodium` dev packages across
  apt/dnf/yum/pacman/apk — the exact "Could NOT find PkgConfig" / "None of
  the required 'libsodium' found" failures), copies `libcedar.so*` /
  `libmayaqua.so*` beside the binaries, registers them with
  `/etc/ld.so.conf.d/zagros-softether.conf` + `ldconfig` (resolved without
  relying on sudo PATH), links **wrapper scripts** instead of symlinks
  (symlinks broke `hamcore.se2` lookup), and drives vpncmd with 5.x-style
  argv (separate tokens after `/CMD` — the 4.x single-string form produced
  `"UserCreate": Command not found`). Verified against a real 240 s source
  build of 5.2.5188: daemon up on 443/5555/992/1194, UserCreate /
  PasswordSet / UserGet / UserList / suspend / delete all real.
* **OpenVPN / WireGuard inside Docker.** Containers created before
  `alpha.7.2` kept missing `NET_ADMIN` + `/dev/net/tun` because `zagros
  update` never re-rendered the compose file. `update_apply` now re-renders
  compose, sha256-diffs it and `up -d --force-recreate`s on drift; install
  runs a host TUN preflight (`modprobe tun`/`wireguard`,
  `/etc/modules-load.d/zagros-tun.conf`, actionable LXC/OpenVZ guidance);
  `zagros doctor` checks the tun device, the wireguard module and the live
  container's `CapAdd`/`Devices` with a `zagros update --force` fix hint.
* **sing-box traffic stats.** sing-box ≥ 1.12 registers its gRPC stats
  service as `v2ray.core.app.stats.command.StatsService`, not
  `xray.app.stats.command.StatsService` (the field error, reproduced with
  the real vendored 1.12.4 binary). The stats source now negotiates both
  dialects, caches the winner, and names both on failure. Verified with real
  traffic through a real socks inbound: exact byte counts on 1.12.4 and
  1.13.16; a live panel boot reports `running | healthy`.
* **SSH usage accounting is real now.** Every proxied payload byte is
  re-emitted by the account's sshd, so a per-UID iptables owner-match chain
  (`ZG-SSH-ACCT`) counts tunnel traffic exactly (reported as downlink,
  uplink honestly 0). Capability is env-gated with an actionable diagnosis
  and DEGRADED status when iptables is unavailable, instead of silently
  returning zeros. Image gains `iptables` + `iproute2`.

### Fixed — platform

* **Deleted-inbound grants reconcile** (item 6): removing an inbound prunes
  its dangling driver grants and revokes emptied accounts; orphan grants no
  longer 500/422 Edit/Save — user sync runs in explicit repair mode that
  skips untouched ghosts instead of mass-revoking.
* **Certificates delete by a stable id.** `scan()` inventoried the whole
  data tree (e.g. `cores/sing-box/certs/tuic.crt`) while `remove()` only
  knew managed `certs/<name>/` entries — "certificate 'tuic' not found".
  Certificates now carry a data-dir-relative `id` (+ `managed` flag) and
  DELETE accepts name or id with escape/non-`.crt` refusal; the dashboard
  deletes by `id`.
* **Per-core traffic totals are real.** Cores page consumed
  `metrics.network_rx/tx` (host NIC counters). The usage journal now
  aggregates exactly-once deltas per core (`GROUP BY` sums; legacy xray
  rollup included where applicable) via `GET /zagros/cores/traffic/totals`.
  No double counting, and it deliberately excludes — not duplicates — the
  per-user quota accounting.

### Changed — studio / dashboard

* **Wizard**: protocol-aware grouped sections (general / transport / TLS /
  REALITY / certificate / advanced); no fake port tiles ("port not
  configured" instead of a fabricated `:443`); certificate picker resolving
  `certificate_ref` to a validated inline PEM pair (existence, PEM format,
  key match, expiry — loud 404/422/CoreError); edit + clone with full
  prefill (secrets never round-trip); `PUT
  /studio/{core}/wizard/inbound/{tag}` replaces in place; import surfaces
  unmapped values in warnings instead of dropping them silently.
* **One user, one subscription**: canonical `GET /sub/{token}` (the legacy
  `/zagros/sub/{token}` alias keeps working); issued links point at `/sub/`.
* **Host settings are protocol-aware**: `GET /zagros/cores/{id}/hosts/schema`
  returns a per-protocol field matrix, so WireGuard/OpenVPN/SSH no longer
  offer ALPN / fingerprint / TLS-style fields they cannot express; blank
  remarks get the default `🛸 Zagros ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]
  » {SERVER_IP}` template with per-section variable resolution.
* **Online presence is tri-state**: online / offline / **unknown** — when a
  core's device read fails the user is shown as unknown (never a false
  "offline"); diagnostics persist the last collect timestamp and failed
  cores.
* **Multi-core quota**: one shared per-user quota across all cores, folded
  exactly-once from the usage journal (dedicated integration test).

### Verified before tagging

* Full python suite **609 passed / 7 skipped / 0 failed**; CLI suite
  **244/0**; `tsc --noEmit` + vite build clean; alembic head boot.
* **24-check real browser + API pass** against a real panel boot: canonical
  sub + alias, cert delete-by-id (+404 on repeat), traffic totals, online
  tri-state, vendored sing-box install + wizard create/edit + cert ref +
  hosts schema, no-fake-port tiles, edit prefill — zero page errors.
* Real-binary verification where the sandbox permits: SoftEther 5.2.5188
  source build + runtime, sing-box 1.12.4 / 1.13.16 stats.
* Not locally runnable in this sandbox (no Docker daemon / NET_ADMIN): the
  Docker image build and in-container `wg-quick`/iptables paths — covered by
  the CLI suite (244 assertions incl. compose re-render/force-recreate) and
  the release pipeline.

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
