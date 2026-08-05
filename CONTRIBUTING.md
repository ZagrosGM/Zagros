# Contributing to Zagros

Thanks for considering a contribution to Zagros — the multi-core,
plugin-based VPN management platform. This document describes how we work.
Please read it fully before opening a pull request.

* Repository: <https://github.com/ZagrosGM/Zagros>
* Telegram channel (announcements): <https://t.me/zagrosgm>
* Telegram group (discussion & support): <https://t.me/zagrosgm_group>

---

## 1. Getting started (fork & setup)

1. **Fork** the repository on GitHub and clone your fork:

   ```bash
   git clone https://github.com/<you>/Zagros.git
   cd Zagros
   git remote add upstream https://github.com/ZagrosGM/Zagros.git
   ```

2. Create a **Python ≥ 3.12** environment and install dependencies:

   ```bash
   pip install -r requirements.txt
   python -m pytest tests/ -q      # make sure you start green
   ```

3. For dashboard work, Node.js ≥ 16.17 is required
   (`app/dashboard`, `npm ci && npm run build`).

4. Keep your fork in sync: `git fetch upstream && git rebase upstream/main`.

## 2. Branch naming

Create every change on a dedicated branch off `main`:

| Prefix | Use for | Example |
|---|---|---|
| `feat/` | new features | `feat/hysteria2-masquerade-port-hopping` |
| `fix/` | bug fixes | `fix/qr-padding-mode4` |
| `driver/` | new core drivers | `driver/naiveproxy` |
| `docs/` | documentation only | `docs/portal-theming` |
| `refactor/` | behavior-preserving changes | `refactor/quota-baselines` |
| `test/` | test-only changes | `test/wireguard-e2e` |
| `release/` | release preparation | `release/1.0.0-beta.1` |

One topic per branch. Do not mix unrelated changes.

## 3. Coding style

**Backend (Python)**

* Type-hint everything; run `ruff check app main.py config.py
  --select F401,F811,F841 --exclude app/db/migrations` before committing
  (it must pass — CI enforces it).
* Follow the existing style: SQLAlchemy 2 typed models, Pydantic DTOs at API
  boundaries, no business logic in routers.
* `app/db/migrations/**` is a **frozen** legacy schema history — never edit
  those files; the live schema is `app/persistence` + Alembic revisions
  (`app/persistence/alembic/versions/`).

**Frontend (React + TypeScript, Chakra UI)**

* Components stay cohesive and single-purpose; readability beats brevity.
* `npm run build` must succeed (it runs `tsc` — type errors are blockers).

**Honesty contract (hard rule)**

Zagros reports capabilities honestly. In product code there must be **no
TODO/FIXME markers, no placeholders, no fake data, no simulated behavior**.
If a core cannot do something, report it explicitly instead of pretending.
Tests must never mock the behavior of a real core binary — mocks are only
allowed for OS/process boundaries, and integration/E2E coverage must exist
for everything a driver claims to support.

## 4. Commit convention

We use Conventional-Commits-style messages:

```
<type>(<scope>): <imperative summary>

<why, not what — the diff shows what>
```

* Types: `feat`, `fix`, `driver`, `docs`, `refactor`, `test`, `chore`,
  `security`, `release`.
* Scope (optional): driver name (`xray`, `singbox`, …) or subsystem
  (`quota`, `portal`, `persistence`, `cli`…).
* Examples:
  * `feat(quota): persist baselines exactly-once across core restarts`
  * `fix(portal): render TUIC links without uuid field`
  * `security(crypto): rotate disk-block cipher AAD binding`
* One logical change per commit; keep the tree testable at every commit.

## 5. Pull request rules

* Open an issue first for anything non-trivial and get agreement on the
  design — this avoids rejected large PRs.
* Keep PRs focused and as small as possible; large features should arrive
  as a stack of reviewable PRs.
* Every PR must include:
  * a clear description of *what* and *why*,
  * tests covering the change (see §8),
  * documentation updates when user-visible behavior changes (see §9),
  * a green CI run.
* Do not introduce dependencies without justification; prefer the standard
  library and the existing stack.
* By submitting a PR you agree your contribution is licensed under the
  project's AGPL-3.0 license and you preserve all existing copyright and
  attribution lines.

## 6. Driver development guide

A Zagros core driver is a folder under `app/cores/drivers/<name>/`:

* **Contract first**: subclass `BaseCoreDriver` (`app/cores/base.py`) and
  declare honest *capabilities* — stats, online tracking, hot reload,
  self-install, account suspend/resume. Managers ask "can you do X?",
  never "are you xray?". Never special-case a driver
  (`if name == "xray"` is a review blocker).
* **One folder = one core**: adding a driver must require **zero changes
  anywhere else**; registration is automatic via `__init_subclass__`.
* **Lifecycle ownership**: install (official upstream binaries only,
  hash-verified where published) → render config → start/monitor →
  per-user sync → harvest stats → suspend/resume → delete. Every stage
  reports through the shared types in `app/cores/types.py`.
* **Sealed delivery**: client configs only leave the server through
  `app/cores/delivery.py`; drivers never expose raw credentials in logs or
  API responses.
* **No stats? Say so.** If upstream has no stats API (e.g. TUIC), declare
  the capability gap and let the UI report *unaccounted* — do not invent
  numbers.
* External drivers may ship as pip packages exposing the
  `zagros.core_drivers` entry-point group; the registry loads them exactly
  like built-ins.

## 7. Multi-core architecture rules

These invariants protect the plugin architecture — PRs breaking them will
be rejected:

1. Xray has **no special status**: it is one driver among eight. Nothing in
   `app/cores`, persistence, routing, quota, devices, portal or studio may
   assume a specific core.
2. Cross-cutting services (quota, device manager, session manager, routing
   engine, outbound manager, delivery, portal, studio) are driver-agnostic
   and negotiate through declared capabilities.
3. Unsupported interactions are reported explicitly per core — never
   silently dropped, never simulated.
4. Cross-core chaining goes through the native-listener contract only.
5. The panel owns persistence; cores are stateless workers described by the
   database.

The full design lives in `docs/MULTICORE-ARCHITECTURE.md`.

## 8. Testing requirements

* Run the suite: `python -m pytest tests/ -q` — it must pass (CI double-checks).
* New behavior needs new tests. Bug fixes need a regression test that fails
  before the fix.
* Unit tests live next to their subsystem suite (`tests/cores`,
  `tests/persistence`, `tests/portal`, `tests/clientapi`, `tests/studio`,
  `tests/adminapi`, `tests/crypto`, `tests/platform`).
* Core behavior additionally needs real-binary E2E coverage
  (`tests/e2e`, `ZAGROS_E2E=1`) that downloads the official upstream
  binaries. A driver without exercised real-binary coverage is documented
  as such in the README table.
* Migration changes need tests in `tests/persistence` (importer is
  idempotent — assert that).

## 9. Documentation rules

* User-visible features must be documented where users look: README
  (feature list, core table), CLI help text, and `docs/` for design.
* Keep claims honest and verifiable — statuses in docs must match what the
  tests actually prove.
* `CHANGELOG.md` gets an entry for every user-visible change.
* Screenshots must show the current Zagros UI.

## 10. Security policy

* **Never commit secrets**: no tokens, keys, passwords or real certificates.
* Security-sensitive bugs are **not** public issues — report them privately
  to the maintainers (reach the team via the Telegram group
  <https://t.me/zagrosgm_group> and ask for a maintainer DM) and allow time
  for a fix before any disclosure.
* Changes touching crypto (`app/utils/crypto.py`, sealed delivery, tokens),
  auth, or permission checks get a mandatory security-focused review.
* New credentials-at-rest must use the platform encryption helpers with
  row-bound AAD — never invent storage formats.

## 11. Review process

1. CI must be green (tests, lint).
2. A maintainer reviews for architecture compliance (§6–§7), the honesty
   contract (§3), tests (§8) and docs (§9).
3. Address review comments with new commits (no force-push during review);
   the PR is squash-merged when approved.
4. Releases are cut by maintainers only (`release/` branches).
