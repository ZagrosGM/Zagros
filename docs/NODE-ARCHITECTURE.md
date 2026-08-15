# Zagros Native Node Architecture (alpha.8.3 cycle)

## Decision

The pre-existing **Node Management** surface is the Marzban-era, Xray-only
compatibility path (`app/routers/node.py` → `app/xray/node.py` → RPyC/ReST).
It sends one Xray JSON document and exposes Xray version/log semantics; it
cannot manage sing-box, OpenVPN, WireGuard, SSH or SoftEther through the
`CoreManager` contract.

Zagros therefore does **not** blindly fork/rename Marzban Node. The native agent
lives in this AGPL-3.0 Zagros repository (`app/node_agent`) and reuses Zagros'
real core adapters. This avoids a second renamed codebase, preserves one
security-update path, and leaves the legacy transport intact only for migration.
The installer is `zagros-node` in `zagros-scripts`.

## Deployment

```text
Zagros Panel                           Zagros Node Agent
-------------                          -----------------
SQL nodes row                          root-private identity.json (0600)
AES-GCM encrypted signing key   <-->   HTTPS listener with pinned certificate
Node client / lifecycle API            CoreManager (builtin ids are not special)
                                       Xray / sing-box / OpenVPN / WireGuard /
                                       SSH / SoftEther adapters
```

The recommended deployment runs the existing Zagros image with command
`python -m app.node_agent`, host networking, `NET_ADMIN`, and `/dev/net/tun`.
It does **not** mount `/var/run/docker.sock`. Core processes are children of the
agent container and persistent core/runtime state is mounted from
`/var/lib/zagros-node`.

## Registration and authentication

1. `zagros-node install <dns-or-ip>` generates a TLS key/certificate and a
   high-entropy one-time registration token.
2. Only `SHA-256(token)` is written to the agent configuration. The plaintext
   token is displayed once.
3. The operator enters the token and TLS SHA-256 fingerprint in Panel.
4. Panel fetches the leaf certificate and compares its DER SHA-256 fingerprint
   before sending any credential.
5. Over that certificate-pinned TLS channel, the agent consumes/burns the
   registration token, generates a separate 256-bit request-signing key, and
   returns that key once.
6. Both sides seal the signing key with `SecretsCipher` (AES-GCM, AAD bound
   to the immutable node identity). Panel uses its master key; the agent uses
   a separate local 0600 identity key. Neither JSON state file contains the
   signer plaintext. The bootstrap token is not retained on either side.

Every later request signs:

```text
METHOD + "\n" + PATH + "\n" + UNIX_TIMESTAMP + "\n" + NONCE + "\n" + SHA256(BODY)
```

with HMAC-SHA256. Agent validation includes constant-time signature comparison,
a five-minute timestamp window, a bounded root-private nonce cache that
survives process restarts, and exact node identity matching.

## Authorization and command surface

There is no shell/RPC evaluator. Endpoints are allowlisted:

- register / revoke
- heartbeat / health / resource metrics
- core inventory / status / version / logs
- core install / uninstall / start / stop / restart
- inbound document apply

FastAPI's `Literal` action schema and the explicit dispatch table prevent an
action string from becoming an argv or shell command. Log tails and operation
timeouts are bounded.

## Lifecycle and rollback

- `CoreManager` serializes lifecycle operations per core and persists state
  atomically through `NodeCoreStateStore`; core settings are AES-GCM sealed
  with per-core AAD and never written as plaintext JSON.
- Xray is composed with `StandaloneXrayBackend` on native agents: it owns a
  node-local process, private atomic config, logs and Stats API, and does not
  import the panel's legacy database/singletons or legacy node fan-out.
- Failed install removes the partially attached driver.
- Failed start transitions the core to `ERROR` rather than reporting running.
- Inbound apply uses `CoreManager.apply_studio_document`, including its live
  status reconciliation and error transition.
- Panel registration is persist-after-remote-success. If local duplicate/DB
  persistence fails after the one-time exchange, Panel immediately revokes the
  newly issued remote signing key.
- Node deletion revokes remote authority first and fails closed while offline;
  a separate explicit `force` path exists for an operator who has isolated the
  host.
- Agent and installer tests terminate processes/listeners and verify no service
  or temporary certificate file remains.

## Compatibility and limitations

The Marzban-era legacy Xray node API remains for existing deployments but is
not represented as generic multi-core support. The capability matrix marks
node support for the six primary adapters through the native agent contract;
its Xray cell explicitly identifies the legacy path as migration-only. A
released alpha.8.3 image is required on the remote node before the new installer
can run this agent.
