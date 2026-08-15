# SoftEther client/outbound capability decision (alpha.8.3)

## Decision

Zagros' current SoftEther core is an **inbound/server implementation**. The
SoftEther client outbound kinds remain `unsupported` and non-selectable. This
is a product capability fact, not an installation probe and not a UI deny-list.

## Evidence

The installed persistent runtime contains `vpnserver`, `vpncmd`, and
`hamcore.se2`. It does not contain or manage a `vpnclient` daemon. `vpncmd
/CLIENT` is only a management CLI for an already-running client service; it is
not a packet dataplane. Starting a server, creating a Virtual Hub, or enabling
OpenVPN compatibility does not create a SoftEther client outbound.

The labels grouped under “SoftEther client” need different Linux providers:

- native SoftEther requires a separately installed `vpnclient`, Virtual NIC
  lifecycle, route/table ownership, secure account/certificate storage, and
  concurrent connection isolation;
- L2TP/IPsec requires an IPsec + L2TP client stack and transactional XFRM/PPP
  cleanup; SoftEther VPN Client is not a generic L2TP client;
- SSTP requires an SSTP client provider and PPP lifecycle;
- raw L2TP has no supported Zagros Linux client adapter;
- PPTP is not exposed by the installed SoftEther server and no fake vpncmd
  command is accepted;
- OpenVPN-compatible SoftEther servers are already reachable through Zagros'
  real `openvpn` outbound kind. Duplicating that dataplane under a fake
  SoftEther label would be misleading.

## Requirements before support can change

A future implementation must provide all of the following before any state is
changed from `unsupported`:

1. an installed and version-probed client dataplane, not vpncmd alone;
2. one isolated lifecycle domain per outbound (process, interface, routing
   table, DNS, credentials, timeout, rollback, and restart recovery);
3. encrypted credential persistence and no secrets in argv/logs;
4. deterministic concurrency and collision handling;
5. real HTTP/HTTPS/DNS egress verification against an expected external IP;
6. source/destination routing integration and exact cleanup;
7. accounting and persistence evidence;
8. API, schema, UI, unit, integration, browser, and real-runtime tests.

Until those criteria are met, API validation rejects enabled SoftEther client
profiles before persistence, schemas mark them unavailable, UI options remain
visible but disabled with the shared capability reason, and routing matrix
cells remain `UNSUPPORTED`.
