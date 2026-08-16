# SoftEther client/outbound capability decision (alpha.8.5)

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

| UI family | Required client/process | TCP | UDP | Generic TUN | Zagros alpha.8.5 result |
|---|---|---:|---:|---:|---|
| Native SoftEther | `vpnclient` service + Virtual NIC/TAP lifecycle | yes | yes | possible only after adapter work | unsupported by design |
| L2TP/IPsec | strongSwan/XFRM + xl2tpd/pppd | yes | outer UDP/IPsec | PPP IP interface | unsupported by design |
| Raw L2TP | dedicated raw-L2TP client stack | yes | outer UDP | PPP IP interface | unsupported by design |
| SSTP | SSTP client + pppd | yes | no | PPP IP interface | unsupported by design |
| PPTP | PPTP client + GRE/pppd | yes | GRE, not UDP | PPP IP interface | unsupported by design |
| OpenVPN compatibility | standard OpenVPN client | yes | yes | yes | use supported `openvpn` outbound |

Native SoftEther additionally requires separately installed `vpnclient`,
Virtual NIC lifecycle, route/table ownership, secure account/certificate
storage, and concurrent connection isolation. SoftEther VPN Client is not a
generic L2TP client. The installed SoftEther server exposes no PPTP command,
and no fake vpncmd command is accepted. OpenVPN-compatible SoftEther servers
are already reachable through Zagros' real `openvpn` outbound kind; duplicating
that dataplane under a fake SoftEther label would be misleading.

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

## Server-source routing is a separate capability

Alpha.8.5 does not turn the server into a client outbound. It adds managed,
isolated **source** identities for sessions terminating on this server:

1. `POST /api/zagros/cores/softether/policy-hubs` creates a new Virtual Hub and
   dedicated user through server-admin vpncmd context. Hub/user passwords never
   enter argv, responses, logs, or persisted core settings.
2. Each tracked hub owns a unique routing-only inbound tag, TAP id, IPv4 subnet,
   and gateway. Overlap with the primary hub or another managed hub is rejected
   before vpncmd mutation.
3. An enabled rule for that tag materializes only that hub's bridge, DHCP pool,
   routed TAP, Linux address, nft classifier, and selected outbound domain.
4. The general user-grant catalog excludes routing-only hubs; the Routing UI
   receives them from the dedicated source inventory.
5. Deletion is refused while any persisted rule references the tag. Successful
   deletion removes user, bridge/TAP, hub metadata, and live Virtual Hub while
   refusing any request to delete the configured primary hub.
6. Shared primary-hub transport tags remain indistinguishable at L2 and cannot
   claim separate decisions. Destination/protocol/priority overlap remains
   deterministic when every tag in that shared hub is selected.

The release gate requires real client traffic from a uniquely named disposable
hub through Xray, sing-box, OpenVPN, and WireGuard, followed by proof that the
hub, user, TAP, routes, firewall state, credentials, and processes were removed
without changing `DEFAULT`.
