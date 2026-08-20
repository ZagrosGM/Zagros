# Independent PPTP provider — Legacy / Insecure

## Identity

- provider: `pptp`
- engine: ACCEL-PPP `1.14.0`
- dataplane: independent `pptp_server` or independent PPP client outbound
- server control: TCP/1723
- carrier: GRE/IP protocol 47
- authentication: MS-CHAPv2 only
- encryption: mandatory MPPE128
- network: IPv4 only
- security class: `legacy_insecure`

This provider is independent of SoftEther. SoftEther PPTP server and client
capabilities remain unsupported; the independent `pptp` provider is not a
SoftEther transport alias.

## Safety gate

The provider is installed disabled and never auto-starts during installation.
The operator must separately acknowledge the legacy cryptographic risk and
explicitly permit Internet exposure. Both values are validated by the backend
on install and start. The inbound repeats the same two confirmations.

PPTP and MS-CHAPv2 have known cryptographic weaknesses. MPPE128 does not make
this a modern or recommended VPN. Prefer WireGuard, IKEv2, or a modern TLS VPN
whenever the client supports one.

## Fixed port and client compatibility

The server control port is fixed to **TCP/1723**. GRE protocol 47 is the
associated data carrier. The reference PPTP client used by the independent
outbound provider does not expose a supported alternate control-port option.
Custom PPTP ports are therefore not a supported feature in this release.

No patched client, proxy, REDIRECT, DNAT or port-rewriting workaround is
included. SoftEther PPTP remains unsupported.

## Runtime

The pinned ACCEL-PPP binary and only the required modules are compiled in a
checksum-verifying image stage. Production hosts need no compiler. The daemon
runs as a child of the panel container and requires `/dev/ppp`, `NET_ADMIN`,
`NET_RAW`, `ppp_generic`, `ppp_mppe`, IPv4 forwarding, `nft` and `ip`.

Configuration and chap secrets are atomically replaced at mode 0600 inside a
mode-0700 work directory. A random management secret is read from a protected
file and sent over a loopback TCP socket; it is never placed on argv.

## Outbound client

The `pptp` outbound is an independent policy-PPP client. It uses the real
`pptp-linux` client, PPP, MPPE128 and fixed TCP/1723/GRE semantics. It creates a
private policy domain, verifies `ppp0`, IPv4 and route readiness, then measures
real post-ready RTT and HTTPS connectivity. Credentials are materialized only
in private PPP files and are absent from argv and public Test responses.

## Ownership and cleanup

One inbound owns five deterministic, comment-tagged nftables rules for
TCP/1723, GRE, forwarding, and subnet masquerade. They are inserted into the
existing INPUT/FORWARD/POSTROUTING base chains so they remain effective even
when FORWARD has a default-drop policy. An atomic ownership manifest records
every exact chain/comment; cleanup resolves and deletes only those handles.
Stop and purge never flush nftables, reset global routes, remove arbitrary PPP
interfaces, or terminate unrelated processes.

## Accounting

Interim raw counters come from ACCEL-PPP `show sessions`. The pppd_compat
`ip-down` hook writes authoritative final byte totals to a provider-owned
SQLite ledger. The ledger tracks each daemon generation and interface,
advances only positive deltas, and prevents interim/final double counting.
The normal Zagros usage recorder then journals deltas and enforces unified
quota.

## Unsupported by design

- PAP, CHAP-MD5, MS-CHAPv1
- MPPE40 or unencrypted sessions
- IPv6
- arbitrary ACCEL-PPP directives/modules
- multiple PPTP listeners in one host network namespace
- custom PPTP control ports
- SoftEther PPTP server/client behavior
