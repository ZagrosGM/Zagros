# SoftEther client/outbound capability decision (alpha.8.7)

## Decision

Zagros implements one native SoftEther client provider:
**`softether_native`**. It uses the official Stable Linux `vpnclient` engine, a
private Virtual NIC and an isolated Linux routing domain. This is a real packet
dataplane, not a server-capability label or UI-only flag.

The similarly named L2TP/IPsec, raw L2TP, SSTP and PPTP **SoftEther** families
are not implemented by native `vpnclient`. They are not fabricated as native
SoftEther outbounds. In this release, the corresponding independent Linux
client providers are separately implemented and selected by their canonical
provider IDs:

- `l2tp_ipsec`
- `l2tp_raw`
- `sstp`
- `pptp`

The independent providers have their own binaries, credentials, PPP lifecycle,
policy domains, readiness checks, RTT/HTTPS tests and cleanup. They must not be
reported as SoftEther native dataplanes.

OpenVPN compatibility continues to use the canonical `openvpn` outbound and
was verified against a real SoftEther compatibility listener.

## Provider verdicts

| Remote SoftEther transport | Native SoftEther provider | Independent Zagros provider | Result |
|---|---|---|---|
| Native SoftEther | Official Stable `vpnclient` + `vpncmd` + Virtual NIC | — | **FIXED + REAL TRAFFIC VERIFIED** |
| OpenVPN compatibility | Not native `vpnclient` | Canonical `openvpn` client/TUN | **FIXED + REAL TRAFFIC VERIFIED** |
| L2TP/IPsec | Not provided by native `vpnclient` | `l2tp_ipsec` strongSwan/XFRM + xl2tpd/PPP | **INDEPENDENT PROVIDER** |
| Raw L2TP | Not provided by native `vpnclient` | `l2tp_raw` xl2tpd/PPP | **INDEPENDENT PROVIDER; endpoint-dependent** |
| SSTP | Not provided by native `vpnclient` | `sstp` sstp-client/PPP | **INDEPENDENT PROVIDER** |
| PPTP | Unsupported by SoftEther | `pptp` ACCEL-PPP / independent PPP client | **INDEPENDENT LEGACY PROVIDER** |

No SoftEther PPTP listener or SoftEther PPTP client capability is advertised.
The independent PPTP provider is not a SoftEther feature and is fixed to
TCP/1723 plus GRE.

## Native dataplane architecture

Every enabled native SoftEther outbound owns deterministic, non-shared
resources:

1. a copied `vpnclient`/`vpncmd` runtime and private client configuration;
2. a named network namespace and namespace-local client service;
3. one client account, Virtual NIC and credential set;
4. separate control and data veth pairs;
5. a VRF, fwmark, return mark and routing table;
6. endpoint-pinned control routing so the native carrier never recurses into
   its own data path;
7. exact namespace and root forwarding/NAT rules scoped to owned interfaces,
   marks and subnets;
8. a local SOCKS gateway for application-level Xray/sing-box chaining;
9. authenticated health and exact `AccountStatusGet` transport counters;
10. symmetric rollback and teardown of process, namespace, interfaces, rules,
    runtime files and account/NIC state.

The host default route is never replaced. Management SSH remains on the host's
original route. Namespace reverse-path filtering is changed only inside the
private namespace through a temporary mount namespace; host-global
`rp_filter` is not changed.

Stable `vpncmd` password automation is driven through an echo-disabled private
PTY. Administrator passwords and account passwords are sent only after the
interactive prompts; secrets never appear in argv, command-runner input,
exceptions or returned diagnostics.

## Reconnect and DHCP recovery

Stable `vpnclient` can keep its Virtual NIC object while flushing the NIC's
IPv4 address during account reconnect or service restart. Alpha.8.7 therefore
owns a namespace-local DHCP supervisor. It restarts a failed or stale `udhcpc`
discovery cycle, and the lease hook restores the client IPv4 address, MTU,
tunnel default route and lease facts used by secret-free runtime health.

The remote server endpoint is pinned through the control veth before DHCP can
install the data default. Forced native transport reset, account reconnect,
`vpnclient` stop/start, Panel restart and repeated recreation were verified
with real traffic and exact counter deltas.

## Routing-source identity and UI contract

Routing rules load the backend source inventory and render grouped checkboxes
containing tag, protocol and source core. Multiple selections persist through
Save, Deploy, reload and Edit.

The backend independently resolves every selected tag and rejects repeated
tags, cross-core duplicates, unknown/deleted tags and target/source dataplane
or TCP/UDP incompatibility before mutation.

## Evidence

The Phase 1–5 release-cycle evidence contains native SoftEther lifecycle and
matrix results, independent PPP provider tests, outbound persistence/security
tests, real RTT evidence and browser checks. No subscription URL or credential
belongs in source, logs, reports, browser state or process arguments.
