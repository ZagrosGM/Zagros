"""Built-in core drivers.

Each core lives in its own subpackage and self-registers on import:

    drivers/
    ├── xray/          # XrayDriver       (port of legacy app/xray)
    ├── singbox/       # SingBoxDriver    (config-render + v2ray stats API;
    │ # serves Hysteria2 + TUIC natively —
    │                   #  the standalone hy2/tuic cores folded into it, see
    │                   #  app/cores/consolidation.py for the rationale)
    ├── wireguard/     # WireGuardDriver  (wg syncconf, key rotation, QR)
    ├── openvpn/       # OpenVPNDriver    (management interface)
    ├── ssh/           # SSHTunnelDriver  (real unix accounts)
    └── softether/     # SoftEtherDriver  (vpncmd hub management)

``discover_builtin()`` imports every subpackage — no central list to maintain.
"""
