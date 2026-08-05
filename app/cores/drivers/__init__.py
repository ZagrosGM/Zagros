"""Built-in core drivers.

Each core lives in its own subpackage and self-registers on import:

    drivers/
    ├── xray/          # XrayDriver       (port of legacy app/xray)
    ├── singbox/       # SingBoxDriver    (config-render + v2ray stats API)
    ├── wireguard/     # WireGuardDriver  (wg syncconf, key rotation, QR)
    ├── openvpn/       # OpenVPNDriver    (management interface)
    ├── hysteria2/     # Hysteria2Driver  (official traffic stats API)
    ├── tuic/          # TUICDriver       (config-render, honest no-stats)
    ├── ssh/           # SSHTunnelDriver  (real unix accounts)
    └── softether/     # SoftEtherDriver  (vpncmd hub management)

``discover_builtin()`` imports every subpackage — no central list to maintain.
"""
