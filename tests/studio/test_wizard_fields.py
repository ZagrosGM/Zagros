"""Wizard field depth — headers parser, certificate validator, port
suggester, and blueprint attachment (alpha.7.5 items 1–4, 6).

Every field the wizard now offers must be pinned HERE (UI shape) AND at
the driver translators (tests/cores/test_alpha71_studio_drivers.py), so a
field can never drift into "rendered in the UI but ignored by the engine".

Run: pytest tests/studio/test_wizard_fields.py -q
"""
from __future__ import annotations

import sys
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

import pytest  # noqa: E402

from app.studio.headers import HeaderError, parse_http_headers  # noqa: E402
from app.studio.ports import (  # noqa: E402
    parse_proc_net_listeners,
    suggest_port,
)
from app.studio.wizard import blueprint_for  # noqa: E402


# --------------------------------------------------------------------- #
# headers parser
# --------------------------------------------------------------------- #

def test_headers_accept_name_value_lines_and_comments():
    parsed = parse_http_headers(
        "Accept: */*\n# a comment\n\nUser-Agent: curl/8.0\nX-Retry : 3",
        context="t")
    assert parsed == {"Accept": "*/*", "User-Agent": "curl/8.0", "X-Retry": "3"}


def test_headers_accept_a_mapping():
    assert parse_http_headers({"Host": "cdn.example.com"}, context="t") == {
        "Host": "cdn.example.com"}


def test_headers_empty_is_empty():
    assert parse_http_headers(None, context="t") == {}
    assert parse_http_headers("", context="t") == {}


def test_headers_reject_malformed_lines_names_and_crlf():
    with pytest.raises(HeaderError, match="no 'Name: value'"):
        parse_http_headers("NotAHeader", context="t")
    with pytest.raises(HeaderError, match="invalid HTTP header name"):
        parse_http_headers("Bad Name: x", context="t")
    # embedded control characters inside a VALUE must die (a \r/\n can never
    # survive splitlines, but other C0 bytes could ride a pasted line)
    with pytest.raises(HeaderError, match="control characters"):
        parse_http_headers("X-B: inject\x08evil", context="t")
    with pytest.raises(HeaderError, match="control characters"):
        parse_http_headers({"X-B": "ok\x07nope"}, context="t")


# --------------------------------------------------------------------- #
# certificate validation (shared app.studio.certs)
# --------------------------------------------------------------------- #

def _pair():
    from app.utils.crypto import generate_certificate

    return generate_certificate()


def test_pem_pair_validation_accepts_a_generated_pair():
    from app.studio.certs import validate_pem_pair

    p = _pair()
    cert = validate_pem_pair(p["cert"], p["key"], context="t")
    assert cert is not None


def test_pem_pair_validation_refuses_mismatch_garbage_and_expired(tmp_path):
    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    from app.studio.certs import CertificateError, validate_pem_pair, validate_pem_pair_paths

    a, b = _pair(), _pair()
    with pytest.raises(CertificateError, match="do NOT match"):
        validate_pem_pair(a["cert"], b["key"], context="t")
    with pytest.raises(CertificateError, match="not a valid PEM"):
        validate_pem_pair("garbage", a["key"], context="t")

    # expired but otherwise valid pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x.Name([_x.NameAttribute(NameOID.COMMON_NAME, "expired.test")])
    cert = (_x.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(_x.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=10))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    kpm = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()).decode()
    with pytest.raises(CertificateError, match="EXPIRED"):
        validate_pem_pair(pem, kpm, context="t")

    # path mode: missing file / good pair
    with pytest.raises(CertificateError, match="not found"):
        validate_pem_pair_paths(str(tmp_path / "nope.pem"), str(tmp_path / "k.pem"),
                                context="t")
    (tmp_path / "c.pem").write_text(a["cert"])
    (tmp_path / "k.pem").write_text(a["key"])
    assert validate_pem_pair_paths(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"),
                                   context="t") is not None
    with pytest.raises(CertificateError, match="required together"):
        validate_pem_pair_paths("", "", context="t")


# --------------------------------------------------------------------- #
# port suggestion
# --------------------------------------------------------------------- #

_PROC_SAMPLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1
   1: 0100007F:9C41 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1
   2: 00000000:B1C9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 333 1
"""


def test_proc_listener_parser_reads_hex_ports():
    ports = parse_proc_net_listeners(_PROC_SAMPLE)
    assert 443 in ports            # 0x01BB (LISTEN)
    assert 0x9C41 in ports         # 127.0.0.1:40001 (LISTEN)
    assert 0xB1C9 in ports         # bound UDP-style row (state != LISTEN)


def test_suggest_port_is_five_digits_in_range_and_never_excluded():
    excluded = set(range(10000, 10100)) | {45000}
    for _ in range(200):
        port = suggest_port(excluded)
        assert 10000 <= port <= 65535
        assert len(str(port)) == 5
        assert port not in excluded


def test_suggest_port_linear_probe_survives_a_crowded_range():
    excluded = set(range(10000, 65500))
    port = suggest_port(excluded)
    assert port in set(range(65500, 65536)) - excluded


# --------------------------------------------------------------------- #
# blueprint attachment — UI may never render what engines cannot serve
# --------------------------------------------------------------------- #

def _cell(core: str, proto: str, transport_id: str):
    bp = blueprint_for(core)
    p = next(x for x in bp["protocols"] if x["id"] == proto)
    t = next(x for x in p["transports"] if x["id"] == transport_id)
    return t


def _field_keys(transport) -> set[str]:
    keys: set[str] = set()
    for sec in transport["securities"]:
        keys |= {f["key"] for f in sec["fields"]}
    return keys


def test_xray_tcp_carries_http_camouflage_fields_only_in_tcp():
    keys = _field_keys(_cell("xray", "vless", "tcp"))
    assert {"header_type", "http_method", "request_headers",
            "response_status", "response_reason", "response_headers"} <= keys
    # and NOT on other transports
    assert "header_type" not in _field_keys(_cell("xray", "vless", "ws"))
    assert "header_type" not in _field_keys(_cell("xray", "vless", "grpc"))


def test_xray_grpc_carries_multi_mode_and_ws_carries_headers():
    assert "multi_mode" in _field_keys(_cell("xray", "vless", "grpc"))
    assert "headers" in _field_keys(_cell("xray", "vless", "ws"))


def test_singbox_http_transport_carries_method_and_headers():
    keys = _field_keys(_cell("sing-box", "vless", "http"))
    assert {"http_method", "headers", "path", "host"} <= keys


def test_tls_section_offers_paste_and_path_modes():
    tls_sec = None
    for proto in blueprint_for("xray")["protocols"]:
        for t in proto["transports"]:
            for s in t["securities"]:
                if s["id"] == "tls":
                    tls_sec = s
                    break
    assert tls_sec is not None
    keys = {f["key"] for f in tls_sec["fields"]}
    assert {"certificate", "certificate_key",
            "certificate_path", "certificate_key_path"} <= keys


def test_new_sections_are_grouped_for_the_ui():
    # the Headers section must exist somewhere (TCP cell) and carry only
    # fields the translator consumes
    cell = _cell("xray", "vless", "tcp")
    header_sections = {f.get("section") for s in cell["securities"] for f in s["fields"]}
    assert "headers" in header_sections


def test_softether_wizard_is_capability_aware_and_psk_is_secure_default():
    first = blueprint_for("softether")
    second = blueprint_for("softether")
    ids = {p["id"] for p in first["protocols"]}
    assert {"softether", "l2tp", "l2tp_raw", "sstp", "ovpn"} <= ids
    assert "pptp" not in ids  # independent ACCEL-PPP provider, never SoftEther
    pptp = blueprint_for("pptp")["protocols"][0]
    assert pptp["security_class"] == "legacy_insecure"
    assert pptp["fixed_port"] is True and pptp["default_port"] == 1723
    l2tp = next(p for p in first["protocols"] if p["id"] == "l2tp")
    psk = next(f for t in l2tp["transports"] for s in t["securities"]
               for f in s["fields"] if f["key"] == "ipsec_psk")
    psk2 = next(f for p in second["protocols"] if p["id"] == "l2tp"
                for t in p["transports"] for s in t["securities"]
                for f in s["fields"] if f["key"] == "ipsec_psk")
    assert psk["required"] is True and len(psk["default"]) == 9
    assert psk["default"] != psk2["default"]
    assert l2tp["fixed_port"] is True and l2tp["default_port"] == 1701
    assert next(p for p in first["protocols"] if p["id"] == "l2tp_raw")["fixed_port"] is True
    assert next(p for p in first["protocols"] if p["id"] == "sstp")["fixed_port"] is False
    for proto in ("softether", "l2tp_raw", "sstp", "ovpn"):
        assert "ipsec_psk" not in _field_keys(
            next(p for p in first["protocols"] if p["id"] == proto)["transports"][0])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
