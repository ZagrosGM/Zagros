"""Panel certificate identity + node TLS target-name derivation."""

from app.utils.crypto import generate_certificate, ssl_target_name_for_cert


def _make_cert_with_cn(cn: str) -> str:
    from OpenSSL import crypto

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = cn
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3650 * 24 * 3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")


def test_fresh_panel_certificate_carries_zagros_cn():
    generated = generate_certificate()
    assert set(generated) == {"cert", "key"}
    assert ssl_target_name_for_cert(generated["cert"]) == "Zagros"


def test_target_name_derived_for_legacy_node_certs():
    """Legacy Marzban-era node certs (CN=Gozargah) must keep connecting."""
    pem = _make_cert_with_cn("Gozargah")
    assert ssl_target_name_for_cert(pem) == "Gozargah"


def test_target_name_falls_back_on_unparseable_cert():
    assert ssl_target_name_for_cert("not a pem at all") == "localhost"


def test_cert_sans_are_plain_text_even_for_ip_sans():
    """A certificate carrying an IP SAN must not leak an ``ipaddress`` object.

    Subscription link generation (``app/subscription/share.py``) rewrites the
    ``*`` placeholder with ``str.replace`` on every SAN it picks, so an
    ``IPv4Address`` escaping from here used to break user creation with
    ``AttributeError: 'IPv4Address' object has no attribute 'replace'``.
    """
    import datetime as _dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from app.utils.crypto import get_cert_SANs

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zagros-test.local")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("zagros-test.local"),
                x509.IPAddress(__import__("ipaddress").ip_address("104.253.175.201")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)

    sans = get_cert_SANs(pem)
    assert "zagros-test.local" in sans
    assert "104.253.175.201" in sans
    assert all(isinstance(item, str) for item in sans), sans
    assert all(item.replace("*", "x") is not None for item in sans)
