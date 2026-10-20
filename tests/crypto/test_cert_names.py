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
