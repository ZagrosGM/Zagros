from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto


def get_cert_SANs(cert: bytes):
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    san_list = []
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            san = extension.value
            for name in san:
                san_list.append(name.value)
    return san_list


def generate_certificate():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    cert = crypto.X509()
    cert.get_subject().CN = "Zagros"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(100*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")

    return {
        "cert": cert_pem,
        "key": key_pem
    }


def ssl_target_name_for_cert(cert_pem: str) -> str:
    """TLS server name the peer certificate is expected to carry.

    Node agents serve a self-signed certificate whose CN is fixed at
    cert-generation time: panel-generated certs use ``CN=Zagros``, while
    legacy Marzban-era node certs use ``CN=Gozargah``. Hardcoding either
    name would break one of the two generations, so the expected name is
    derived from the actual served certificate. ``grpc.ssl_target_name_override``
    verification still applies — this only selects which identity to expect.
    """
    try:
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem,
        )
        cn = cert.get_subject().CN
        if cn:
            return cn
    except Exception:
        pass
    return "localhost"
