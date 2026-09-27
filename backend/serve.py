"""
Start LOGVAULT. With LOGVAULT_TLS=true the server speaks HTTPS: it uses the certificate in
data/tls/ (put your organisation's cert.pem / key.pem there) or creates a self-signed one on
first start. Usage: python -m backend.serve
"""
import datetime
import ipaddress
import os
import socket

import uvicorn

from .config import config

TLS_DIR = os.path.join(config.DATA_DIR, "tls")
CERT, KEY = os.path.join(TLS_DIR, "cert.pem"), os.path.join(TLS_DIR, "key.pem")


def ensure_self_signed() -> None:
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    os.makedirs(TLS_DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LOGVAULT"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LOGVAULT self-signed")])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname()),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(KEY, 0o600)
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[TLS] created self-signed certificate {CERT}")


def main():
    host = os.getenv("LOGVAULT_HOST", "0.0.0.0")
    port = int(os.getenv("LOGVAULT_INTERNAL_PORT", "8000"))
    if config.TLS:
        ensure_self_signed()
        uvicorn.run("backend.app:app", host=host, port=port, ssl_certfile=CERT, ssl_keyfile=KEY)
    else:
        uvicorn.run("backend.app:app", host=host, port=port)


if __name__ == "__main__":
    main()
