"""Certificate related helper methods for anbox charms."""

import ipaddress
import os
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_fingerprint(cert: str) -> str:
    """Get a SHA-256 digest of a certificate.

    Args:
        cert: `str` path of the certificate.
    """
    x509_cert = x509.load_pem_x509_certificate(cert.encode())
    return x509_cert.fingerprint(hashes.SHA256()).hex()


def create_cert_files_if_needed(
    cert_path: Path, key_path: Path, hostname: str, public_ip: str, private_ip: str
):
    """Create self-signed certificates at the given cert and key paths including the given hostname, public ip, and private ip as SAN Names.

    Args:
        cert_path: `Path` object to store the generated certificate at.
        key_path: `Path` object to store the generated key at.
        hostname: `str` the hostname to be included in CN and SAN fields of the
            cert.
        public_ip: `str` the public ip to be included in SAN field of the cert.
        private_ip: `str` the private ip to be included in SAN field of the cert.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    cert, key = _generate_selfsigned_cert(hostname, public_ip, private_ip)

    cert_base_path = os.path.dirname(cert_path)
    if not os.path.exists(cert_base_path):
        os.makedirs(cert_base_path, mode=0o0700)

    key_base_path = os.path.dirname(key_path)
    if not os.path.exists(key_base_path):
        os.makedirs(key_base_path, mode=0o0700)

    with open(os.open(cert_path, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write(str(cert, "UTF-8"))

    with open(os.open(key_path, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write(str(key, "UTF-8"))


def _generate_selfsigned_cert(hostname, public_ip, private_ip):
    if not hostname:
        raise Exception("A hostname is required")

    if not public_ip:
        raise Exception("A public IP is required")

    if not private_ip:
        raise Exception("A private IP is required")

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)])
    alt_names = x509.SubjectAlternativeName(
        [
            # best practice seem to be to include the hostname in the SAN
            x509.DNSName(hostname),
            # allow addressing by IP, for when you don't have real DNS
            # openssl wants DNSnames for ips...
            x509.DNSName(public_ip),
            x509.DNSName(private_ip),
            x509.IPAddress(ipaddress.IPv4Address(public_ip)),
            x509.IPAddress(ipaddress.IPv4Address(private_ip)),
        ]
    )
    # path_len=0 means this cert can only sign itnot other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(alt_names, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem
