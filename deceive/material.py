from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def exclusive_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def ssh_key(data_dir: Path, name: str, explicit: Path | None) -> Path:
    if explicit:
        if not explicit.is_file():
            raise ValueError(f"Configured SSH host key does not exist: {explicit}")
        return explicit
    path = data_dir / "keys" / f"{name}-ssh-key"
    if not path.exists():
        key = asyncssh.generate_private_key("ssh-ed25519")
        exclusive_write(path, key.export_private_key())
    return path


def tls_pair(data_dir: Path, name: str, hostname: str,
             cert: Path | None, key: Path | None) -> tuple[Path, Path]:
    if cert and key:
        if not cert.is_file() or not key.is_file():
            raise ValueError("Configured TLS certificate/key does not exist")
        return cert, key
    cert = data_dir / "certificates" / f"{name}.crt"
    key = data_dir / "certificates" / f"{name}.key"
    if cert.exists() != key.exists():
        raise ValueError(f"Incomplete generated TLS pair for {name}; restore the missing file")
    if not cert.exists():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        names = [x509.DNSName(hostname), x509.DNSName("localhost")]
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(private, hashes.SHA256())
        )
        exclusive_write(key, private.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        exclusive_write(cert, certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    return cert, key
