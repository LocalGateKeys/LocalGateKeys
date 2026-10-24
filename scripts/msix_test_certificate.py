"""Create a self-signed code-signing certificate for sideload-testing the MSIX.

TEST ONLY. Windows installs a sideloaded package only when its signer is
trusted, so testing needs a certificate whose subject equals the manifest's
Publisher. Microsoft Store packages are signed by Microsoft after
certification; this certificate is never used for a Store submission and must
never be trusted on anyone else's machine.

Usage: python scripts/msix_test_certificate.py <out dir> --subject "CN=..." --password <pfx password>

Writes <out dir>/LocalGateKeys-TestSigning.pfx (private key, for signtool) and
<out dir>/LocalGateKeys-TestSigning.cer (public certificate, to trust on the
test machine). An existing pair with the same subject is reused. Nothing is
added to any Windows certificate store.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASENAME = "LocalGateKeys-TestSigning"
VALID_DAYS = 365


def _subject_name(subject: str) -> x509.Name:
    prefix = "CN="
    if not subject.startswith(prefix) or "," in subject:
        raise ValueError("Test subject must be a single CN=... (it must equal the manifest Publisher)")
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject[len(prefix):])])


def create(out_dir: Path, subject: str, password: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    pfx_path, cer_path = out_dir / f"{BASENAME}.pfx", out_dir / f"{BASENAME}.cer"
    name = _subject_name(subject)
    if pfx_path.is_file() and cer_path.is_file():
        existing = x509.load_der_x509_certificate(cer_path.read_bytes())
        still_valid = existing.not_valid_after_utc > datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
        if existing.subject == name and still_valid:
            return pfx_path, cer_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        BASENAME.encode(), key, certificate, None, serialization.BestAvailableEncryption(password.encode()))
    pfx_path.write_bytes(pfx)
    cer_path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    return pfx_path, cer_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args(argv)
    pfx_path, cer_path = create(args.out_dir, args.subject, args.password)
    print(f"Test signing certificate: {cer_path}")
    print(f"Test signing key (PFX):   {pfx_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
