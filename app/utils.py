import base64
from os import path
from typing import Union, Any
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, x25519
from cryptography.x509 import Certificate
from jwcrypto.jwk import JWK

from app.models.certificate_with_jwk import CertificateWithJWK


def file_content_raise_if_none(filepath: str) -> str:
    optional_file_content = file_content(filepath)
    if optional_file_content is None:
        raise ValueError(f"file_content for {filepath} shouldn't be None")
    return optional_file_content


def file_content(filepath: str) -> Union[str, None]:
    if filepath is not None and path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    return None


def read_cert_as_x509_certificate(cert_path: str) -> Certificate:
    cert_data = file_content_raise_if_none(cert_path)
    return x509.load_pem_x509_certificate(cert_data.encode())


def kid_from_certificate(certificate: Certificate) -> str:
    """
    The "kid" (Key ID) is a unique identifier for the key. There is no standard way to generate a kid.
    This implementation uses the base64-encoded SHA-256 fingerprint of the certificate, it needs
    to match the implementation of the external userinfo service that is used in Max (this service).
    """
    sha256_fingerprint = certificate.fingerprint(hashes.SHA256())
    return base64.b64encode(sha256_fingerprint).decode("utf-8")


def x5t_from_certificate(certificate: Certificate) -> str:
    """
    Generate the "x5t" (X.509 certificate SHA-1 thumbprint) as specified in RFC 7517 section 4.8.
    This is the base64url-encoded SHA-1 digest of the DER encoding of the X.509 certificate.
    See: https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
    See: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
    """
    sha1_fingerprint = certificate.fingerprint(hashes.SHA1())  # nosec B303
    return base64.urlsafe_b64encode(sha1_fingerprint).decode("utf-8").rstrip("=")


def load_certificate_with_jwk_from_path(filepath: str) -> CertificateWithJWK:
    """
    Load a certificate from the given file path and return it as a CertificateWithJWK object.
    The certificate is expected to be in PEM format.
    """
    certificate = read_cert_as_x509_certificate(filepath)
    return load_certificate_with_jwk(certificate)


def load_certificate_with_jwk(certificate: Certificate) -> CertificateWithJWK:
    """
    Build CertificateWithJWK object based on the provided certificate.
    """
    jwk = jwk_from_certificate(certificate)
    kid = kid_from_certificate(certificate)
    x5t = x5t_from_certificate(certificate)
    pem = pem_from_certificate(certificate)

    return CertificateWithJWK(
        certificate=certificate,
        jwk=jwk,
        kid=kid,
        x5t=x5t,
        pem=pem,
    )


def load_x5c_as_certificate(content: str) -> CertificateWithJWK:
    x509_cert = x509.load_pem_x509_certificate(
        f"-----BEGIN CERTIFICATE-----{content}-----END CERTIFICATE-----".encode("utf-8")
    )

    return load_certificate_with_jwk(x509_cert)


def load_jwk(filepath: str) -> JWK:
    with open(filepath, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))


def jwk_from_certificate(certificate: Certificate) -> JWK:
    """
    Convert a x509 Certificate object to a JWK (JSON Web Key) object.
    """
    public_key = certificate.public_key()

    # Explicitly check the type of the public key for mypy linting instead of catching exception to JWK.from_pyca
    if not isinstance(
        public_key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
            x25519.X25519PublicKey,
        ),
    ):
        raise ValueError(
            f"Unsupported public key type in certificate: {type(public_key)}"
        )

    return JWK.from_pyca(public_key)


def pem_from_certificate(cert: Certificate) -> str:
    """
    Convert a x509 Certificate object to a PEM-encoded string.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


def json_from_file(filepath: str) -> Any:
    return json.loads(file_content_raise_if_none(filepath))
