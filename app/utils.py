import json
import base64
from os import path
from typing import Dict, Any, Union

from cryptography.x509 import load_pem_x509_certificate
from Cryptodome.Hash import SHA256
from Cryptodome.IO import PEM
from jwcrypto.jwk import JWK


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


def kid_from_certificate(certificate: str) -> str:
    der = PEM.decode(certificate)
    sha = SHA256.new()
    sha.update(der[0])
    return base64.b64encode(sha.digest()).decode("utf-8")


def load_pub_key_from_cert(content: str) -> JWK:
    x509_cert = load_pem_x509_certificate(
        f"-----BEGIN CERTIFICATE-----{content}-----END CERTIFICATE-----".encode("utf-8")
    )
    return JWK.from_pyca(x509_cert.public_key())


def load_jwk(filepath: str) -> JWK:
    with open(filepath, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))
