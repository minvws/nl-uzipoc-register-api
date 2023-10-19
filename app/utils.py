import json
import time
import base64
from os import path
from typing import Dict, Any, Union

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from Cryptodome.Hash import SHA256
from Cryptodome.IO import PEM
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT


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


def load_jwk(path: str) -> JWK:
    with open(path, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))


def load_json_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


def create_jwe(
    jwt_sign_priv_key: JWK,
    jwt_sign_crt_path: str,
    jwe_enc_pub_key: JWK,
    payload: Dict[str, Any],
) -> str:
    crt_content = file_content_raise_if_none(jwt_sign_crt_path)
    jwt_header = {
        "alg": "RS256",
        "x5t": jwt_sign_priv_key.thumbprint(hashes.SHA256()),
        "kid": kid_from_certificate(crt_content),
    }
    jwt_payload = {
        **{
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 60,
        },
        **payload,
    }
    jwt_token = JWT(
        header=jwt_header,
        claims=jwt_payload,
    )
    jwt_token.make_signed_token(jwt_sign_priv_key)
    jwe_header = {
        "typ": "JWT",
        "cty": "JWT",
        "alg": "RSA-OAEP",
        "enc": "A128CBC-HS256",
        "x5t": jwt_sign_priv_key.thumbprint(hashes.SHA256()),
    }
    tok = jwt_token.serialize()
    print(tok)
    jwe_token = JWT(header=jwe_header, claims=tok)
    print("pubkey", jwe_enc_pub_key.export_to_pem())
    jwe_token.make_encrypted_token(jwe_enc_pub_key)
    return jwe_token.serialize()
