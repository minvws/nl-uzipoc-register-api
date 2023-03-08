import time
from typing import Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT


def load_pub_key_from_cert(content: str) -> JWK:
    x509_cert = load_pem_x509_certificate(
        f"-----BEGIN CERTIFICATE-----{content}-----END CERTIFICATE-----".encode("utf-8"))
    return JWK.from_pyca(x509_cert.public_key())


def create_jwe(
        jwt_sign_priv_key: JWK,
        jwt_sign_crt_path: JWK,
        jwe_enc_pub_key: JWK,
        payload: Dict[str, Any]
) -> str:
    jwt_header = {
        "alg": "RS256",
        "x5t": jwt_sign_priv_key.thumbprint(hashes.SHA256()),
        "kid": jwt_sign_crt_path.kid,
    }
    jwt_payload = {
        **{
            "aud": "cibg",
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 60,
        },
        **payload
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
    jwe_token = JWT(
        header=jwe_header,
        claims=jwt_token.serialize()
    )
    jwe_token.make_encrypted_token(jwe_enc_pub_key)
    return jwe_token.serialize()
