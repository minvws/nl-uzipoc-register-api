import json
import logging
import time
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

logger = logging.getLogger(__name__)


class JwtService:
    def __init__(self, jwt_priv_key: JWK, jwt_pub_key: JWK, crt_kid):
        self._jwt_priv_key = jwt_priv_key
        self._jwt_pub_key = jwt_pub_key
        self._crt_kid = crt_kid

    def create_jwt(self, payload: Dict[str, Any]):
        return create_jwt(self._jwt_priv_key, self._crt_kid, payload)

    def create_jwe(self, jwe_enc_pub_key: JWK, payload: Dict[str, Any]):
        return create_jwe(self._jwt_priv_key, self._crt_kid, jwe_enc_pub_key, payload)

    def from_jwt(self, jwt: str):
        return from_jwt(self._jwt_pub_key, jwt)

    def from_jwe(self, jwe: str):
        return from_jwe(self._jwt_priv_key, self._jwt_pub_key, jwe)


def from_jwt(jwt_pub_key: JWK, jwt_str: str) -> Dict[str, Any]:
    jwt = JWT.from_jose_token(jwt_str)
    jwt.validate(jwt_pub_key)
    return json.loads(jwt.claims)


def from_jwe(jwt_priv_key: JWK, jwt_pub_key: JWK, jwe_str: str) -> Dict[str, Any]:
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(jwt_priv_key)
    return from_jwt(jwt_pub_key, jwe.payload.decode("utf-8"))


def create_jwt(
    jwt_priv_key: JWK,
    crt_kid: str,
    payload: Dict[str, Any],
) -> str:
    jwt_header = {
        "alg": "RS256",
        "x5t": jwt_priv_key.thumbprint(hashes.SHA256()),
        "kid": crt_kid,
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
    jwt_token.make_signed_token(jwt_priv_key)
    return jwt_token.serialize()


def create_jwe(
    jwt_priv_key: JWK,
    crt_kid: str,
    jwe_enc_pub_key: JWK,
    payload: Dict[str, Any],
) -> str:
    jwt_token = create_jwt(jwt_priv_key, crt_kid, payload)

    jwe_header = {
        "typ": "JWT",
        "cty": "JWT",
        "alg": "RSA-OAEP",
        "enc": "A128CBC-HS256",
        "x5t": jwt_priv_key.thumbprint(hashes.SHA256()),
    }

    jwe_token = JWT(header=jwe_header, claims=jwt_token)
    jwe_token.make_encrypted_token(jwe_enc_pub_key)
    return jwe_token.serialize()
