import json
from typing import Dict, Any

from jwcrypto.jwk import JWK

from app.config import config
from app.service import Service


def _load_jwk(path: str) -> JWK:
    with open(path, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))


def _load_json_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


issuer = config.get("app", "issuer")

jwt_sign_priv_key = _load_jwk(config.get("app", "jwt_sign_priv_key_path"))
jwt_sign_crt_path = _load_jwk(config.get("app", "jwt_sign_crt_path"))

jwt_request_issuer_pub_key = _load_jwk(config.get("app", "jwt_request_issuer_pub_key"))

irma_controller_result_url = config.get("app", "irma_controller_result_url")

register_ = _load_json_file(config.get("app", "register_path"))

service_ = Service(
    issuer=issuer,
    jwt_sign_priv_key=jwt_sign_priv_key,
    jwt_sign_crt_path=jwt_sign_crt_path,
    jwt_request_issuer_pub_key=jwt_request_issuer_pub_key,
    irma_controller_result_url=irma_controller_result_url,
    register=register_,
)
