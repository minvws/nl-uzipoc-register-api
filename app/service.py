import json
import logging
from typing import Dict, Any

import requests
from fastapi import Request
from fastapi.security.utils import get_authorization_scheme_param
from jwcrypto.jwk import JWK
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jwt import JWT
from starlette.responses import Response

from app.exceptions import UnauthorizedError
from app.exchange_request import ExchangeRequest
from app.utils import load_pub_key_from_cert, create_jwe

logger = logging.getLogger(__name__)


class Service:
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwt_sign_priv_key: JWK,
        jwt_sign_crt_path: JWK,
        jwt_request_issuer_pub_key: JWK,
        irma_controller_result_url: str,
        register: Dict[str, Any],
    ):
        self._issuer = issuer
        self._audience = audience
        self._jwt_sign_priv_key = jwt_sign_priv_key
        self._jwt_sign_crt_path = jwt_sign_crt_path
        self._jwt_request_issuer_pub_key = jwt_request_issuer_pub_key
        self._irma_controller_result_url = irma_controller_result_url
        self._register = register

    def _get_request_claims(self, request: Request) -> Dict[str, Any]:
        if request.headers.get("Authorization") is None:
            raise UnauthorizedError("Missing authorization header")
        try:
            scheme, raw_jwt = get_authorization_scheme_param(
                request.headers.get("Authorization")
            )
            if scheme.lower() != "bearer":
                raise UnauthorizedError(f"Invalid scheme {scheme}, expected bearer")
            request_jwt = JWT(jwt=raw_jwt, key=self._jwt_request_issuer_pub_key)
            return (
                json.loads(request_jwt.claims)
                if isinstance(request_jwt.claims, str)
                else request_jwt.claims
            )
        except InvalidJWSObject as invalid_jws_object:
            logger.warning(
                "Invalid jwt received: %s", request.headers.get("Authorization")
            )
            raise UnauthorizedError("Invalid jwt received") from invalid_jws_object

    def _fetch_irma_result(self, exchange_token: str) -> Any:
        irma_response = requests.get(
            f"{self._irma_controller_result_url}/{exchange_token}", timeout=60
        )
        if irma_response.status_code >= 400:
            raise UnauthorizedError(
                f"Received invalid response({irma_response.status_code}) from IRMA"
            )
        return irma_response.json()

    def handle_request(
        self,
        request: Request,
        exchange_request: ExchangeRequest,
    ):
        claims = self._get_request_claims(request)
        jwe_pub_key = load_pub_key_from_cert(claims["x5c"])
        irma_response_json = self._fetch_irma_result(exchange_request.exchange_token)

        jwt_payload = self._register[irma_response_json["uziId"]]
        jwt_payload["relations"] = [
            r
            for r in jwt_payload["relations"]
            if r["ura"] == irma_response_json["uziId"]
        ]
        jwt_payload["req_iss"] = self._issuer
        jwt_payload["x5c"] = claims["x5c"]
        jwt_payload["loa_authn"] = claims["loa_authn"]
        jwt_payload["aud"] = self._audience
        jwe_token = create_jwe(
            self._jwt_sign_priv_key, self._jwt_sign_crt_path, jwe_pub_key, jwt_payload
        )
        headers = {
            "Authorization": f"Bearer {jwe_token}",
        }
        return Response(headers=headers)
