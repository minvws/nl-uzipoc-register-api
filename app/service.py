import json
import logging
import time
from typing import Dict, Any

import requests
from fastapi import HTTPException
from fastapi import Request
from fastapi.security.utils import get_authorization_scheme_param
from jwcrypto.jwk import JWK
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jwt import JWT
from starlette.responses import Response

from app.exceptions import UnauthorizedError
from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.utils import load_pub_key_from_cert, create_jwe

logger = logging.getLogger(__name__)


class Service:
    def __init__(
        self,
        artifact_response_factory: ArtifactResponseFactory,
        expected_issuer: str,
        expected_audience: str,
        jwt_sign_priv_key: JWK,
        jwt_sign_crt_path: JWK,
        jwt_request_issuer_pub_key: JWK,
        irma_controller_session_url: str,
        register: Dict[str, Any],
    ):
        self._artifact_response_factory = artifact_response_factory
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._jwt_sign_priv_key = jwt_sign_priv_key
        self._jwt_sign_crt_path = jwt_sign_crt_path
        self._jwt_request_issuer_pub_key = jwt_request_issuer_pub_key
        self._irma_controller_session_url = irma_controller_session_url
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
            request_jwt = JWT(
                jwt=raw_jwt,
                key=self._jwt_request_issuer_pub_key,
                check_claims={
                    "iss": self._expected_issuer,
                    "aud": self._expected_audience,
                    "exp": time.time(),
                    "nbf": time.time(),
                },
            )
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
            f"{self._irma_controller_session_url}/{exchange_token}/result", timeout=60
        )
        if irma_response.status_code >= 400:
            raise UnauthorizedError(
                f"Received invalid response({irma_response.status_code}) from IRMA"
            )
        return irma_response.json()

    def _create_response(self, jwt_payload: Dict[str, Any], claims: Dict[str, Any]):
        jwe_pub_key = load_pub_key_from_cert(claims["x5c"])

        if "req_iss" in claims:
            jwt_payload["iss"] = claims["req_iss"]
        if "req_aud" in claims:
            jwt_payload["aud"] = claims["req_aud"]

        jwt_payload["x5c"] = claims["x5c"]
        jwt_payload["loa_authn"] = claims["loa_authn"]
        jwe_token = create_jwe(
            self._jwt_sign_priv_key, self._jwt_sign_crt_path, jwe_pub_key, jwt_payload
        )
        headers = {
            "Authorization": f"Bearer {jwe_token}",
        }
        return Response(headers=headers)

    def handle_exchange_request(self, request: Request):
        claims = self._get_request_claims(request)
        irma_response_json = self._fetch_irma_result(claims.get("exchange_token", ""))

        jwt_payload = {}
        for bsn in self._register:
            if self._register[bsn]["uzi_id"] == irma_response_json["uziId"]:
                jwt_payload = self._register[bsn]
                break
        if claims["ura"] != "*":
            allowed_uras = claims["ura"].split(",")
            jwt_payload["relations"] = [
                r for r in jwt_payload["relations"] if r["ura"] in allowed_uras
            ]
        return self._create_response(jwt_payload, claims)

    async def handle_saml_request(
        self,
        request: Request,
    ):
        claims = self._get_request_claims(request)
        saml_message = await request.body()
        artifact_response = self._artifact_response_factory.from_string(
            saml_message.decode("utf-8")
        )
        if claims["saml-id"] != artifact_response.root.attrib["ID"]:
            raise HTTPException(status_code=403, detail="Saml-id's dont match")
        bsn = artifact_response.get_bsn(False)
        jwt_payload = self._register.get(bsn, {})
        if claims["ura"] != "*":
            allowed_uras = claims["ura"].split(",")
            jwt_payload["relations"] = [
                r for r in jwt_payload["relations"] if r["ura"] in allowed_uras
            ]
        return self._create_response(jwt_payload, claims)
