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
from app.jwt_service import JwtService
from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.utils import load_pub_key_from_cert, create_jwe

logger = logging.getLogger(__name__)


class Service:
    def __init__(
        self,
        artifact_response_factory: ArtifactResponseFactory,
        expected_issuer: str,
        expected_audience: str,
        jwt_priv_key: JWK,
        jwt_pub_key: JWK,
        max_crt_path: JWK,
        login_controller_session_url: str,
        register: Dict[str, Any],
        jwt_service: JwtService,
        zsm_feature: bool,
    ):
        self._artifact_response_factory = artifact_response_factory
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._jwt_priv_key = jwt_priv_key
        self._jwt_pub_key = jwt_pub_key
        self._max_crt_path = max_crt_path
        self._login_controller_session_url = login_controller_session_url
        self._register = register
        self._jwt_service = jwt_service
        self._zsm_feature = zsm_feature

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
                key=self._max_crt_path,
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

    def _fetch_result(self, exchange_token: str) -> Any:
        response = requests.get(
            f"{self._login_controller_session_url}/{exchange_token}/result", timeout=60
        )
        if response.status_code >= 400:
            raise UnauthorizedError(
                f"Received invalid response({response.status_code}) from the login controller"
            )
        return response.json()

    def _fetch_result_jwt(self, exchange_token: str) -> Any:
        response = requests.get(
            f"{self._login_controller_session_url}/{exchange_token}/result", timeout=60
        )
        if response.status_code >= 400:
            raise UnauthorizedError(
                f"Received invalid response({response.status_code}) from the login controller"
            )
        return response.json()

    def _create_response(self, jwt_payload: Dict[str, Any], claims: Dict[str, Any]):
        jwe_pub_key = load_pub_key_from_cert(claims["x5c"])

        jwt_payload["x5c"] = claims["x5c"]

        if "req_iss" in claims:
            jwt_payload["iss"] = claims["req_iss"]
        if "req_aud" in claims:
            jwt_payload["aud"] = claims["req_aud"]
        if "req_acme_token" in claims:
            jwt_payload["acme_token"] = claims["req_acme_token"]
        if "loa_authn" in claims:
            jwt_payload["loa_authn"] = claims["loa_authn"]

        jwt_payload["x5c"] = claims["x5c"]
        jwt_payload["loa_authn"] = claims.get(
            "loa_authn", jwt_payload.get("loa_authn", None)
        )

        jwe_token = self._jwt_service.create_jwe(jwe_pub_key, jwt_payload)
        headers = {
            "Authorization": f"Bearer {jwe_token}",
        }
        return Response(headers=headers)

    def handle_exchange_request(self, request: Request):
        claims = self._get_request_claims(request)
        jwt_payload = {}

        if self._zsm_feature:
            response_dict = self._fetch_result_jwt(claims.get("exchange_token", ""))
            print(response_dict)
            uzi_jwt = response_dict["uzi_id"]
            signed_response = self._jwt_service.from_jwt(self._jwt_pub_key, uzi_jwt)

            print("response_jwt")
            print(signed_response)
            response_dict.update({
                "token": signed_response["token"],
                "uzi_id": signed_response["uzi_id"]
            })
        else:
            response_dict = self._fetch_result(claims.get("exchange_token", ""))


        for bsn in self._register:
            if (
                "uzi_id" in response_dict
                and self._register[bsn]["uzi_id"] == response_dict["uzi_id"]
            ):
                jwt_payload = self._register[bsn]
                jwt_payload["loa_authn"] = response_dict["loa_authn"]
                break
            if (
                "email" in response_dict
                and "email" in self._register[bsn]
                and self._register[bsn]["email"] == response_dict["email"]
            ):
                jwt_payload = self._register[bsn]
                jwt_payload["loa_authn"] = response_dict["loa_authn"]
                break
        if not jwt_payload:
            logger.info(
                f"Unable to find an entry in register for: {json.dumps(response_dict)}"
            )

        if self._zsm_feature and response_dict["token"] != jwt_payload["token"]:
            raise HTTPException(status_code=403, detail="Token mismatch")
        del jwt_payload["token"]

        if claims["ura"] != "*" and jwt_payload:
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
        if claims["saml_id"] != artifact_response.root.attrib["ID"]:
            raise HTTPException(status_code=403, detail="Saml id's dont match")
        bsn = artifact_response.get_bsn(False)
        jwt_payload = self._register.get(bsn, {})
        if claims["ura"] != "*":
            allowed_uras = claims["ura"].split(",")
            jwt_payload["relations"] = [
                r for r in jwt_payload["relations"] if r["ura"] in allowed_uras
            ]
        return self._create_response(jwt_payload, claims)

    def get_signed_uzi_number(self, uzi_number: str):
        for bsn in self._register:
            if self._register[bsn]["uzi_id"] == uzi_number:
                return self._jwt_service.create_jwt(
                    {
                        "uzi_id": uzi_number,
                        "token": self._register[bsn]["token"],
                    }
                )
