import json
import time
import logging
import requests
from typing import Dict, Any, List

from fastapi.security.utils import get_authorization_scheme_param
from fastapi import HTTPException
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from starlette.requests import Request
from starlette.responses import Response

from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.services.jwt_service import JwtService
from app.services.register_service import RegisterService
from app.utils import load_pub_key_from_cert
from app.exceptions import UnauthorizedError

logger = logging.getLogger(__name__)


class RequestHandlerService:
    def __init__(
        self,
        artifact_response_factory: ArtifactResponseFactory,
        expected_issuer: str,
        expected_audience: str,
        max_crt_path: JWK,
        login_controller_session_url: str,
        allow_plain_uzi_id: bool,
        jwt_service: JwtService,
        register_service: RegisterService,
    ):
        self._artifact_response_factory = artifact_response_factory
        self._expected_issuer = expected_issuer  # may be not needed
        self._expected_audience = expected_audience  # may be not needed
        self._max_crt_path = max_crt_path
        self._login_controller_session_url = login_controller_session_url
        self._jwt_service = jwt_service
        self._allow_plain_uzi_id = allow_plain_uzi_id
        self.register_service = register_service

    def handle_exchange_request(self, request: Request) -> Response:
        claims = self._get_request_claims(request)
        fetched = self._fetch_result(claims.get("exchange_token", ""))
        uzi_id = fetched["uzi_id"]

        if self._allow_plain_uzi_id and len(fetched["uzi_id"]) < 16:
            identity = self.register_service._get_claims_from_register_by_uzi(uzi_id)
        else:
            identity = self.register_service._get_claims_for_signed_jwt(uzi_id)

        if "relations" in identity:
            relations = identity["relations"]
            identity["relations"] = self.filter_relations(
                relations, claims["ura"].split(",")
            )

        return self._create_response(identity, claims)

    async def handle_saml_request(
        self,
        request: Request,
    ) -> Response:
        claims = self._get_request_claims(request)
        saml_message = await request.body()
        artifact_response = self._artifact_response_factory.from_string(
            saml_message.decode("utf-8")
        )
        if claims["saml_id"] != artifact_response.root.attrib["ID"]:
            raise HTTPException(status_code=403, detail="Saml id's dont match")
        bsn = artifact_response.get_bsn(False)
        jwt_payload = self._get_claims_from_register_by_bsn(bsn)
        jwt_payload["relations"] = RegisterService.filter_relations(
            jwt_payload["relations"], claims["ura"].split(",")
        )
        return self._create_response(jwt_payload, claims)

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

    def _create_response(
        self, jwt_payload: Dict[str, Any], claims: Dict[str, Any]
    ) -> Response:
        jwe_pub_key = load_pub_key_from_cert(claims["x5c"])

        jwt_payload["x5c"] = claims["x5c"]

        if "req_iss" in claims:
            jwt_payload["iss"] = claims["req_iss"]
        if "req_aud" in claims:
            jwt_payload["aud"] = claims["req_aud"]
        if "req_acme_tokens" in claims:
            jwt_payload["acme_tokens"] = claims["req_acme_tokens"]
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


    @staticmethod
    def filter_relations(
        relations: List[Dict[str, Any]], allowed_uras: List[str]
    ) -> List[Dict[str, Any]]:
        if "*" in allowed_uras:
            return relations
        return [r for r in relations if r["ura"] in allowed_uras]
