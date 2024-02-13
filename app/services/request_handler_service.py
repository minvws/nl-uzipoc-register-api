import json
import time
import logging
from typing import Dict, Any, Optional
import requests

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
from app.exceptions import UnauthorizedError, EntryNotFound
from app.models.identity import Identity

logger = logging.getLogger(__name__)


class RequestHandlerService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        artifact_response_factory: ArtifactResponseFactory,
        expected_issuer: str,
        expected_audience: str,
        max_crt_path: JWK,
        jwt_pub_key: JWK,
        userinfo_token_exp: int,
        login_controller_session_url: str,
        allow_plain_uzi_id: bool,
        jwt_service: JwtService,
        register_service: RegisterService,
    ):
        self._artifact_response_factory = artifact_response_factory
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._max_crt_path = max_crt_path
        self._jwt_pub_key = jwt_pub_key
        self._login_controller_session_url = login_controller_session_url
        self._jwt_service = jwt_service
        self._allow_plain_uzi_id = allow_plain_uzi_id
        self._register_service = register_service
        self._userinfo_token_exp = (
            userinfo_token_exp * 24 * 60 * 60
        )  # from days to seconds

    def get_signed_uzi_number(self, uzi_number: str) -> str:
        # ToDo: Maybe not needed anymore
        identity = self._register_service.get_claims_from_register_by_uzi(uzi_number)
        if identity is None:
            return self._jwt_service.create_jwt({})

        return self._jwt_service.create_jwt(
            {"uzi_id": identity.uzi_id, "token": identity.token}
        )

    def get_signed_userinfo_token(self, bsn: str) -> str:
        identity = self._register_service.get_claims_from_register_by_bsn(bsn)
        if identity is None:
            raise EntryNotFound("Entry not found in register")
        token = {
            "bsn": identity.bsn,
            "token": identity.token,
            "iss": self._expected_issuer,
        }
        return self._jwt_service.create_jwt(token, self._userinfo_token_exp)

    def handle_exchange_request(self, request: Request) -> Response:
        claims = self._get_request_claims(request)
        fetched = self._fetch_result(claims.get("exchange_token", ""))
        if self._allow_plain_uzi_id and len(fetched["bsn"]) < 16:
            identity = self._register_service.get_claims_from_register_by_uzi(
                fetched["uzi_id"]
            )
        else:
            identity = self._get_claims_for_signed_jwt(fetched["bsn"])

        if identity is None:
            raise EntryNotFound("Entry not found in register")

        if hasattr(identity, "relations"):
            allowed_uras = claims["ura"].split(",")
            return self._create_response(identity.to_dict(allowed_uras), claims)

        return self._create_response(identity.to_dict(), claims)

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
        identity = self._register_service.get_claims_from_register_by_bsn(bsn)
        allowed_uras = claims["ura"].split(",")
        if identity is None:
            raise EntryNotFound("Entry not found in register")

        return self._create_response(identity.to_dict(allowed_uras), claims)

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

    def _get_claims_for_signed_jwt(self, uzi_jwt: str) -> Optional[Identity]:
        fetched_claims = self._jwt_service.from_jwt(self._jwt_pub_key, uzi_jwt)
        bsn = fetched_claims["bsn"] if "bsn" in fetched_claims else None
        token = fetched_claims["token"] if "token" in fetched_claims else None
        return self._register_service.get_claims_from_register_by_bsn(bsn, token)
