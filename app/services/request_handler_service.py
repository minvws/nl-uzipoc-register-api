import time
import logging
from typing import Dict, Any, Optional

import requests

from fastapi.security.utils import get_authorization_scheme_param
from fastapi import HTTPException
from jwcrypto.jwk import JWK
from starlette.requests import Request
from starlette.responses import Response

from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.services.jwt_service import JWTService, from_jwt
from app.services.register_service import RegisterService
from app.utils import load_x5c_as_certificate
from app.exceptions import UnauthorizedError, EntryNotFound
from app.models.identity import Identity

logger = logging.getLogger(__name__)


class RequestHandlerService:
    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        artifact_response_factory: ArtifactResponseFactory,
        userinfo_request_jwt_issuer: str,
        userinfo_request_jwt_audience: str,
        userinfo_request_jwt_pub_key: JWK,
        session_result_jwt_audience: str,
        login_controller_session_url: str,
        default_zsm_validity_in_days: int,
        allow_plain_uzi_id: bool,
        jwt_service: JWTService,
        zsm_signed_userinfo_jwt_service: JWTService,
        register_service: RegisterService,
    ):
        self._artifact_response_factory = artifact_response_factory
        self._userinfo_request_jwt_issuer = userinfo_request_jwt_issuer
        self._userinfo_request_jwt_audience = userinfo_request_jwt_audience
        self._userinfo_request_jwt_pub_key = userinfo_request_jwt_pub_key
        self._login_controller_session_url = login_controller_session_url
        self._session_result_jwt_audience = session_result_jwt_audience
        self._jwt_service = jwt_service
        self._zsm_signed_userinfo_jwt_service = zsm_signed_userinfo_jwt_service
        self._allow_plain_uzi_id = allow_plain_uzi_id
        self._register_service = register_service
        self.default_zsm_validity_in_seconds = (
            default_zsm_validity_in_days * 24 * 60 * 60
        )  # from days to seconds

    def get_signed_userinfo_token(
        self, bsn: str, zsm_validity_in_seconds: Optional[int] = None
    ) -> str:
        identity = self._register_service.get_claims_from_register_by_bsn(bsn)
        if identity is None:
            raise EntryNotFound("Entry not found in register")

        userinfo_data = identity.to_dict()

        exp_offset = (
            zsm_validity_in_seconds
            if zsm_validity_in_seconds is not None
            else self.default_zsm_validity_in_seconds
        )
        token = {
            **userinfo_data,
            "aud": self._userinfo_request_jwt_audience,
            "exp": int(time.time()) + exp_offset,
        }

        return self._zsm_signed_userinfo_jwt_service.create_jwt(token)

    def handle_exchange_request(self, request: Request) -> Response:
        claims = self._get_request_claims(request)
        if "meta" in claims:
            logger.debug(
                "Request from %s with headers: %s",
                claims["meta"]["ip"],
                claims["meta"]["headers"],
            )

        fetched = self._fetch_result(claims.get("exchange_token", ""))
        if self._allow_plain_uzi_id and len(fetched["uzi_id"]) < 16:
            identity = self._register_service.get_claims_from_register_by_uzi(
                fetched["uzi_id"]
            )
        else:
            identity = self._get_claims_for_signed_jwt(fetched["uzi_id"])

        allowed_uras = claims["ura"].split(",") if "ura" in claims else None
        return self._create_response(
            identity.to_dict(allowed_uras) if identity is not None else {}, claims
        )

    async def handle_saml_request(
        self,
        request: Request,
    ) -> Response:
        claims = self._get_request_claims(request)
        if "meta" in claims:
            logger.debug(
                "Request from %s with headers: %s",
                claims["meta"]["ip"],
                claims["meta"]["headers"],
            )

        saml_message = await request.body()
        artifact_response = self._artifact_response_factory.from_string(
            saml_message.decode("utf-8")
        )
        if claims["saml_id"] != artifact_response.root.attrib["ID"]:
            raise HTTPException(status_code=403, detail="Saml id's dont match")
        bsn = artifact_response.get_bsn(False)
        identity = self._register_service.get_claims_from_register_by_bsn(bsn)
        allowed_uras = claims["ura"].split(",") if "ura" in claims else None

        return self._create_response(
            identity.to_dict(allowed_uras) if identity is not None else {}, claims
        )

    def _get_request_claims(self, request: Request) -> Dict[str, Any]:
        if request.headers.get("Authorization") is None:
            raise UnauthorizedError("Missing authorization header")

        scheme, raw_jwt = get_authorization_scheme_param(
            request.headers.get("Authorization")
        )
        if scheme.lower() != "bearer":
            raise UnauthorizedError(f"Invalid scheme {scheme}, expected bearer")

        claims = from_jwt(
            jwt_pub_key=self._userinfo_request_jwt_pub_key,
            jwt_str=raw_jwt,
            check_claims={
                "iss": self._userinfo_request_jwt_issuer,
                "aud": self._userinfo_request_jwt_audience,
                "exp": time.time(),
                "nbf": time.time(),
            },
        )
        if claims is None:
            logger.warning(
                "Invalid jwt received: %s", request.headers.get("Authorization")
            )
            raise UnauthorizedError("Invalid jwt received")

        return claims

    def _fetch_result(self, exchange_token: str) -> Any:
        exchange_token_jwt = self._jwt_service.create_jwt(
            payload={
                "aud": self._session_result_jwt_audience,
                "exchange_token": exchange_token,
            }
        )
        response = requests.get(
            f"{self._login_controller_session_url}/results",
            timeout=60,
            headers={"Authorization": "Bearer " + exchange_token_jwt},
        )
        if response.status_code >= 400:
            raise UnauthorizedError(
                f"Received invalid response({response.status_code}) from the login controller"
            )
        return response.json()

    def _create_response(
        self, jwt_payload: Dict[str, Any], claims: Dict[str, Any]
    ) -> Response:
        certificate = load_x5c_as_certificate(claims["x5c"])

        req_claims = claims["req_claims"]

        if "iss" in req_claims:
            jwt_payload["iss"] = req_claims["iss"]
        if "aud" in req_claims:
            jwt_payload["aud"] = req_claims["aud"]
        if "sub" in req_claims:
            jwt_payload["sub"] = req_claims["sub"]
        if "acme_tokens" in req_claims:
            jwt_payload["acme_tokens"] = req_claims["acme_tokens"]
        if "loa_authn" in claims:
            jwt_payload["loa_authn"] = claims["loa_authn"]

        jwt_payload["x5c"] = claims["x5c"]
        jwt_payload["loa_authn"] = claims.get(
            "loa_authn", jwt_payload.get("loa_authn", None)
        )

        jwe_token = self._jwt_service.create_jwe(certificate, jwt_payload)
        headers = {
            "Authorization": f"Bearer {jwe_token}",
        }
        return Response(headers=headers)

    def _get_claims_for_signed_jwt(self, uzi_jwt: str) -> Optional[Identity]:
        fetched_claims = from_jwt(
            self._jwt_service.get_signing_certificate().jwk, uzi_jwt
        )
        if fetched_claims is None:
            logger.error("Invalid jwt received: %s", uzi_jwt)
            raise UnauthorizedError("Invalid uzi_id jwt received")

        uzi_id = fetched_claims["uzi_id"] if "uzi_id" in fetched_claims else None

        if not isinstance(uzi_id, str):
            raise UnauthorizedError("Missing uzi_id in JWT claims")

        return self._register_service.get_claims_from_register_by_bsn(uzi_id)
