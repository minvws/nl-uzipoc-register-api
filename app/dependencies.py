import json
from typing import Dict, Any

from jinja2 import Environment
from jwcrypto.jwk import JWK

from app.config import config
from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.saml.metadata import IdPMetadata, SPMetadata
from app.service import Service
from packaging.version import parse as version_parse
from jinja2 import Environment, FileSystemLoader, select_autoescape


def _load_jwk(path: str) -> JWK:
    with open(path, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))


def _load_json_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


issuer = config.get("app", "issuer")
audience = config.get("app", "audience")

jwt_sign_priv_key = _load_jwk(config.get("app", "jwt_sign_priv_key_path"))
jwt_sign_crt_path = _load_jwk(config.get("app", "jwt_sign_crt_path"))

jwt_request_issuer_pub_key = _load_jwk(config.get("app", "jwt_request_issuer_pub_key"))

irma_controller_result_url = config.get("app", "irma_controller_result_url")

register_ = _load_json_file(config.get("app", "register_path"))


saml_jinja_env_ = Environment(
    loader=FileSystemLoader(config.get("saml", "xml_templates_path")),
    autoescape=select_autoescape(),
)

saml_settings_ = _load_json_file(config.get("saml", "sp_settings_path"))
saml_sp_settings_ = saml_settings_.get("sp", {})
saml_idp_metadata_ = IdPMetadata(saml_settings_.get("idp", {}).get("metadata_path"))
saml_sp_metadata_ = SPMetadata(
    saml_settings_,
    (
        saml_sp_settings_.get("cert_path"),
        saml_sp_settings_.get("key_path"),
    ),
    saml_jinja_env_)

artifact_response_factory_ = ArtifactResponseFactory(
    cluster_key=None,
    priv_key_path=(saml_sp_settings_.get("key_path", None)),
    expected_service_uuid=saml_sp_settings_["attributeConsumingService"][
                "requestedAttributes"
            ][0]["attributeValue"][0],
    expected_response_destination=saml_sp_settings_["assertionConsumerService"].get(
        "url"
    ),
    expected_entity_id=saml_sp_settings_.get("entityId"),
    sp_metadata=saml_sp_metadata_,
    idp_metadata=saml_idp_metadata_,
    saml_specification_version=version_parse(
        str(saml_settings_.get("saml_specification_version"))
    ),
    strict=saml_settings_.get("strict", True) is True,
    insecure=saml_settings_.get("insecure", False) is True,
)

service_ = Service(
    artifact_response_factory=artifact_response_factory_,
    issuer=issuer,
    audience=audience,
    jwt_sign_priv_key=jwt_sign_priv_key,
    jwt_sign_crt_path=jwt_sign_crt_path,
    jwt_request_issuer_pub_key=jwt_request_issuer_pub_key,
    irma_controller_result_url=irma_controller_result_url,
    register=register_,
)
