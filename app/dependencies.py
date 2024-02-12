import json
from typing import Dict, Any, List

from jinja2 import Environment, FileSystemLoader, select_autoescape
from packaging.version import parse as version_parse

from app.config import config
from app.models.identity import Identity
from app.models.relation import Relation
from app.services.jwt_service import JwtService
from app.services.request_handler_service import RequestHandlerService
from app.saml.artifact_response_factory import ArtifactResponseFactory
from app.saml.metadata import IdPMetadata, SPMetadata
from app.services.register_service import RegisterService
from app.utils import (
    file_content_raise_if_none,
    kid_from_certificate,
    load_jwk,
    json_from_file,
)


def load_saml_file(filepath: str) -> Dict[str, Any]:
    with open(filepath, encoding="utf-8") as file:
        return json.loads(file.read())


def load_register(filepath: str) -> List[Identity]:
    register_data = json_from_file(filepath)
    register_list = []
    for entry in register_data:
        identity_data = entry.copy()
        relations = (
            [Relation(**r) for r in entry["relations"]]
            if "relations" in identity_data
            else []
        )
        identity_data["relations"] = relations
        register_list.append(Identity(**identity_data))
    return register_list


expected_issuer = config.get("app", "expected_issuer")
expected_audience = config.get("app", "expected_audience")

jwt_crt_path = config.get("app", "jwt_crt_path")
jwt_crt_content = file_content_raise_if_none(jwt_crt_path)

jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))
jwt_pub_key = load_jwk(config.get("app", "jwt_pub_key_path"))

max_crt_path = load_jwk(config.get("app", "max_crt_path"))

login_controller_session_url = config.get("app", "login_controller_session_url")

register_ = load_register(config.get("app", "register_path"))

userinfo_token_exp = int(config.get("app", "userinfo_token_exp"))

allow_plain_uzi_id_ = config.get("app", "allow_plain_uzi_id", fallback="true") == "true"

saml_jinja_env_ = Environment(
    loader=FileSystemLoader(config.get("saml", "xml_templates_path")),
    autoescape=select_autoescape(),
)

saml_settings_ = load_saml_file(config.get("saml", "sp_settings_path"))
saml_sp_settings_ = saml_settings_.get("sp", {})
saml_idp_metadata_ = IdPMetadata(saml_settings_.get("idp", {}).get("metadata_path"))
saml_sp_metadata_ = SPMetadata(
    saml_settings_,
    (
        saml_sp_settings_.get("cert_path"),
        saml_sp_settings_.get("key_path"),
    ),
    saml_jinja_env_,
)

####
## Services
####
jwt_service = JwtService(
    jwt_priv_key=jwt_priv_key,
    crt_kid=kid_from_certificate(jwt_crt_content),
)

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

register_service_ = RegisterService(
    register=register_,
)

request_handler_service_ = RequestHandlerService(
    artifact_response_factory=artifact_response_factory_,
    expected_issuer=expected_issuer,
    expected_audience=expected_audience,
    max_crt_path=max_crt_path,
    userinfo_token_exp=userinfo_token_exp,
    jwt_pub_key=jwt_pub_key,
    login_controller_session_url=login_controller_session_url,
    allow_plain_uzi_id=allow_plain_uzi_id_,
    jwt_service=jwt_service,
    register_service=register_service_,
)
