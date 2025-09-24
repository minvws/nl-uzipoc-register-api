import base64
import json

from app.services.jwt_service import JWTService, from_jwt
from app.utils import load_jwk, load_certificate_with_jwk_from_path


def test_create_and_validate_jwt_and_jwe():
    jwt_priv_key = load_jwk("tests/resources/secrets/sign_jwt.key")

    jwt_sign_crt = load_certificate_with_jwk_from_path(
        "tests/resources/secrets/sign_jwt.crt"
    )
    jwt_service = JWTService(
        issuer="some-issuer",
        signing_private_key=jwt_priv_key,
        signing_certificate=jwt_sign_crt,
    )

    jwt = jwt_service.create_jwt(payload={"claim": "value"})
    parts = jwt.split(".")
    assert len(parts) == 3

    expected_header = {
        "alg": "RS256",
        "kid": jwt_sign_crt.kid,
        "x5t": jwt_sign_crt.x5t,
    }
    assert (
        json.loads(base64.b64decode(parts[0] + "==").decode("utf-8")) == expected_header
    )

    assert (
        json.loads(base64.b64decode(parts[1] + "==").decode("utf-8"))["claim"]
        == "value"
    )

    result = from_jwt(jwt_sign_crt.jwk, jwt)
    assert result["claim"] == "value"

    jwe = jwt_service.create_jwe(
        encryption_certificate=jwt_sign_crt, payload={"claim": "value"}
    )

    parts = jwe.split(".")
    assert len(parts) == 5

    expected_header = {
        "alg": "RSA-OAEP",
        "enc": "A128CBC-HS256",
        "x5t": jwt_sign_crt.x5t,
        "typ": "JWT",
        "cty": "JWT",
    }
    assert (
        json.loads(base64.b64decode(parts[0] + "==").decode("utf-8")) == expected_header
    )

    result = jwt_service.from_jwe(jwt_sign_crt.jwk, jwe)
    assert result["claim"] == "value"
