import base64
import json

from app.jwt_service import JwtService
from app.utils import load_jwk, file_content_raise_if_none, kid_from_certificate


def test_create_and_validate_jwt_and_jwe():
    jwt_priv_key = load_jwk("tests/resources/secrets/sign_jwt.key")
    jwt_pub_key = load_jwk("tests/resources/secrets/sign_jwt.pub")

    jwt_sign_crt_content = file_content_raise_if_none(
        "tests/resources/secrets/sign_jwt.crt"
    )
    kid = kid_from_certificate(jwt_sign_crt_content)
    jwt_service = JwtService(jwt_priv_key=jwt_priv_key, crt_kid=kid)
    jwt = jwt_service.create_jwt(payload={"claim": "value"})
    parts = jwt.split(".")
    assert len(parts) == 3
    expected_header = {
        "alg": "RS256",
        "kid": kid,
        "x5t": jwt_priv_key.thumbprint(),
    }
    assert json.loads(base64.b64decode(parts[0]).decode("utf-8")) == expected_header

    assert json.loads(base64.b64decode(parts[1]).decode("utf-8"))["claim"] == "value"

    result = jwt_service.from_jwt(jwt_pub_key, jwt)
    assert result["claim"] == "value"

    jwe = jwt_service.create_jwe(
        jwe_enc_pub_key=jwt_pub_key, payload={"claim": "value"}
    )

    parts = jwe.split(".")
    assert len(parts) == 5
    expected_header = {
        "alg": "RSA-OAEP",
        "enc": "A128CBC-HS256",
        "x5t": jwt_priv_key.thumbprint(),
        "typ": "JWT",
        "cty": "JWT",
    }
    assert (
        json.loads(base64.b64decode(parts[0] + "==").decode("utf-8")) == expected_header
    )

    result = jwt_service.from_jwe(jwt_pub_key, jwe)
    assert result["claim"] == "value"
