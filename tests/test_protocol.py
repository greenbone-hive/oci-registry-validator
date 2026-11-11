from urllib.parse import parse_qs, urlsplit

import pytest

from registry_validator.evidence import REDACTED, sanitize_headers, sanitize_url
from registry_validator.protocol import (
    infer_scope,
    parse_image_reference,
    parse_next_link,
    parse_www_authenticate,
)


def test_parse_multiple_auth_challenges() -> None:
    challenges = parse_www_authenticate(
        [
            'Basic realm="Registry", Bearer realm="https://auth.example/token",'
            'service="registry.example",scope="repository:example/app:pull"'
        ]
    )
    assert [challenge.scheme for challenge in challenges] == ["basic", "bearer"]
    assert challenges[1].parameters == {
        "realm": "https://auth.example/token",
        "service": "registry.example",
        "scope": "repository:example/app:pull",
    }


def test_parse_next_link() -> None:
    value = '</v2/_catalog?n=2&last=example%2Fapp>; rel="next"'
    assert (
        parse_next_link(value, "https://registry.example/v2/_catalog?n=2")
        == "https://registry.example/v2/_catalog?n=2&last=example%2Fapp"
    )


def test_infer_scope() -> None:
    assert infer_scope("/v2/_catalog?n=100") == "registry:catalog:*"
    assert infer_scope("/v2/team/example/manifests/latest") == "repository:team/example:pull"
    assert infer_scope("/v2/") is None


def test_parse_image_reference() -> None:
    assert parse_image_reference("team/example:latest").repository == "team/example"
    assert (
        parse_image_reference(
            "oci://registry.example/team/example@sha256:abc",
            "registry.example",
        ).reference
        == "sha256:abc"
    )


def test_parse_image_reference_requires_matching_authority() -> None:
    with pytest.raises(ValueError, match="does not match"):
        parse_image_reference("oci://other.example/team/example:latest", "registry.example")


def test_redaction() -> None:
    assert sanitize_headers({"Authorization": "Bearer secret"})["Authorization"] == REDACTED
    sanitized = sanitize_url("https://user:pass@objects.example/blob?X-Amz-Signature=secret&part=1")
    assert "user" not in sanitized
    assert "pass" not in sanitized
    assert "secret" not in sanitized
    assert "part=1" in sanitized


@pytest.mark.parametrize("header", ["Location", "location", "LOCATION"])
@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@objects.example/blob?X-Amz-Signature=secret&part=1",
        "/blob?X-Amz-Signature=secret&part=1",
        "//objects.example/blob?X-Amz-Signature=secret&part=1",
    ],
)
def test_redirect_header_redaction(header: str, url: str) -> None:
    headers = {header: url, "Content-Type": "application/json"}
    sanitized = sanitize_headers(headers)
    location = urlsplit(sanitized[header])
    assert location.path == "/blob"
    assert location.username is None
    assert location.password is None
    assert parse_qs(location.query) == {"X-Amz-Signature": [REDACTED], "part": ["1"]}
    assert sanitized["Content-Type"] == "application/json"
    assert headers[header] == url


def test_malformed_redirect_header_redaction() -> None:
    headers = {"Location": "https://objects.example:invalid/blob?token=secret"}
    assert sanitize_headers(headers)["Location"] == REDACTED
