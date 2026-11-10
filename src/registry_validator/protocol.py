from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

SCHEME_RE = re.compile(r"(?:^|,)\s*(Bearer|Basic)\s+", re.IGNORECASE)
PARAM_RE = re.compile(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:\"((?:\\.|[^\"])*)\"|([^,\s]+))")
NEXT_LINK_RE = re.compile(r'<([^>]+)>\s*;[^,]*\brel\s*=\s*"?next"?', re.IGNORECASE)


@dataclass(frozen=True)
class AuthChallenge:
    scheme: str
    parameters: dict[str, str]


@dataclass(frozen=True)
class ImageReference:
    repository: str
    reference: str


def parse_www_authenticate(values: list[str]) -> list[AuthChallenge]:
    challenges: list[AuthChallenge] = []
    for value in values:
        matches = list(SCHEME_RE.finditer(value))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
            parameter_text = value[match.end() : end]
            parameters: dict[str, str] = {}
            for parameter in PARAM_RE.finditer(parameter_text):
                raw = parameter.group(2) if parameter.group(2) is not None else parameter.group(3)
                parameters[parameter.group(1).lower()] = re.sub(r"\\(.)", r"\1", raw or "")
            challenges.append(AuthChallenge(match.group(1).lower(), parameters))
    return challenges


def parse_next_link(value: str | None, current_url: str) -> str | None:
    if not value:
        return None
    match = NEXT_LINK_RE.search(value)
    if not match:
        return None
    return urljoin(current_url, match.group(1))


def infer_scope(path_or_url: str) -> str | None:
    path = urlsplit(path_or_url).path if "://" in path_or_url else path_or_url.split("?", 1)[0]
    if path.rstrip("/") == "/v2/_catalog":
        return "registry:catalog:*"
    match = re.match(r"^/v2/(.+?)/(?:tags/list|manifests/|blobs/)", path)
    if match:
        return f"repository:{match.group(1)}:pull"
    return None


def parse_image_reference(value: str, registry_authority: str | None = None) -> ImageReference:
    candidate = value.strip()
    if candidate.startswith("oci://"):
        without_scheme = candidate.removeprefix("oci://")
        authority, separator, candidate = without_scheme.partition("/")
        if not separator:
            raise ValueError(f"image reference {value!r} has no repository")
        if registry_authority and authority != registry_authority:
            raise ValueError(
                f"image reference authority {authority!r} does not match {registry_authority!r}"
            )

    if "@" in candidate:
        repository, reference = candidate.rsplit("@", 1)
    else:
        last_slash = candidate.rfind("/")
        last_colon = candidate.rfind(":")
        if last_colon <= last_slash:
            raise ValueError(f"image reference {value!r} requires an explicit tag or digest")
        repository, reference = candidate[:last_colon], candidate[last_colon + 1 :]
    if not repository or not reference:
        raise ValueError(f"invalid image reference {value!r}")
    return ImageReference(repository=repository, reference=reference)
