from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import RegistryConfig
from .protocol import AuthChallenge, parse_www_authenticate
from .transport import (
    BodyMode,
    RecordedTransport,
    RedirectPolicyError,
    ResponseData,
    TransportError,
)


class AuthenticationError(TransportError):
    category = "FAIL_AUTH"


@dataclass(frozen=True)
class RegistryHandshake:
    status_code: int
    scheme: str
    challenges: tuple[AuthChallenge, ...]


class RegistryAuthenticator:
    def __init__(self, config: RegistryConfig, transport: RecordedTransport) -> None:
        self.config = config
        self.transport = transport
        self._handshake: RegistryHandshake | None = None
        self._token_cache: dict[str, str] = {}

    @staticmethod
    def _basic_value(username: str, password: str) -> str:
        payload = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {payload}"

    async def handshake(self) -> RegistryHandshake:
        if self._handshake is not None:
            return self._handshake
        headers: dict[str, str] = {}
        if self.config.auth == "basic":
            assert self.config.username is not None and self.config.password is not None
            headers["Authorization"] = self._basic_value(self.config.username, self.config.password)
        elif self.config.auth == "bearer":
            assert self.config.bearer_token is not None
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"

        response = await self.transport.request(
            "GET",
            f"{self.config.url}/v2/",
            headers=headers,
            body_mode="capture",
            operation="registry-handshake",
        )
        values = [
            value for key, value in response.headers.items() if key.lower() == "www-authenticate"
        ]
        challenges = tuple(parse_www_authenticate(values))

        if response.status_code == 200:
            scheme = self.config.auth if self.config.auth != "auto" else "anonymous"
        elif response.status_code == 401:
            if self.config.auth == "anonymous":
                raise AuthenticationError("registry requires authentication")
            if self.config.auth in {"basic", "bearer"}:
                scheme = self.config.auth
            elif any(challenge.scheme == "bearer" for challenge in challenges):
                scheme = "bearer"
            elif any(challenge.scheme == "basic" for challenge in challenges):
                scheme = "basic"
            else:
                raise AuthenticationError("registry returned 401 without a supported challenge")
        else:
            raise AuthenticationError(f"registry handshake returned HTTP {response.status_code}")

        self._handshake = RegistryHandshake(response.status_code, scheme, challenges)
        return self._handshake

    async def authorization_header(self, scope: str | None, *, refresh: bool = False) -> str | None:
        handshake = await self.handshake()
        if handshake.scheme == "anonymous":
            return None
        if handshake.scheme == "basic":
            if self.config.username is None or self.config.password is None:
                raise AuthenticationError("Basic authentication requires configured credentials")
            return self._basic_value(self.config.username, self.config.password)
        if self.config.auth == "bearer" and self.config.bearer_token:
            return f"Bearer {self.config.bearer_token}"

        cache_key = scope or ""
        if not refresh and cache_key in self._token_cache:
            return f"Bearer {self._token_cache[cache_key]}"
        challenge = next(
            (item for item in handshake.challenges if item.scheme == "bearer"),
            None,
        )
        if challenge is None or not challenge.parameters.get("realm"):
            raise AuthenticationError("Bearer challenge has no realm")
        realm = challenge.parameters["realm"]
        if not self.transport.host_allowed(realm, self.config.auth_hosts):
            raise RedirectPolicyError(f"Bearer realm is not allowlisted: {realm}")

        parsed = urlsplit(realm)
        query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key not in {"service", "scope"}
        ]
        if challenge.parameters.get("service"):
            query.append(("service", challenge.parameters["service"]))
        if scope:
            query.append(("scope", scope))
        token_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
        headers: dict[str, str] = {}
        if self.config.username is not None and self.config.password is not None:
            headers["Authorization"] = self._basic_value(self.config.username, self.config.password)
        response = await self.transport.request(
            "GET",
            token_url,
            headers=headers,
            body_mode="memory",
            sensitive_body=True,
            operation="bearer-token",
            scope=scope,
            allowed_hosts=self.config.auth_hosts,
        )
        token = self._parse_token(response)
        self._token_cache[cache_key] = token
        return f"Bearer {token}"

    @staticmethod
    def _parse_token(response: ResponseData) -> str:
        if response.status_code != 200:
            raise AuthenticationError(f"token service returned HTTP {response.status_code}")
        try:
            payload = json.loads((response.body or b"").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthenticationError("token service returned invalid JSON") from error
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token or token == "unauthenticated":
            raise AuthenticationError("token service did not return a usable token")
        return token

    async def get(
        self,
        url: str,
        *,
        scope: str | None,
        body_mode: BodyMode,
        operation: str,
        max_stream_bytes: int | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> ResponseData:
        if not self.transport.host_allowed(url):
            raise RedirectPolicyError(f"registry API URL is outside the configured origin: {url}")
        authorization = await self.authorization_header(scope)
        headers = dict(extra_headers or {})
        if authorization:
            headers["Authorization"] = authorization
        response = await self.transport.request(
            "GET",
            url,
            headers=headers,
            body_mode=body_mode,
            operation=operation,
            scope=scope,
            max_stream_bytes=max_stream_bytes,
        )
        if response.status_code == 401 and authorization and authorization.startswith("Bearer "):
            authorization = await self.authorization_header(scope, refresh=True)
            response = await self.transport.request(
                "GET",
                url,
                headers={**dict(extra_headers or {}), "Authorization": authorization},
                body_mode=body_mode,
                operation=f"{operation}-after-token-refresh",
                scope=scope,
                max_stream_bytes=max_stream_bytes,
            )
        return response
