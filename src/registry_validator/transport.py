from __future__ import annotations

import fnmatch
import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urljoin, urlsplit

import httpx

from .evidence import EvidenceWriter, sanitize_headers, sanitize_url

BodyMode = Literal["capture", "memory", "stream"]
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class TransportError(RuntimeError):
    category = "FAIL_NETWORK"


class RedirectPolicyError(TransportError):
    category = "FAIL_REDIRECT_POLICY"


class ResponseTooLargeError(TransportError):
    category = "FAIL_FORMAT"


class TlsError(TransportError):
    category = "FAIL_TLS"


@dataclass(frozen=True)
class ResponseData:
    status_code: int
    headers: dict[str, str]
    body: bytes | None
    final_url: str
    byte_count: int
    sha256: str
    exchange_ids: tuple[str, ...]


class RecordedTransport:
    def __init__(
        self,
        *,
        registry_name: str,
        registry_url: str,
        evidence: EvidenceWriter,
        allow_http: bool,
        verify_tls: bool | str,
        client_cert: str | tuple[str, str] | None,
        redirect_hosts: tuple[str, ...],
        max_capture_bytes: int,
        max_response_bytes: int,
        max_redirects: int = 10,
    ) -> None:
        self.registry_name = registry_name
        self.registry_url = registry_url
        self.evidence = evidence
        self.allow_http = allow_http
        self.redirect_hosts = redirect_hosts
        self.max_capture_bytes = max_capture_bytes
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self._registry_authority = self._authority(registry_url)
        self._client = httpx.AsyncClient(
            verify=verify_tls,
            cert=client_cert,
            follow_redirects=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    @staticmethod
    def _authority(url: str) -> str:
        parsed = urlsplit(url)
        if not parsed.hostname:
            return ""
        return f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname

    def host_allowed(self, url: str, patterns: tuple[str, ...] = ()) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.scheme == "http" and not self.allow_http:
            return False
        authority = self._authority(url)
        if authority == self._registry_authority:
            return True
        candidates = (authority, parsed.hostname or "")
        return any(
            fnmatch.fnmatch(candidate, pattern) for candidate in candidates for pattern in patterns
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body_mode: BodyMode = "capture",
        sensitive_body: bool = False,
        operation: str,
        scope: str | None = None,
        allowed_hosts: tuple[str, ...] | None = None,
        max_stream_bytes: int | None = None,
    ) -> ResponseData:
        allowed_patterns = self.redirect_hosts if allowed_hosts is None else allowed_hosts
        current_url = url
        current_headers = dict(headers or {})
        exchange_ids: list[str] = []
        visited: set[str] = set()

        for redirect_number in range(self.max_redirects + 1):
            if current_url in visited:
                raise RedirectPolicyError(f"redirect loop at {sanitize_url(current_url)}")
            visited.add(current_url)
            if not self.host_allowed(current_url, allowed_patterns):
                raise RedirectPolicyError(
                    f"request destination is not allowed: {sanitize_url(current_url)}"
                )

            exchange_id = self.evidence.next_exchange_id()
            exchange_ids.append(exchange_id)
            started_utc = time.time()
            started = time.monotonic()
            status_code: int | None = None
            response_headers: dict[str, str] = {}
            byte_count = 0
            body_hash = hashlib.sha256()
            body_buffer = bytearray()
            error_text: str | None = None
            response: httpx.Response | None = None

            try:
                request = self._client.build_request(method, current_url, headers=current_headers)
                response = await self._client.send(request, stream=True)
                status_code = response.status_code
                response_headers = dict(response.headers.items())
                is_redirect = status_code in REDIRECT_STATUSES and "location" in response.headers
                chunks = response.aiter_raw() if body_mode == "stream" else response.aiter_bytes()
                async for chunk in chunks:
                    byte_count += len(chunk)
                    body_hash.update(chunk)
                    if body_mode != "stream" and len(body_buffer) <= self.max_response_bytes:
                        body_buffer.extend(chunk)
                    if body_mode != "stream" and len(body_buffer) > self.max_response_bytes:
                        raise ResponseTooLargeError(
                            f"response exceeded {self.max_response_bytes} bytes at "
                            f"{sanitize_url(current_url)}"
                        )
                    if max_stream_bytes is not None and byte_count > max_stream_bytes:
                        raise ResponseTooLargeError(
                            f"stream exceeded {max_stream_bytes} bytes at "
                            f"{sanitize_url(current_url)}"
                        )
            except httpx.HTTPError as error:
                error_text = str(error)
                lowered = error_text.lower()
                if any(value in lowered for value in ("ssl", "tls", "certificate")):
                    raise TlsError(error_text) from error
                raise TransportError(error_text) from error
            except TransportError as error:
                error_text = str(error)
                raise
            finally:
                if response is not None:
                    await response.aclose()
                duration_ms = round((time.monotonic() - started) * 1000, 3)
                record = {
                    "schema_version": 1,
                    "exchange_id": exchange_id,
                    "registry": self.registry_name,
                    "operation": operation,
                    "scope": scope,
                    "started_at_unix": started_utc,
                    "duration_ms": duration_ms,
                    "request": {
                        "method": method,
                        "url": sanitize_url(current_url),
                        "headers": sanitize_headers(current_headers),
                    },
                    "response": {
                        "status": status_code,
                        "headers": sanitize_headers(response_headers),
                        "byte_count": byte_count,
                        "sha256": body_hash.hexdigest(),
                    },
                    "error": error_text,
                }
                self.evidence.record_exchange(record)

            assert response is not None
            is_redirect = (
                response.status_code in REDIRECT_STATUSES and "location" in response_headers
            )
            if is_redirect:
                if redirect_number >= self.max_redirects:
                    raise RedirectPolicyError(f"too many redirects at {sanitize_url(current_url)}")
                next_url = urljoin(current_url, response_headers["location"])
                if not self.host_allowed(next_url, allowed_patterns):
                    raise RedirectPolicyError(
                        f"redirect destination is not allowed: {sanitize_url(next_url)}"
                    )
                if self._authority(next_url) != self._authority(current_url):
                    current_headers.pop("Authorization", None)
                    current_headers.pop("Cookie", None)
                current_url = next_url
                continue

            body = None if body_mode == "stream" else bytes(body_buffer)
            if (
                body_mode == "capture"
                and not sensitive_body
                and body is not None
                and len(body) <= self.max_capture_bytes
            ):
                content_type = response_headers.get("content-type", "application/octet-stream")
                self.evidence.store_body(exchange_id, body, content_type)
            return ResponseData(
                status_code=response.status_code,
                headers=response_headers,
                body=body,
                final_url=current_url,
                byte_count=byte_count,
                sha256=body_hash.hexdigest(),
                exchange_ids=tuple(exchange_ids),
            )

        raise RedirectPolicyError(f"too many redirects at {sanitize_url(current_url)}")

    async def close(self) -> None:
        await self._client.aclose()
