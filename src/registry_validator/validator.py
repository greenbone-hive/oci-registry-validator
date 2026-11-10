from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from .auth import RegistryAuthenticator
from .config import Mode, ProbeConfig, RegistryConfig
from .protocol import infer_scope, parse_image_reference, parse_next_link
from .transport import RecordedTransport, ResponseData

MANIFEST_ACCEPT = ",".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)
INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}


class ValidationError(RuntimeError):
    def __init__(self, message: str, category: str = "FAIL_FORMAT") -> None:
        super().__init__(message)
        self.category = category


def _json_body(response: ResponseData, operation: str) -> dict[str, Any]:
    try:
        value = json.loads((response.body or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{operation} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{operation} returned a non-object JSON value")
    return value


def _result(
    operation: str,
    status: str,
    *,
    message: str = "",
    required: bool = True,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "status": status,
        "message": message,
        "required": required,
        "details": details or {},
    }


class RegistryValidator:
    def __init__(
        self,
        config: RegistryConfig,
        mode: Mode,
        transport: RecordedTransport,
    ) -> None:
        self.config = config
        self.mode = mode
        self.transport = transport
        self.auth = RegistryAuthenticator(config, transport)
        self.results: list[dict[str, Any]] = []
        self.inventory: dict[str, Any] = {
            "registry": config.name,
            "catalog_status": "not-requested",
            "complete": True,
            "repositories": {},
        }

    async def run(self) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            handshake = await self.auth.handshake()
            self.results.append(
                _result(
                    "registry-handshake",
                    "PASS",
                    details={"http_status": handshake.status_code, "scheme": handshake.scheme},
                )
            )
        except Exception as error:
            self._record_exception("registry-handshake", error)
            return self.summary(), self.inventory

        for probe in self.config.probes:
            await self._run_probe(probe)

        repositories = set(self.config.repositories)
        if self.mode == "inventory" or self.config.walk_catalog:
            repositories.update(await self._walk_catalog())
        for repository in sorted(repositories):
            await self._walk_tags(repository)

        if self.mode in {"metadata", "openvas"}:
            for image in self.config.images:
                await self._validate_image(image, download_layers=self.mode == "openvas")

        return self.summary(), self.inventory

    def summary(self) -> dict[str, Any]:
        required_failures = [
            result
            for result in self.results
            if result["required"] and result["status"].startswith("FAIL")
        ]
        partial = any(result["status"] == "PARTIAL" for result in self.results)
        return {
            "registry": self.config.name,
            "url": self.config.url,
            "mode": self.mode,
            "status": "FAIL" if required_failures else ("PARTIAL" if partial else "PASS"),
            "results": self.results,
        }

    def _record_exception(self, operation: str, error: Exception, required: bool = True) -> None:
        category = getattr(error, "category", "FAIL_FORMAT")
        self.results.append(_result(operation, category, message=str(error), required=required))

    async def _run_probe(self, probe: ProbeConfig) -> None:
        operation = f"probe:{probe.path}"
        url = (
            probe.path
            if "://" in probe.path
            else urljoin(f"{self.config.url}/", probe.path.lstrip("/"))
        )
        scope = probe.scope or infer_scope(probe.path)
        try:
            response = await self.auth.get(
                url,
                scope=scope,
                body_mode="capture",
                operation=operation,
            )
            if response.status_code not in probe.expected_statuses:
                raise ValidationError(
                    f"expected HTTP {probe.expected_statuses}, received {response.status_code}",
                    "FAIL_HTTP",
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0]
            if probe.expected_content_types and not any(
                content_type.startswith(expected) for expected in probe.expected_content_types
            ):
                raise ValidationError(
                    f"unexpected content type {content_type!r}",
                    "FAIL_FORMAT",
                )
            self.results.append(
                _result(
                    operation,
                    "PASS",
                    required=probe.required,
                    details={"http_status": response.status_code},
                )
            )
        except Exception as error:
            self._record_exception(operation, error, required=probe.required)

    async def _walk_catalog(self) -> set[str]:
        operation = "inventory:catalog"
        repositories: set[str] = set()
        url: str | None = f"{self.config.url}/v2/_catalog?n={self.config.page_size}"
        visited: set[str] = set()
        page = 0
        try:
            while url:
                if url in visited:
                    raise ValidationError("catalog pagination loop detected")
                if page >= self.config.max_pages:
                    self.inventory["complete"] = False
                    self.results.append(
                        _result(operation, "PARTIAL", message="catalog page limit reached")
                    )
                    break
                visited.add(url)
                page += 1
                response = await self.auth.get(
                    url,
                    scope="registry:catalog:*",
                    body_mode="capture",
                    operation=operation,
                )
                if response.status_code in {401, 403}:
                    self.inventory["catalog_status"] = "forbidden"
                    self.inventory["complete"] = False
                    self.results.append(
                        _result(
                            operation,
                            "PARTIAL",
                            message=f"catalog returned HTTP {response.status_code}",
                        )
                    )
                    return repositories
                if response.status_code in {404, 405}:
                    self.inventory["catalog_status"] = "unsupported"
                    self.inventory["complete"] = False
                    self.results.append(
                        _result(
                            operation,
                            "PARTIAL",
                            message=f"catalog returned HTTP {response.status_code}",
                        )
                    )
                    return repositories
                if response.status_code != 200:
                    raise ValidationError(
                        f"catalog returned HTTP {response.status_code}",
                        "FAIL_HTTP",
                    )
                payload = _json_body(response, operation)
                page_repositories = payload.get("repositories")
                if not isinstance(page_repositories, list) or not all(
                    isinstance(value, str) for value in page_repositories
                ):
                    raise ValidationError("catalog response has no string repositories array")
                repositories.update(page_repositories)
                if len(repositories) > self.config.max_repositories:
                    repositories = set(sorted(repositories)[: self.config.max_repositories])
                    self.inventory["complete"] = False
                    self.results.append(
                        _result(operation, "PARTIAL", message="repository limit reached")
                    )
                    break
                url = parse_next_link(response.headers.get("link"), response.final_url)
            self.inventory["catalog_status"] = "accessible"
            if not any(result["operation"] == operation for result in self.results):
                self.results.append(
                    _result(
                        operation,
                        "PASS",
                        details={"repositories": len(repositories), "pages": page},
                    )
                )
        except Exception as error:
            self.inventory["catalog_status"] = "failed"
            self.inventory["complete"] = False
            self._record_exception(operation, error)
        return repositories

    async def _walk_tags(self, repository: str) -> None:
        operation = f"inventory:tags:{repository}"
        quoted_repository = quote(repository, safe="/")
        url: str | None = (
            f"{self.config.url}/v2/{quoted_repository}/tags/list?n={self.config.page_size}"
        )
        scope = f"repository:{repository}:pull"
        tags: set[str] = set()
        visited: set[str] = set()
        page = 0
        try:
            while url:
                if url in visited:
                    raise ValidationError(f"tag pagination loop detected for {repository}")
                if page >= self.config.max_pages:
                    self.inventory["complete"] = False
                    self.results.append(
                        _result(operation, "PARTIAL", message="tag page limit reached")
                    )
                    break
                visited.add(url)
                page += 1
                response = await self.auth.get(
                    url,
                    scope=scope,
                    body_mode="capture",
                    operation=operation,
                )
                if response.status_code != 200:
                    raise ValidationError(
                        f"tag listing returned HTTP {response.status_code}",
                        "FAIL_HTTP",
                    )
                payload = _json_body(response, operation)
                page_tags = payload.get("tags") or []
                if not isinstance(page_tags, list) or not all(
                    isinstance(value, str) for value in page_tags
                ):
                    raise ValidationError("tag response has no string tags array")
                tags.update(page_tags)
                if len(tags) > self.config.max_tags:
                    tags = set(sorted(tags)[: self.config.max_tags])
                    self.inventory["complete"] = False
                    self.results.append(_result(operation, "PARTIAL", message="tag limit reached"))
                    break
                url = parse_next_link(response.headers.get("link"), response.final_url)
            self.inventory["repositories"][repository] = sorted(tags)
            if not any(result["operation"] == operation for result in self.results):
                self.results.append(
                    _result(operation, "PASS", details={"tags": len(tags), "pages": page})
                )
        except Exception as error:
            self.inventory["complete"] = False
            self._record_exception(operation, error)

    async def _get_manifest(
        self,
        repository: str,
        reference: str,
        *,
        operation: str,
    ) -> tuple[dict[str, Any], ResponseData, str]:
        url = (
            f"{self.config.url}/v2/{quote(repository, safe='/')}/manifests/"
            f"{quote(reference, safe=':@')}"
        )
        scope = f"repository:{repository}:pull"
        headers = {"Accept": MANIFEST_ACCEPT}
        response = await self.auth.get(
            url,
            scope=scope,
            body_mode="capture",
            operation=operation,
            extra_headers=headers,
        )
        if response.status_code != 200:
            raise ValidationError(f"manifest returned HTTP {response.status_code}", "FAIL_HTTP")
        manifest = _json_body(response, operation)
        media_type = str(
            manifest.get("mediaType") or response.headers.get("content-type", "")
        ).split(";", 1)[0]
        return manifest, response, media_type

    async def _validate_image(self, image: str, *, download_layers: bool) -> None:
        operation = f"image:{image}"
        authority = urlsplit(self.config.url).netloc
        try:
            expected_authority = authority
            if image.startswith("oci://docker.io/") and authority == "registry-1.docker.io":
                expected_authority = "docker.io"
            reference = parse_image_reference(image, expected_authority)
            repository = reference.repository
            if authority == "registry-1.docker.io" and "/" not in repository:
                repository = f"library/{repository}"
            manifest, response, media_type = await self._get_manifest(
                repository,
                reference.reference,
                operation=f"{operation}:manifest",
            )
            expected_digest = (
                reference.reference if reference.reference.startswith("sha256:") else None
            )
            if expected_digest and expected_digest != f"sha256:{response.sha256}":
                raise ValidationError(
                    "manifest digest does not match image reference", "FAIL_DIGEST"
                )

            platform_results: list[dict[str, Any]] = []
            if media_type in INDEX_MEDIA_TYPES or "manifests" in manifest:
                descriptors = manifest.get("manifests")
                if not isinstance(descriptors, list):
                    raise ValidationError("index has no manifests array")
                supported = [
                    descriptor
                    for descriptor in descriptors
                    if isinstance(descriptor, dict)
                    and isinstance(descriptor.get("platform"), dict)
                    and descriptor["platform"].get("os") not in {None, "", "unknown"}
                    and descriptor["platform"].get("architecture") not in {None, "", "unknown"}
                ]
                if len(supported) > self.config.max_platforms:
                    raise ValidationError(
                        f"index has {len(supported)} supported platforms; "
                        f"limit is {self.config.max_platforms}"
                    )
                for descriptor in supported:
                    digest = descriptor.get("digest")
                    if not isinstance(digest, str):
                        raise ValidationError("platform descriptor has no digest")
                    child, child_response, child_media_type = await self._get_manifest(
                        reference.repository,
                        digest,
                        operation=f"{operation}:platform-manifest",
                    )
                    if child_media_type in INDEX_MEDIA_TYPES or "manifests" in child:
                        raise ValidationError("embedded manifest indexes are not supported")
                    if digest.startswith("sha256:") and digest != f"sha256:{child_response.sha256}":
                        raise ValidationError("platform manifest digest mismatch", "FAIL_DIGEST")
                    platform_results.append(
                        await self._validate_leaf_manifest(
                            repository,
                            child,
                            operation,
                            descriptor.get("platform", {}),
                            download_layers,
                        )
                    )
            else:
                platform_results.append(
                    await self._validate_leaf_manifest(
                        repository,
                        manifest,
                        operation,
                        {},
                        download_layers,
                    )
                )
            self.results.append(
                _result(
                    operation,
                    "PASS",
                    details={"media_type": media_type, "platforms": platform_results},
                )
            )
        except Exception as error:
            self._record_exception(operation, error)

    async def _validate_leaf_manifest(
        self,
        repository: str,
        manifest: dict[str, Any],
        operation: str,
        platform: dict[str, Any],
        download_layers: bool,
    ) -> dict[str, Any]:
        scope = f"repository:{repository}:pull"
        config = manifest.get("config")
        if isinstance(config, dict) and isinstance(config.get("digest"), str):
            config_digest = config["digest"]
            config_response = await self.auth.get(
                f"{self.config.url}/v2/{quote(repository, safe='/')}/blobs/"
                f"{quote(config_digest, safe=':')}",
                scope=scope,
                body_mode="capture",
                operation=f"{operation}:config",
            )
            if config_response.status_code != 200:
                raise ValidationError(
                    f"config blob returned HTTP {config_response.status_code}",
                    "FAIL_HTTP",
                )
            if (
                config_digest.startswith("sha256:")
                and config_digest != f"sha256:{config_response.sha256}"
            ):
                raise ValidationError("config blob digest mismatch", "FAIL_DIGEST")

        layers = manifest.get("layers")
        if layers is None and isinstance(manifest.get("fsLayers"), list):
            layers = [{"digest": value.get("blobSum")} for value in manifest["fsLayers"]]
        if not isinstance(layers, list):
            raise ValidationError("manifest has no layers array")
        layer_digests = [
            layer.get("digest")
            for layer in layers
            if isinstance(layer, dict) and isinstance(layer.get("digest"), str)
        ]
        if len(layer_digests) != len(layers):
            raise ValidationError("one or more layer descriptors have no digest")

        downloaded_bytes = 0
        if download_layers:
            for digest in layer_digests:
                remaining = self.config.max_layer_bytes - downloaded_bytes
                if remaining <= 0:
                    raise ValidationError("image layer byte limit reached", "PARTIAL")
                response = await self.auth.get(
                    f"{self.config.url}/v2/{quote(repository, safe='/')}/blobs/"
                    f"{quote(digest, safe=':')}",
                    scope=scope,
                    body_mode="stream",
                    operation=f"{operation}:layer",
                    max_stream_bytes=remaining,
                )
                if response.status_code != 200:
                    raise ValidationError(
                        f"layer blob returned HTTP {response.status_code}",
                        "FAIL_HTTP",
                    )
                if digest.startswith("sha256:") and digest != f"sha256:{response.sha256}":
                    raise ValidationError("layer blob digest mismatch", "FAIL_DIGEST")
                downloaded_bytes += response.byte_count

        return {
            "platform": platform,
            "layers": len(layer_digests),
            "downloaded_bytes": downloaded_bytes,
        }
