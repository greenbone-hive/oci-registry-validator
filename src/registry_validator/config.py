from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

Mode = Literal["probe", "inventory", "metadata", "openvas"]
AuthMode = Literal["auto", "anonymous", "basic", "bearer"]


class ConfigError(ValueError):
    """Raised when configuration is invalid."""


@dataclass(frozen=True)
class ProbeConfig:
    path: str
    scope: str | None = None
    expected_statuses: tuple[int, ...] = (200,)
    expected_content_types: tuple[str, ...] = ()
    required: bool = True


@dataclass(frozen=True)
class RegistryConfig:
    name: str
    url: str
    auth: AuthMode = "auto"
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None
    allow_http: bool = False
    verify_tls: bool | str = True
    client_cert: str | tuple[str, str] | None = None
    auth_hosts: tuple[str, ...] = ()
    redirect_hosts: tuple[str, ...] = ()
    page_size: int = 100
    max_pages: int = 20
    max_repositories: int = 1000
    max_tags: int = 10000
    max_platforms: int = 20
    max_layer_bytes: int = 10 * 1024 * 1024 * 1024
    walk_catalog: bool = False
    repositories: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    probes: tuple[ProbeConfig, ...] = ()


@dataclass(frozen=True)
class RunConfig:
    mode: Mode
    output_dir: Path
    strict_inventory: bool = False
    max_capture_bytes: int = 1024 * 1024
    max_response_bytes: int = 8 * 1024 * 1024
    registries: tuple[RegistryConfig, ...] = field(default_factory=tuple)


def _env_secret(data: dict[str, Any], direct_key: str, env_key: str) -> str | None:
    if direct_key in data:
        raise ConfigError(
            f"{direct_key} must not be stored directly; use {env_key} "
            "to name an environment variable"
        )
    env_name = data.get(env_key)
    if not env_name:
        return None
    value = os.environ.get(str(env_name))
    if value is None:
        raise ConfigError(f"environment variable {env_name!r} is not set")
    return value


def _positive_int(data: dict[str, Any], key: str, default: int) -> int:
    value = int(data.get(key, default))
    if value <= 0:
        raise ConfigError(f"{key} must be greater than zero")
    return value


def _parse_probe(data: dict[str, Any]) -> ProbeConfig:
    path = str(data.get("path", "")).strip()
    if not path:
        raise ConfigError("probe.path is required")
    statuses = tuple(int(value) for value in data.get("expected_statuses", [200]))
    if not statuses or any(value < 100 or value > 599 for value in statuses):
        raise ConfigError(f"invalid expected_statuses for probe {path!r}")
    return ProbeConfig(
        path=path,
        scope=str(data["scope"]) if data.get("scope") else None,
        expected_statuses=statuses,
        expected_content_types=tuple(
            str(value) for value in data.get("expected_content_types", [])
        ),
        required=bool(data.get("required", True)),
    )


def _parse_registry(data: dict[str, Any]) -> RegistryConfig:
    name = str(data.get("name", "")).strip()
    url = str(data.get("url", "")).rstrip("/")
    if not name or not url:
        raise ConfigError("each registry requires name and url")

    parsed = urlsplit(url)
    allow_http = bool(data.get("allow_http", False))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError(f"registry {name!r} has an invalid URL")
    if parsed.username or parsed.password:
        raise ConfigError(f"registry {name!r} URL must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigError(f"registry {name!r} URL must contain only scheme and authority")
    if parsed.scheme == "http" and not allow_http:
        raise ConfigError(f"registry {name!r} uses HTTP without allow_http=true")

    auth = str(data.get("auth", "auto"))
    if auth not in {"auto", "anonymous", "basic", "bearer"}:
        raise ConfigError(f"registry {name!r} has unsupported auth mode {auth!r}")

    username = _env_secret(data, "username", "username_env")
    password = _env_secret(data, "password", "password_env")
    token = _env_secret(data, "bearer_token", "bearer_token_env")
    if auth == "basic" and (username is None or password is None):
        raise ConfigError(f"registry {name!r} basic auth requires username_env and password_env")
    if auth == "bearer" and token is None:
        raise ConfigError(f"registry {name!r} bearer auth requires bearer_token_env")

    verify_value = data.get("verify_tls", True)
    verify_tls: bool | str
    verify_tls = verify_value if isinstance(verify_value, bool) else str(verify_value)

    client_cert_data = data.get("client_cert")
    client_key_data = data.get("client_key")
    client_cert: str | tuple[str, str] | None = None
    if client_cert_data and client_key_data:
        client_cert = (str(client_cert_data), str(client_key_data))
    elif client_cert_data:
        client_cert = str(client_cert_data)

    return RegistryConfig(
        name=name,
        url=url,
        auth=cast(AuthMode, auth),
        username=username,
        password=password,
        bearer_token=token,
        allow_http=allow_http,
        verify_tls=verify_tls,
        client_cert=client_cert,
        auth_hosts=tuple(str(value) for value in data.get("auth_hosts", [])),
        redirect_hosts=tuple(str(value) for value in data.get("redirect_hosts", [])),
        page_size=_positive_int(data, "page_size", 100),
        max_pages=_positive_int(data, "max_pages", 20),
        max_repositories=_positive_int(data, "max_repositories", 1000),
        max_tags=_positive_int(data, "max_tags", 10000),
        max_platforms=_positive_int(data, "max_platforms", 20),
        max_layer_bytes=_positive_int(data, "max_layer_bytes", 10 * 1024 * 1024 * 1024),
        walk_catalog=bool(data.get("walk_catalog", False)),
        repositories=tuple(str(value) for value in data.get("repositories", [])),
        images=tuple(str(value) for value in data.get("images", [])),
        probes=tuple(_parse_probe(value) for value in data.get("probes", [])),
    )


def load_config(path: Path) -> RunConfig:
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"unable to load {path}: {error}") from error

    run = data.get("run", {})
    mode = str(run.get("mode", "probe"))
    if mode not in {"probe", "inventory", "metadata", "openvas"}:
        raise ConfigError(f"unsupported run mode {mode!r}")
    output_dir = Path(str(run.get("output_dir", "registry-validator-evidence")))
    registries = tuple(_parse_registry(value) for value in data.get("registries", []))
    if not registries:
        raise ConfigError("at least one [[registries]] entry is required")
    if len({registry.name for registry in registries}) != len(registries):
        raise ConfigError("registry names must be unique")

    return RunConfig(
        mode=cast(Mode, mode),
        output_dir=output_dir,
        strict_inventory=bool(run.get("strict_inventory", False)),
        max_capture_bytes=_positive_int(run, "max_capture_bytes", 1024 * 1024),
        max_response_bytes=_positive_int(run, "max_response_bytes", 8 * 1024 * 1024),
        registries=registries,
    )
