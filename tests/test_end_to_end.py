from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from registry_validator.cli import run_validation
from registry_validator.config import load_config

LAYER = b"mock layer content\n"
LAYER_DIGEST = f"sha256:{hashlib.sha256(LAYER).hexdigest()}"
CONFIG_BODY = json.dumps(
    {"architecture": "amd64", "os": "linux", "config": {}},
    separators=(",", ":"),
).encode()
CONFIG_DIGEST = f"sha256:{hashlib.sha256(CONFIG_BODY).hexdigest()}"
MANIFEST_BODY = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(CONFIG_BODY),
            "digest": CONFIG_DIGEST,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "size": len(LAYER),
                "digest": LAYER_DIGEST,
            }
        ],
    },
    separators=(",", ":"),
).encode()


class RegistryHandler(BaseHTTPRequestHandler):
    server_version = "MockRegistry/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _send(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == "Bearer mock-secret-token"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/v2/":
            if self._authorized():
                self._send(200, b"{}")
            else:
                realm = f"http://127.0.0.1:{self.server.server_port}/token"
                self._send(
                    401,
                    b'{"errors":[]}',
                    headers={"WWW-Authenticate": f'Bearer realm="{realm}",service="mock-registry"'},
                )
            return
        if parsed.path == "/token":
            query = parse_qs(parsed.query)
            assert query.get("service") == ["mock-registry"]
            assert query.get("scope")
            self._send(200, b'{"token":"mock-secret-token"}')
            return
        if not self._authorized():
            self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}')
            return
        if parsed.path == "/v2/_catalog":
            query = parse_qs(parsed.query)
            if "last" not in query:
                next_link = (
                    f"<http://127.0.0.1:{self.server.server_port}"
                    '/v2/_catalog?n=1&last=team%2Fone>; rel="next"'
                )
                self._send(200, b'{"repositories":["team/one"]}', headers={"Link": next_link})
            else:
                self._send(200, b'{"repositories":["team/two"]}')
            return
        if parsed.path == "/v2/team/one/tags/list":
            self._send(200, b'{"name":"team/one","tags":["latest"]}')
            return
        if parsed.path == "/v2/team/two/tags/list":
            self._send(200, b'{"name":"team/two","tags":["stable"]}')
            return
        if parsed.path == "/v2/team/one/manifests/latest":
            digest = f"sha256:{hashlib.sha256(MANIFEST_BODY).hexdigest()}"
            self._send(
                200,
                MANIFEST_BODY,
                content_type="application/vnd.docker.distribution.manifest.v2+json",
                headers={"Docker-Content-Digest": digest},
            )
            return
        if parsed.path == f"/v2/team/one/blobs/{CONFIG_DIGEST}":
            self._send(200, CONFIG_BODY)
            return
        if parsed.path == f"/v2/team/one/blobs/{LAYER_DIGEST}":
            self._send(200, LAYER, content_type="application/octet-stream")
            return
        self._send(404, b'{"errors":[{"code":"NOT_FOUND"}]}')


class BasicRegistryHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        expected = "Basic " + base64.b64encode(b"test-user:test-password").decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="mock"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_basic_auth_probe(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    server = ThreadingHTTPServer(("127.0.0.1", 0), BasicRegistryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("BASIC_USER", "test-user")
    monkeypatch.setenv("BASIC_PASSWORD", "test-password")
    try:
        output = tmp_path / "basic-evidence"
        config_path = tmp_path / "basic.toml"
        config_path.write_text(
            f"""
[run]
mode = "probe"
output_dir = "{output}"

[[registries]]
name = "basic"
url = "http://127.0.0.1:{server.server_port}"
auth = "basic"
username_env = "BASIC_USER"
password_env = "BASIC_PASSWORD"
allow_http = true
verify_tls = false

[[registries.probes]]
path = "/v2/example/tags/list"
expected_statuses = [200]
""",
            encoding="utf-8",
        )
        exit_code = asyncio.run(run_validation(load_config(config_path)))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exit_code == 0
    evidence_bytes = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
    evidence_text = (output / "exchanges.jsonl").read_text(encoding="utf-8")
    assert b"test-password" not in evidence_bytes
    assert "[REDACTED]" in evidence_text


def test_openvas_mode_end_to_end(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        output = tmp_path / "evidence"
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            f"""
[run]
mode = "openvas"
output_dir = "{output}"
strict_inventory = true

[[registries]]
name = "mock"
url = "http://127.0.0.1:{server.server_port}"
auth = "auto"
allow_http = true
verify_tls = false
auth_hosts = ["127.0.0.1"]
page_size = 1
walk_catalog = true
images = ["team/one:latest"]

[[registries.probes]]
path = "/v2/team/one/tags/list"
scope = "repository:team/one:pull"
expected_statuses = [200]
expected_content_types = ["application/json"]
""",
            encoding="utf-8",
        )
        exit_code = asyncio.run(run_validation(load_config(config_path)))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exit_code == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert summary["status"] == "PASS"
    assert inventory["registries"]["mock"]["repositories"] == {
        "team/one": ["latest"],
        "team/two": ["stable"],
    }
    evidence_bytes = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
    evidence_text = (output / "exchanges.jsonl").read_text(encoding="utf-8")
    assert b"mock-secret-token" not in evidence_bytes
    assert "[REDACTED]" in evidence_text
    assert LAYER not in b"".join(path.read_bytes() for path in (output / "bodies").iterdir())
