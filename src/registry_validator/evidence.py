from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-auth-token",
}
SENSITIVE_QUERY_RE = re.compile(
    r"(?:token|signature|credential|secret|password|x-amz-|x-goog-|^sig$|^se$|^sp$|^sv$)",
    re.IGNORECASE,
)


def sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: REDACTED if key.lower() in SENSITIVE_HEADERS else value
        for key, value in sorted(headers.items(), key=lambda item: item[0].lower())
    }


def sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    query = urlencode(
        [
            (key, REDACTED if SENSITIVE_QUERY_RE.search(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


class EvidenceWriter:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.body_dir = output_dir / "bodies"
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.body_dir.mkdir(exist_ok=True, mode=0o700)
        os.chmod(output_dir, 0o700)
        os.chmod(self.body_dir, 0o700)
        self._exchange_path = output_dir / "exchanges.jsonl"
        self._exchange_file = self._exchange_path.open("w", encoding="utf-8")
        os.chmod(self._exchange_path, 0o600)
        self._counter = 0

    def next_exchange_id(self) -> str:
        self._counter += 1
        return f"exchange-{self._counter:06d}"

    def record_exchange(self, record: dict[str, Any]) -> None:
        self._exchange_file.write(json.dumps(record, sort_keys=True) + "\n")
        self._exchange_file.flush()

    def store_body(self, exchange_id: str, body: bytes, content_type: str) -> str:
        suffix = ".json" if "json" in content_type.lower() else ".body"
        relative = Path("bodies") / f"{exchange_id}{suffix}"
        destination = self.output_dir / relative
        destination.write_bytes(body)
        os.chmod(destination, 0o600)
        return str(relative)

    def write_json(self, name: str, value: Any) -> None:
        destination = self.output_dir / name
        destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(destination, 0o600)

    def write_text(self, name: str, value: str) -> None:
        destination = self.output_dir / name
        destination.write_text(value, encoding="utf-8")
        os.chmod(destination, 0o600)

    def close(self) -> None:
        self._exchange_file.close()

    def __enter__(self) -> EvidenceWriter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
