from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import ConfigError, RunConfig, load_config
from .evidence import EvidenceWriter
from .transport import RecordedTransport
from .validator import RegistryValidator


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="registry-validator",
        description="Validate OCI registry operations used by OpenVAS",
    )
    parser.add_argument("--config", required=True, type=Path, help="TOML configuration file")
    parser.add_argument("--output", type=Path, help="override evidence output directory")
    parser.add_argument(
        "--mode",
        choices=("probe", "inventory", "metadata", "openvas"),
        help="override configured validation mode",
    )
    return parser


def _report(summary: dict[str, Any], output_dir: Path) -> str:
    lines = [
        "OCI registry validator",
        f"Generated: {summary['generated_at']}",
        f"Mode: {summary['mode']}",
        f"Overall status: {summary['status']}",
        f"Evidence: {output_dir}",
        "",
    ]
    for registry in summary["registries"]:
        lines.append(f"{registry['registry']}: {registry['status']} ({registry['url']})")
        for result in registry["results"]:
            message = f" - {result['message']}" if result["message"] else ""
            lines.append(f"  [{result['status']}] {result['operation']}{message}")
        lines.append("")
    return "\n".join(lines)


async def run_validation(config: RunConfig) -> int:
    generated_at = datetime.now(UTC).isoformat()
    summaries: list[dict[str, Any]] = []
    inventories: dict[str, Any] = {}

    with EvidenceWriter(config.output_dir) as evidence:
        for registry in config.registries:
            transport = RecordedTransport(
                registry_name=registry.name,
                registry_url=registry.url,
                evidence=evidence,
                allow_http=registry.allow_http,
                verify_tls=registry.verify_tls,
                client_cert=registry.client_cert,
                redirect_hosts=registry.redirect_hosts,
                max_capture_bytes=config.max_capture_bytes,
                max_response_bytes=config.max_response_bytes,
            )
            try:
                validator = RegistryValidator(registry, config.mode, transport)
                registry_summary, inventory = await validator.run()
            except Exception as error:
                registry_summary = {
                    "registry": registry.name,
                    "url": registry.url,
                    "mode": config.mode,
                    "status": "FAIL",
                    "results": [
                        {
                            "operation": "validator",
                            "status": getattr(error, "category", "FAIL_FORMAT"),
                            "message": str(error),
                            "required": True,
                            "details": {},
                        }
                    ],
                }
                inventory = {
                    "registry": registry.name,
                    "catalog_status": "failed",
                    "complete": False,
                    "repositories": {},
                }
            finally:
                await transport.close()
            summaries.append(registry_summary)
            inventories[registry.name] = inventory

        failed = any(summary["status"] == "FAIL" for summary in summaries)
        partial = any(summary["status"] == "PARTIAL" for summary in summaries)
        overall = "FAIL" if failed else ("PARTIAL" if partial else "PASS")
        summary = {
            "schema_version": 1,
            "generated_at": generated_at,
            "mode": config.mode,
            "status": overall,
            "registries": summaries,
        }
        evidence.write_json("summary.json", summary)
        evidence.write_json("inventory.json", {"schema_version": 1, "registries": inventories})
        evidence.write_text("report.txt", _report(summary, config.output_dir))

    if failed:
        return 1
    if partial and config.strict_inventory:
        return 3
    return 0


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.output:
            config = replace(config, output_dir=args.output)
        if args.mode:
            config = replace(config, mode=args.mode)
    except ConfigError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    exit_code = asyncio.run(run_validation(config))
    print(config.output_dir / "report.txt")
    raise SystemExit(exit_code)
