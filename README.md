# OCI registry validator

`oci-registry-validator` checks whether an OCI/Docker Distribution registry
supports the discovery and image-pull operations needed by the OpenVAS
container image scanner. It records sanitized evidence for authentication,
inventory, manifest, configuration-blob, and layer requests.

The validator is diagnostic tooling. It does not scan images for
vulnerabilities and it does not modify registry content.

## Capabilities

The validator supports:

- anonymous, Basic, and Bearer challenge authentication;
- caller-defined endpoint probes;
- paginated catalog and tag inventory;
- Docker schema 1/2 and OCI manifest/index traversal;
- image configuration blob retrieval;
- optional full layer streaming with digest verification; and
- sanitized request/response evidence.

Four modes control the amount of registry traffic:

- `probe` checks `/v2/` and explicitly configured endpoints.
- `inventory` also walks catalog and tag-list endpoints.
- `metadata` also retrieves configured image manifests and configuration
  blobs.
- `openvas` also streams image layers and verifies their digests, closely
  reproducing the scanner's network requirements.

The implementation is deliberately conservative. HTTPS is required unless
HTTP is explicitly enabled, authentication and redirect destinations must be
allowlisted, and inventory, response, platform, and layer sizes are bounded.

## Configuration

Copy [`example.toml`](example.toml) and adjust the non-secret registry
settings. Credentials and pre-issued tokens must be supplied through named
environment variables; the validator rejects secrets stored directly in the
TOML file.

```bash
cp example.toml registry-validator.toml
export REGISTRY_USERNAME='example-user'
export REGISTRY_PASSWORD='example-password'
```

Configured `repositories` are enumerated in every mode. Catalog walking is
performed in `inventory` mode and can also be enabled with
`walk_catalog = true`. Configured images are validated only in `metadata` and
`openvas` modes. Inventory results are never converted automatically into
bulk image downloads.

## Run with a container

Build the minimal, non-root Alpine-based image:

```bash
docker build -t oci-registry-validator .
```

Run it with a read-only configuration mount and a writable evidence directory:

```bash
mkdir -p registry-evidence
docker run --rm \
  -e REGISTRY_USERNAME \
  -e REGISTRY_PASSWORD \
  -v "$PWD/registry-validator.toml:/config/config.toml:ro" \
  -v "$PWD/registry-evidence:/evidence" \
  oci-registry-validator \
  --config /config/config.toml \
  --output /evidence
```

Pass `--mode probe`, `inventory`, `metadata`, or `openvas` to override the
configured mode. The container runs as an unprivileged user, so the mounted
evidence directory must be writable by the container user.

## Run from Python

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/registry-validator --config registry-validator.toml
```

The command exits with:

- `0` when every required operation passes;
- `1` when a required operation fails;
- `2` when configuration is invalid; or
- `3` when strict inventory completeness was requested but the result is
  partial.

## Evidence

Each run writes the following files under the configured output directory:

```text
summary.json
exchanges.jsonl
inventory.json
report.txt
bodies/
```

Authorization headers, cookies, token response bodies, URL user information,
and common signed-query parameters are redacted. Small non-sensitive response
bodies may be stored under `bodies/`; layer bodies are streamed, hashed, and
discarded.

Evidence sanitization is defense in depth, not a guarantee that arbitrary
registry responses contain no sensitive data. Review an evidence bundle
before sharing it outside its intended audience.

## Development

Install the test dependencies and run the checks:

```bash
python3 -m venv .venv
.venv/bin/pip install '.[test]'
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest
```

The end-to-end tests use in-process mock registries and do not require access
to an external registry.

## Status and limitations

This repository contains an early diagnostic implementation, not a supported
customer-facing product. It validates registry protocol behavior and network
reachability but does not reproduce every scanner implementation detail or
guarantee that a later image scan will succeed.

Licensed under the [MIT License](LICENSE).
