# Registry validator PoC

This PoC validates the OCI/Docker Distribution operations used by the OpenVAS
container image scanner. It supports:

- anonymous, Basic, and Bearer challenge authentication;
- caller-defined endpoint probes;
- paginated catalog and tag inventory;
- Docker schema 1/2 and OCI manifest/index traversal;
- config blob retrieval;
- optional full layer streaming and digest verification; and
- sanitized request/response evidence.

It is intentionally conservative: HTTPS is required unless explicitly
disabled, external authentication and redirect hosts require allowlisting, and
inventory and response sizes are bounded.

## Install

Use a disposable virtual environment outside the repository:

```bash
python3 -m venv /tmp/openvas-registry-validator-venv
/tmp/openvas-registry-validator-venv/bin/pip install .
```

## Configure

Copy `example.toml` and provide secrets through environment variables. Do not
put credentials directly in the TOML file.

```bash
export REGISTRY_USERNAME='example-user'
export REGISTRY_PASSWORD='example-password'
cp example.toml /tmp/registry-validator.toml
```

The four modes are:

- `probe`: `/v2/` and configured explicit probes;
- `inventory`: probe plus catalog and tag walking;
- `metadata`: probe plus configured image manifests and config blobs; and
- `openvas`: metadata plus streamed layer GETs and digest verification.

Configured `repositories` are enumerated in all modes. Catalog walking is
performed in `inventory` mode and can also be enabled with
`walk_catalog = true` in other modes. Images are validated only in `metadata`
and `openvas` modes; inventory is never converted automatically into mass
layer downloads.

## Run

```bash
/tmp/openvas-registry-validator-venv/bin/registry-validator \
  --config /tmp/registry-validator.toml
```

Override the configured mode or evidence directory when needed:

```bash
/tmp/openvas-registry-validator-venv/bin/registry-validator \
  --config /tmp/registry-validator.toml \
  --mode inventory \
  --output /tmp/registry-evidence
```

The command returns:

- `0` when all required operations pass;
- `1` when a required operation fails;
- `2` for invalid configuration; and
- `3` when strict inventory completeness was requested but inventory is
  partial.

## Evidence

Each run writes:

```text
<output>/
├── summary.json
├── exchanges.jsonl
├── inventory.json
├── report.txt
└── bodies/
```

Authorization headers, cookies, token response bodies, URL userinfo, and common
signed-query parameters are redacted. Small non-sensitive response bodies are
stored under `bodies/`; layer bodies are streamed, hashed, and discarded.

This is a PoC, not yet a hardened customer-facing diagnostic. Review the
limitations in the parent project README before using it against sensitive
registries.

## Test

```bash
python3 -m venv /tmp/openvas-registry-validator-test-venv
/tmp/openvas-registry-validator-test-venv/bin/pip install '.[test]'
/tmp/openvas-registry-validator-test-venv/bin/ruff check .
/tmp/openvas-registry-validator-test-venv/bin/ruff format --check .
/tmp/openvas-registry-validator-test-venv/bin/pytest
```

The end-to-end test starts an in-process token-authenticated mock registry and
does not require external network access.

## Cleanup

Remove only the explicit disposable paths used above:

```bash
rm -rf -- /tmp/openvas-registry-validator-venv
rm -rf -- /tmp/openvas-registry-validator-test-venv
rm -rf -- /tmp/registry-evidence
rm -f -- /tmp/registry-validator.toml
```
