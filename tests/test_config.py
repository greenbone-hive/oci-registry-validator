from pathlib import Path

import pytest

from registry_validator.config import ConfigError, load_config


def test_rejects_direct_secret(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        """
[run]
mode = "probe"

[[registries]]
name = "bad"
url = "https://registry.example"
username = "do-not-store-this"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="must not be stored directly"):
        load_config(config)


def test_rejects_http_without_opt_in(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        """
[run]
mode = "probe"

[[registries]]
name = "bad"
url = "http://registry.example"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="allow_http"):
        load_config(config)
