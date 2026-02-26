from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

try:  # pragma: no cover - optional dependency
    import yaml as _yaml
except Exception:  # pragma: no cover - optional dependency
    _yaml = None


def load_yaml(path: Path) -> Any:
    docs = load_yaml_all(path)
    if not docs:
        return None
    if len(docs) > 1:
        raise ValueError(f"expected a single document in {path}, found {len(docs)}")
    return docs[0]


def load_yaml_all(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()

    if stripped.startswith("{") or stripped.startswith("["):
        decoded = json.loads(text)
        if isinstance(decoded, list):
            return [doc for doc in decoded if doc is not None]
        return [decoded]

    if _yaml is not None:
        docs = list(_yaml.safe_load_all(text))
        return [doc for doc in docs if doc is not None]

    return _load_yaml_with_ruby(text, path)


def _load_yaml_with_ruby(text: str, path: Path) -> list[Any]:
    script = """
require 'yaml'
require 'json'
input = STDIN.read
docs = YAML.load_stream(input).to_a
puts JSON.generate(docs)
"""
    try:
        result = subprocess.run(
            ["ruby", "-e", script],
            input=text,
            text=True,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "YAML parsing requires either PyYAML or Ruby with Psych support"
        ) from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or "unknown YAML parse error"
        raise ValueError(f"failed parsing YAML in {path}: {message}") from exc

    decoded = json.loads(result.stdout or "[]")
    if not isinstance(decoded, list):
        raise ValueError(f"unexpected YAML decoding result for {path}")
    return [doc for doc in decoded if doc is not None]
