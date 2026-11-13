"""Webhook verification policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    max_skew_seconds: int
    require_kid: bool
    allowed_methods: set[str]
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    skew = data.get("max_skew_seconds", 300)
    if not isinstance(skew, int) or isinstance(skew, bool) or skew < 0:
        raise PolicyError("max_skew_seconds must be a non-negative integer")
    methods = data.get("allowed_methods", ["POST"])
    if not isinstance(methods, list) or not all(isinstance(x, str) for x in methods):
        raise PolicyError("allowed_methods must be an array of strings")
    return Policy(
        max_skew_seconds=skew,
        require_kid=bool(data.get("require_kid", True)),
        allowed_methods={m.upper() for m in methods},
        raw=data,
    )
