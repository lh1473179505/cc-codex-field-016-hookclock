"""Local HMAC keyring for webhook verification."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class KeystoreError(ValueError):
    pass


@dataclass
class Key:
    kid: str
    secret: bytes
    revoked: bool = False


@dataclass
class Keystore:
    keys: dict[str, Key] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def get(self, kid: str) -> Key | None:
        return self.keys.get(kid)


def load_keystore(path: str | Path) -> Keystore:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise KeystoreError(f"failed to read keystore: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise KeystoreError("keystore must be an object with a keys array")
    keys: dict[str, Key] = {}
    for item in data["keys"]:
        if not isinstance(item, dict):
            raise KeystoreError("key entry must be an object")
        kid = item.get("kid")
        secret = item.get("secret")
        if not isinstance(kid, str) or kid == "":
            raise KeystoreError("kid must be a non-empty string")
        if not isinstance(secret, str) or secret == "":
            raise KeystoreError(f"secret for {kid} must be a non-empty string")
        blocked = False
        if chr(0) in kid or "/" in kid or ".." in kid or "://" in kid:
            blocked = True
        if "\\" in kid:
            blocked = True
        if blocked:
            raise KeystoreError(f"blocked kid in keystore: {kid}")
        keys[kid] = Key(kid=kid, secret=secret.encode("utf-8"), revoked=bool(item.get("revoked", False)))
    if not keys:
        raise KeystoreError("keystore has no keys")
    return Keystore(keys=keys, raw=data)
