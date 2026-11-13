"""Load a webhook request fixture and build the signing string.

This module does not verify the signature. It reads a JSON request
object, normalizes the header names, and exposes the canonical
signing input so inspect can print it and verify can apply policy.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RequestError(ValueError):
    pass


@dataclass
class HookRequest:
    method: str
    path: str
    headers: dict[str, str]  # original names preserved; lookup is case-insensitive
    body: bytes
    kid: str | None
    timestamp_text: str | None
    timestamp: int | None
    signature_hex: str | None
    signing_input: bytes
    parse_ok: bool
    parse_error: str | None


def _header(headers: dict[str, str], name: str) -> str | None:
    want = name.lower()
    for key, val in headers.items():
        if key.lower() == want:
            return val
    return None


def build_signing_input(method: str, path: str, timestamp_text: str, body: bytes) -> bytes:
    """Canonical signing input: METHOD \\n path \\n timestamp \\n hex(sha256(body))."""
    digest = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp_text}\n{digest}".encode("utf-8")


def parse_request_obj(data: dict[str, Any]) -> HookRequest:
    if not isinstance(data, dict):
        raise RequestError("request must be a JSON object")
    method = data.get("method", "POST")
    path = data.get("path", "/")
    if not isinstance(method, str) or not isinstance(path, str):
        raise RequestError("method and path must be strings")
    headers = data.get("headers", {})
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
        raise RequestError("headers must be an object of string values")
    body_field = data.get("body", "")
    if isinstance(body_field, str):
        body = body_field.encode("utf-8")
    elif isinstance(body_field, dict):
        # compact JSON, keys sorted, so the same fixture always signs the same way
        body = json.dumps(body_field, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    else:
        raise RequestError("body must be a string or a JSON object")

    kid = _header(headers, "X-Hook-Kid")
    ts_text = _header(headers, "X-Hook-Timestamp")
    sig = _header(headers, "X-Hook-Signature")
    timestamp = None
    err = None
    ok = True
    if ts_text is not None:
        if ts_text.isdigit() or (ts_text.startswith("-") and ts_text[1:].isdigit()):
            try:
                timestamp = int(ts_text)
            except ValueError:
                ok = False
                err = "invalid timestamp"
        else:
            ok = False
            err = "invalid timestamp"
    signing = build_signing_input(method, path, ts_text or "", body)
    return HookRequest(
        method=method,
        path=path,
        headers=headers,
        body=body,
        kid=kid,
        timestamp_text=ts_text,
        timestamp=timestamp,
        signature_hex=sig,
        signing_input=signing,
        parse_ok=ok,
        parse_error=err,
    )


def load_request(path: str | Path) -> HookRequest:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise RequestError(f"failed to read request: {exc}") from exc
    return parse_request_obj(data)


def request_to_dict(req: HookRequest) -> dict[str, Any]:
    return {
        "method": req.method,
        "path": req.path,
        "kid": req.kid,
        "timestamp": req.timestamp,
        "timestamp_text": req.timestamp_text,
        "signature_hex": req.signature_hex,
        "body_sha256": hashlib.sha256(req.body).hexdigest(),
        "signing_input": req.signing_input.decode("utf-8"),
        "parse_ok": req.parse_ok,
        "parse_error": req.parse_error,
    }
