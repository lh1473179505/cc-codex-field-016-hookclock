"""Fail-closed webhook signature verification.

Every check that cannot be proven valid contributes a reason code, and a
request is allowed only when no reason code was produced.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from hookclock.keys import Keystore
from hookclock.parse import HookRequest
from hookclock.policy import Policy


_BLOCKED_KID_MARKERS = ("/", "\\", "..", chr(0), "://")
_LOWER_HEX_DIGITS = frozenset("0123456789abcdef")
_SIGNATURE_LENGTH = 64


def _is_blocked_kid(kid: str) -> bool:
    return any(marker in kid for marker in _BLOCKED_KID_MARKERS)


def _parse_timestamp(text: str | None) -> int | None:
    """Parse a strict decimal integer timestamp.

    Rejects signs (other than a leading minus), leading zeros (except the
    value 0 itself), and any trailing junk.
    """
    if not text:
        return None
    digits = text[1:] if text[0] == "-" else text
    if not digits.isdigit():
        return None
    if digits[0] == "0" and digits != "0":
        return None
    if text[0] == "-" and digits == "0":
        return None
    return int(text)


def verify_hook(request: HookRequest, keystore: Keystore, policy: Policy, *, now: int) -> dict[str, Any]:
    reasons: list[str] = []
    method = request.method.upper()
    if method not in policy.allowed_methods:
        reasons.append("blocked_method")

    active_key = None
    kid = request.kid
    if kid is None:
        reasons.append("missing_kid")
    elif _is_blocked_kid(kid):
        reasons.append("blocked_kid")
    else:
        candidate = keystore.get(kid)
        if candidate is None:
            reasons.append("unknown_kid")
        elif candidate.revoked:
            reasons.append("revoked_kid")
        else:
            active_key = candidate

    timestamp = _parse_timestamp(request.timestamp_text)
    if timestamp is None:
        reasons.append("bad_timestamp")
    else:
        skew = policy.max_skew_seconds
        if timestamp < now - skew:
            reasons.append("stale")
        elif timestamp > now + skew:
            reasons.append("future")

    signature = request.signature_hex
    signature_format_ok = False
    if signature is None:
        reasons.append("missing_signature")
    elif (
        len(signature) != _SIGNATURE_LENGTH
        or any(ch not in _LOWER_HEX_DIGITS for ch in signature)
    ):
        reasons.append("bad_signature")
    else:
        signature_format_ok = True

    if signature_format_ok and active_key is not None:
        expected = hmac.new(
            active_key.secret, request.signing_input, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            reasons.append("bad_signature")

    return {
        "decision": "allow" if not reasons else "deny",
        "reason_codes": reasons,
        "kid": kid,
        "timestamp": timestamp,
        "method": method,
    }
