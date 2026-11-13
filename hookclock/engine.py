"""Webhook signature verification. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from hookclock.keys import Keystore
from hookclock.parse import HookRequest
from hookclock.policy import Policy


def verify_hook(request: HookRequest, keystore: Keystore, policy: Policy, *, now: int) -> dict[str, Any]:
    raise NotImplementedError("verify_hook is not implemented in this snapshot")
