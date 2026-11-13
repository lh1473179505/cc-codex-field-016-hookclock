"""CLI. inspect already works; verify is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from hookclock.keys import KeystoreError, load_keystore
from hookclock.parse import RequestError, load_request, parse_request_obj, request_to_dict
from hookclock.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hookclock")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="print the unverified signing input of a webhook request")
    ins.add_argument("--request", required=True, help="path to a JSON request, or @path")
    ver = sub.add_parser("verify", help="fail-closed webhook signature verification")
    ver.add_argument("--request", required=True, help="path to a JSON request, or @path")
    ver.add_argument("--keystore", required=True)
    ver.add_argument("--policy", required=True)
    ver.add_argument("--report", required=True)
    ver.add_argument("--now", type=int, default=None, help="unix timestamp used for the skew window")
    return p


def _read_request(value: str):
    path = value[1:] if value.startswith("@") else value
    return load_request(path)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        req = _read_request(args.request)
    except (OSError, RequestError) as exc:
        print(f"failed to read request: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "inspect":
        print(json.dumps(request_to_dict(req), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "verify":
        try:
            keystore = load_keystore(args.keystore)
            policy = load_policy(args.policy)
        except (KeystoreError, PolicyError, OSError) as exc:
            print(f"failed to load keystore or policy: {exc}", file=sys.stderr)
            return 2
        now = args.now if args.now is not None else int(time.time())
        from hookclock.engine import verify_hook
        try:
            report = verify_hook(req, keystore, policy, now=now)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"verify failed unexpectedly: {exc}", file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
