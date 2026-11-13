# Verify rules

`verify` is fail-closed. A webhook is only allowed when the method, kid, timestamp window, and HMAC all succeed. An unreadable keystore, policy, or request file is a process error (exit 2). A request JSON that can be read, even when headers are missing, must produce a deny report and exit 1.

Reuse `load_request` / `parse_request_obj`, `load_keystore`, `load_policy`, and the `signing_input` already computed by the parser. Do not add a JWT or webhook SDK. Compare MAC values with `hmac.compare_digest`.

`--now` is the Unix timestamp used for the skew window. When it is omitted, the current time is used. Public fixtures are signed around `1763000000`.

## Method, kid, and timestamp

- Uppercase the method and require it to be in `allowed_methods`. The public policy allows only `POST`. Anything else is `blocked_method`.
- If `require_kid` is true (the public default), a missing `X-Hook-Kid` is `missing_kid`. A kid that is not in the keystore is `unknown_kid`. A kid present in the keystore with `revoked` true is `revoked_kid`.
- A kid containing `/`, `\`, `..`, a NUL byte, or `://` is `blocked_kid`. Do not treat the kid as a path or URL.
- `X-Hook-Timestamp` must be a decimal integer (no `+`, no leading zeros except the value `0`, no trailing junk). Otherwise `bad_timestamp`.
- Let `skew = policy.max_skew_seconds` (300 in the public policy). If `timestamp < now - skew` the request is `stale`. If `timestamp > now + skew` it is `future`.

## Signature

- The signing input is already on the parsed request: `METHOD \n path \n timestamp-text \n hex(sha256(body))`, where `METHOD` is uppercased and the timestamp text is the header value as received. Do not re-encode the JSON body a second way; use the parser's `body` and `signing_input`.
- `X-Hook-Signature` must be a lowercase hex SHA-256 HMAC (64 hex characters). Missing header is `missing_signature`. Any other length, uppercase hex, a `sha256=` prefix, or non-hex is `bad_signature`.
- Compute `HMAC-SHA256(secret, signing_input)` with the keystore secret for that kid, and compare using `hmac.compare_digest` against the decoded signature bytes (or against lowercase hex in a length-safe way). A mismatch is `bad_signature`.
- Do not verify with a revoked key even if the MAC would otherwise match.
- `fixtures/requests/tampered-body.json` keeps the signature from the original body, so it must be `bad_signature`.

## Public fixtures

Against `fixtures/keystore.json`, `fixtures/policy.json`, and `--now 1763000000`:

- `fixtures/requests/ok.json` → allow
- `fixtures/requests/stale.json` → deny / `stale`
- `fixtures/requests/bad-signature.json` → deny / `bad_signature`
- `fixtures/requests/revoked-kid.json` → deny / `revoked_kid`
- `fixtures/requests/missing-kid.json` → deny / `missing_kid`
- `fixtures/requests/wrong-method.json` → deny / `blocked_method`
- `fixtures/requests/tampered-body.json` → deny / `bad_signature`

## Exit status

- `allow` → exit 0
- `deny` → exit 1
- Keystore, policy, or request-file load errors → exit 2, and do not write a report that claims `allow`.
