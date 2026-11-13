# hookclock

A small fail-closed verifier for payment-channel webhook callbacks. Request loading, the local keystore, and the canonical signing string already work. `inspect` prints the kid, timestamp, and signing input, and `verify` enforces the method, kid, timestamp window, and HMAC before writing an allow/deny report.

The callback is authenticated with `X-Hook-Kid`, `X-Hook-Timestamp`, and an HMAC-SHA256 over the method, path, timestamp, and the SHA-256 of the body. The verifier must reject a stale timestamp, a revoked kid, and a body that no longer matches the signature.

## Requirements

- Python 3.11+
- Standard library only (`hmac`, `hashlib`)
- No containers, no network

## Already working

```bash
python -m hookclock inspect --request fixtures/requests/ok.json
```

The public fixtures were signed around Unix time `1763000000`.

## CLI

```bash
python -m hookclock verify \
  --request fixtures/requests/ok.json \
  --keystore fixtures/keystore.json \
  --policy fixtures/policy.json \
  --report /tmp/hookclock-report.json \
  --now 1763000000
```

Parameter names are fixed in `hookclock/__main__.py`. `verify` exits 0 on allow,
1 on deny, and 2 when the request, keystore, or policy cannot be loaded. See
`docs/verify-rules.md` for the full rule set and `docs/report-schema.md` for
the report fields.
