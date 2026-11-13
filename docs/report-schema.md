# Report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "kid": "hook-main",
  "timestamp": 1763000000,
  "method": "POST"
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is empty on `allow`. On `deny` it contains one or more of `blocked_method`, `missing_kid`, `unknown_kid`, `revoked_kid`, `blocked_kid`, `bad_timestamp`, `stale`, `future`, `missing_signature`, `bad_signature`.
- `kid`, `timestamp`, and `method` are copied from the request when present, otherwise `null`.
