# Reviewed reference run

`reference-run.json` is a committed benchmark over the demonstration catalogue,
produced by:

```bash
CCDEMO_SOURCE_REVISION=reference CCDEMO_SOURCE_TREE_STATE=clean-checkout \
  uv run ccdemo benchmark --iterations 100 --out benchmarks/reference
```

`inputs.sha256` pins the committed pass/fail ground truth. CI verifies it with
`sha256sum --check benchmarks/reference/inputs.sha256`.

## What the run establishes

- **Correctness.** All seven demos pass: each primitive matches a plaintext
  reference (encrypted SUM/AVG, secure total) or a security control correctly
  rejects a bad input (tampered measurement, replayed nonce, foreign sealing
  key), matching `fixtures/ground-truth.json` (`ground_truth_verified == true`).
- **Determinism.** Every pass produces a byte-identical result set — the same
  ciphertext prefixes, signatures, and sealed blobs — collapsed to one
  `report_hash` (`deterministic == true`). This relies on seeded keys and shares
  and RFC 8032 Ed25519 signatures.

Latency is machine dependent and not asserted in CI; only correctness,
determinism, and input integrity are. The keys are demonstration keys — see
`SECURITY.md`.
