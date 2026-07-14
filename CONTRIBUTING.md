# Contributing

Every change to a primitive needs:

1. a correctness test against a plaintext reference (encrypted SUM equals the
   real SUM, secure total equals the true total, a genuine quote verifies);
2. a negative test for each security control (tampered measurement, replayed
   nonce, wrong sealing measurement, out-of-range plaintext);
3. a determinism check: the benchmark must reproduce a single stable hash;
4. a ground-truth review when a demo's pass/fail changes, kept in sync with
   `fixtures/ground-truth.json` (a test enforces this).

Keep the demos deterministic (seeded keys, seeded shares, fixed nonces) so the
catalogue stays reproducible. If you add a primitive, state its trust model and
its limits honestly in `SECURITY.md`; do not imply production security the code
does not provide.

Run before submitting:

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
sha256sum --check benchmarks/reference/inputs.sha256
docker compose config --quiet
docker build -t confidential-compute-demo:test .
```

Do not commit real keys, real data, or generated co-author trailers.
