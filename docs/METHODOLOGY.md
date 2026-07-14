# Methodology

How the measured evidence is produced and what each demo actually checks.

## What "passed" means

Every demo compares a confidential computation against a plaintext reference, or
asserts that a security control rejects a bad input:

- **homomorphic-encrypted-sum / -filtered-average** — the decrypted aggregate
  equals the plaintext aggregate, and ciphertexts differ from plaintext.
- **mpc-secure-average** — the secure total equals the true total, and no share a
  party received equals any plaintext value.
- **attestation-accept** — a genuine quote verifies.
- **attestation-reject-tampered / -reject-replay** — a validly signed quote over
  the wrong measurement, and a quote with a stale nonce, are both refused.
- **sealed-computation** — the enclave result is correct, the host cannot unseal
  the inputs, and the result's quote verifies.

A demo passes only if the primitive did the mathematically correct thing or the
control made the correct decision.

## Ground truth and determinism

Every demo is expected to pass; `fixtures/ground-truth.json` records that, and a
test asserts the actual outcomes match. `ccdemo benchmark` runs the catalogue
`iterations` times and hashes the full result set — including ciphertext
prefixes, signatures, and sealed-blob bytes — each pass. `deterministic == true`
means all passes produced one identical hash, which holds because keys, shares,
and nonces are seeded and Ed25519 is deterministic.

## What the evidence does and does not show

It shows the primitives are **implemented correctly** and compose into working
confidential-computing flows. It does **not** show they are secure for real data:
the keys are demo-sized and seeded, sealing nonces are fixed, and the enclave is
a software model with no hardware root of trust. Those caveats are stated in
`SECURITY.md` and [LIMITATIONS.md](LIMITATIONS.md).

Reproduce locally:

```bash
uv run ccdemo demo all
uv run ccdemo benchmark --iterations 100
```
