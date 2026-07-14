# Limitations

This is a portfolio-grade prototype. It demonstrates how confidential-computing
primitives work and compose, with correct implementations, over synthetic data.
It is **not** production cryptography and must never protect real data.

- **Demo keys, not secure keys.** Paillier keys come from a seeded,
  non-cryptographic PRNG for reproducibility and are deliberately small for speed.
  They provide no confidentiality against a real adversary.
- **Additive homomorphism only.** Paillier supports encrypted `SUM`, `COUNT`, and
  `AVG`. Multiplying two ciphertexts, or comparing the encrypted column, needs
  fully-homomorphic encryption (BFV/CKKS), which is out of scope. "SQL on
  encrypted data" here means additive aggregates with plaintext filters.
- **Simulated attestation.** Ed25519 quote signing and verification are real, but
  there is no SGX/TDX/SEV chip. The attestation key is a software key, not a
  hardware-fused one, so a `verified` quote proves the protocol logic, not that
  code ran on genuine confidential-computing silicon.
- **Deterministic sealing nonces.** Sealing uses fixed nonces so demos reproduce
  byte-for-byte. Real AES-GCM sealing must use random nonces; reusing a nonce
  under one key breaks GCM completely.
- **Honest-but-curious MPC.** Secret sharing assumes parties follow the protocol
  and a trusted transport. There is no authentication, no malicious security, and
  no defense against collusion of all-but-one parties.
- **No side-channel resistance.** The implementations are for clarity, not
  constant-time execution; timing and other side channels are not addressed.
- **Local API.** Unauthenticated and for loopback only.

The value here is pedagogical: correct, readable, reproducible implementations of
the building blocks of confidential computing, with every shortcut stated openly.
See the [architecture](ARCHITECTURE.md) and [methodology](METHODOLOGY.md).
