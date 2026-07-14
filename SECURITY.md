# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Include
the affected commit, the demo, the expected outcome, and the observed outcome.

**These are demonstration primitives, not production cryptography.** In
particular:

- Paillier keys are generated from a *seeded, non-cryptographic* PRNG so runs are
  reproducible, and default key sizes are small for speed. They protect nothing;
  never encrypt real data with them.
- Sealing uses deterministic nonces for reproducibility. Real AES-GCM sealing must
  use random nonces; nonce reuse under a fixed key is catastrophic.
- Remote attestation is a software simulation: the Ed25519 quote signing and
  verification are real, but there is no hardware root of trust issuing the
  attestation key. A `verified` quote here proves the protocol logic, not that
  code ran on genuine SGX/TDX silicon.
- The MPC assumes honest-but-curious parties over a trusted transport; there is no
  authentication or malicious-security machinery.

The code runs entirely in-process, opens no network connections while computing,
and executes no untrusted payloads. The homomorphic layer supports additive
aggregates only; arbitrary computation on ciphertext needs fully-homomorphic
encryption, which is out of scope.

Do not deploy any of this to protect real data. It exists to demonstrate how the
primitives work and fit together.
