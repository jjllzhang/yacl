# threshold_signatures

C++20 prototype implementation of the signing protocols from:

- `threshold-ecdsa.pdf`: threshold ECDSA.
- `threshold-SM2.pdf`: threshold SM2.

The directory was named `threshold_signatures` because the implementation now
contains two scheme-specific protocol flows, ECDSA and SM2, over a small shared
threshold-signature toolkit.

This is a research prototype for protocol review and testing. It is not a
production wallet, network service, or hardened signing system.

## Scope

Implemented pieces:

- Shared protocol primitives in `core/`: curve/scalar wrappers, Feldman VSS,
  commitments, transcripts, Schnorr proofs, Paillier, auxiliary RSA setup and
  MtA/MtAwc proof checks.
- Common protocol types in `common/`.
- Threshold ECDSA in `ecdsa/`: key generation, signing, relation proofs, and
  final ECDSA signature verification.
- Threshold SM2 in `sm2/`: ZID binding, key generation, offline presigning,
  online signing, identifiable-abort evidence, and final SM2 signature
  verification.
- Minimal flow tests in `tests/` for ECDSA and SM2 happy paths plus tamper
  smoke checks.

Out of scope:

- Real transport, storage, session orchestration, or wallet integration.
- Production hardening claims.
- Compatibility wrappers for older experimental APIs.

## Layout

```text
common/  # shared ids, aliases, and error helpers
core/    # reusable threshold-signature primitives
ecdsa/   # threshold ECDSA keygen/sign/verify protocol code
sm2/     # threshold SM2 keygen/offline/online/verify protocol code
tests/   # compact ECDSA and SM2 flow tests
```

## Bazel Targets

The supported in-repo build path is Bazel. The module exposes three libraries
and two executable flow-test targets:

```bash
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim build //yacl/crypto/experimental/threshold_signatures:all
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim build //yacl/crypto/experimental/threshold_signatures:tsig_core
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim build //yacl/crypto/experimental/threshold_signatures:tsig_ecdsa
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim build //yacl/crypto/experimental/threshold_signatures:tsig_sm2
```

Run the flow tests with `bazelisk run`; these are `yacl_cc_binary` targets, not
`cc_test` targets:

```bash
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim run //yacl/crypto/experimental/threshold_signatures:sign_flow_tests
bazelisk --batch --output_user_root=/tmp/bazel_zjl_phase_slim run //yacl/crypto/experimental/threshold_signatures:sm2_sign_flow_tests
```

## Protocol Shape

Threshold ECDSA:

1. Dealerless key generation uses Feldman VSS commitments, Paillier public
   parameters, auxiliary RSA parameters, square-free proofs, and Schnorr proofs
   for the final local public shares.
2. Signing uses a threshold-plus-one signer set, Lagrange-remapped signing
   shares, pairwise MtA/MtAwc, commitment openings, relation proofs, and final
   ECDSA signature verification.

Threshold SM2:

1. Key generation derives SM2 public-key material from distributed `z_i` shares,
   pairwise MtA sigma shares, group relation proofs, and Paillier proof
   artifacts.
2. Offline presigning computes nonce/product state with MtAwc and validates the
   aggregate product relation.
3. Online signing binds the SM2 ZID digest, computes partial signatures, and
   returns identifiable abort evidence for invalid partials when possible.

## Notes

- The code intentionally follows the paper round structure rather than exposing
  a generic signing framework.
- `core/` is shared only where both protocols need the same primitive; ECDSA
  and SM2 keep separate scheme-level message and round semantics.
- The implementation uses YACL/OpenSSL curve support and YACL `MPInt`; it does
  not introduce GMP/GMPXX or another third-party big-integer dependency.
