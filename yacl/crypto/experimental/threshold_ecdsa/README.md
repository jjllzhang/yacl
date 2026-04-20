# threshold_ecdsa

Research artifact for a C++20 prototype implementation of threshold ECDSA and
threshold SM2 protocol building blocks.

## Paper Reference

- Rosario Gennaro, Steven Goldfeder.
  *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (CCS 2019).

This repository now exposes a round-driven prototype layer and emphasizes:

- protocol-correct message flow,
- strict input validation and abort behavior,
- reproducible tests.

It is not a production-ready wallet or signing service.

## Scope of This Artifact

### Implemented Components

- Elliptic-curve scalar and point operations (`yacl::crypto::EcGroup` with the
  OpenSSL backend).
- Native Paillier encryption implementation (MPInt-based, no GMP or GMPXX
  dependency).
- Hashing, commitments, transcript/challenge utilities, and wire encoding.
- Round-driven threshold key generation
  (`tecdsa::proto::KeygenParty`, 3 rounds).
- Round-driven threshold signing (`tecdsa::proto::SignParty`, `Phase1` through
  `Phase5E`).
- SM2-specific `ZID` preprocessing, threshold keygen, offline presign, online
  signing, and math verification.
- Fixed prototype proof validation for square-free and auxiliary-parameter
  artifacts.

### Current Engineering Goal

The repository targets protocol engineering reproducibility, not hardened
deployment.

## Repository Layout

```text
core/          # stage-1 suite/algebra groundwork for shared threshold-signature code
common/        # bytes/error helpers
crypto/        # compatibility wrappers plus shared Paillier/hash/encoding/transcript/proof helpers
ecdsa/         # ECDSA-specific keygen/sign/verify orchestration
sm2/           # SM2-specific zid/keygen/offline/online/verify orchestration
protocol/      # legacy proto namespace shims kept for compatibility
tests/
  crypto_primitives_test.cc
  keygen_flow_test.cc
  sign_flow_test.cc
  sign_flow_test_cases.cc
  sign_flow_test_shared.h
  sign_flow_test_support.cc
  sm2/
    keygen_flow_test.cc
    offline_presign_test.cc
    online_sign_test.cc
    sign_flow_test.cc
    tamper_cases_test.cc
    test_support.cc
    test_support.h
```

## Reproducibility

### Requirements

- CMake >= 3.22
- C++20 compiler (`clang++` or `g++`)
- Abseil headers (`absl/debugging/stacktrace.h`, `absl/types/span.h`)
- libtommath headers (`libtommath/tommath.h`)
- OpenSSL `libcrypto`

### Build

The verified in-repo build path is Bazel. The standalone CMake path below only
works when Abseil and libtommath headers are already provisioned for the local
toolchain.

```bash
cmake -S yacl/crypto/experimental/threshold_ecdsa -B /tmp/tecdsa-cmake
cmake --build /tmp/tecdsa-cmake --target tsig_core tsig_ecdsa tsig_sm2 -j
```

Canonical CMake targets:

- `tsig_core`: shared threshold-signature building blocks (`core/` plus shared
  compatibility facades in `crypto/`).
- `tsig_ecdsa`: ECDSA scheme layer plus legacy `protocol/` shims; links
  `tsig_core`.
- `tsig_sm2`: SM2 scheme layer (`sm2/`); links `tsig_core`.
- `tecdsa_core`: compatibility alias to `tsig_ecdsa`.
- `tecdsa_m0`: legacy compatibility alias retained as an alias to
  `tsig_ecdsa`.

### Bazel

Canonical stage-8 naming is `:tsig_core`, `:tsig_ecdsa`, and `:tsig_sm2`, with
`:tecdsa_core` kept as the compatibility name and `:tecdsa_m0` retained as the
legacy alias.

```bash
bazelisk --output_user_root=/tmp/bazel_zjl query //yacl/crypto/experimental/threshold_ecdsa:all
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tsig_core
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tsig_ecdsa
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tsig_sm2
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tecdsa_core
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tecdsa_m0
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:crypto_primitives_tests
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:keygen_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:sign_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:sm2_keygen_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:sm2_sign_flow_tests
```

If your environment resolves `rules_foreign_cc` to `built_make` and fails on
`BootstrapGNUMake`, run with one-off toolchain flags:

```bash
bazelisk --output_user_root=/tmp/bazel_zjl build //yacl/crypto/experimental/threshold_ecdsa:tsig_ecdsa \
  --extra_toolchains=@rules_foreign_cc//toolchains:preinstalled_make_toolchain,@rules_foreign_cc//toolchains:preinstalled_pkgconfig_toolchain
```

### Test Suite

Run all CMake tests:

```bash
ctest --test-dir /tmp/tecdsa-cmake --output-on-failure
```

Run individual CMake executables:

```bash
/tmp/tecdsa-cmake/crypto_primitives_tests
/tmp/tecdsa-cmake/keygen_flow_tests
/tmp/tecdsa-cmake/sign_flow_tests
/tmp/tecdsa-cmake/sm2_keygen_flow_tests
/tmp/tecdsa-cmake/sm2_sign_flow_tests
```

Run Bazel test binaries. These are `yacl_cc_binary` targets, not `cc_test` rules:

```bash
bazelisk --output_user_root=/tmp/bazel_zjl run //yacl/crypto/experimental/threshold_ecdsa:crypto_primitives_tests
bazelisk --output_user_root=/tmp/bazel_zjl run //yacl/crypto/experimental/threshold_ecdsa:keygen_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl run //yacl/crypto/experimental/threshold_ecdsa:sign_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl run //yacl/crypto/experimental/threshold_ecdsa:sm2_keygen_flow_tests
bazelisk --output_user_root=/tmp/bazel_zjl run //yacl/crypto/experimental/threshold_ecdsa:sm2_sign_flow_tests
```

Migration sanity check (should be zero hits in code files):

```bash
rg -n "#include <gmpxx.h>|\bmpz_class\b|\bmpz_" yacl/crypto/experimental/threshold_ecdsa --glob '!**/0*.txt' --glob '!**/*.md'
```

### Test Coverage Summary

- `crypto_primitives_tests`: basic crypto primitives and wire format checks.
- `keygen_flow_tests`: end-to-end keygen, proof validation, and adversarial
  tampering.
- `sign_flow_tests`: end-to-end signing, proof checks, and adversarial failure
  paths.
- `sm2_keygen_flow_tests`: end-to-end SM2 keygen and `ZID` consistency.
- `sm2_sign_flow_tests`: SM2 offline presign, online sign, and tamper checks.

## Error Handling Style

- Runtime argument, logic, and runtime failures in module code are normalized
  through `common/errors.h` (`TECDSA_THROW*`) and map to YACL exception macros.

## Protocol Flow (Primary API)

### Keygen (`tecdsa::proto::KeygenParty`)

1. Round1: broadcast commitment and Paillier public parameters.
2. Round2: broadcast openings and send secret shares point-to-point.
3. Round3: broadcast `X_i = g^{x_i}` with Schnorr proof.
4. Finalization: aggregate `x_i`, `y`, all `X_i`, and Paillier/public proof
   artifacts.

### Sign (`tecdsa::proto::SignParty`)

1. Phase1: commit to `Gamma_i`.
2. Phase2: MtA and MtAwc interaction with Appendix-A style proof checks.
3. Phase3: broadcast `delta_i` and aggregate inversion path.
4. Phase4: open `Gamma_i`, verify proof, derive `R` and `r`.
5. Phase5A to Phase5E: commit/open rounds with relation proofs, then finalize
   `(r, s)`.

## Limitations

- No real network or transport layer is implemented.
- No claim of production security hardening.
- Intended for protocol implementation study and testing.
