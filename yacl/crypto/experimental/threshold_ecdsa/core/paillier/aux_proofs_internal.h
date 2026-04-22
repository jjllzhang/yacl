// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"

namespace tecdsa::core::paillier_internal {

using BigInt = paillier::BigInt;

inline constexpr char kSquareFreeProofNameGmr98[] = "SquareFreeGMR98";
inline constexpr size_t kStrictNonceLen = 32;
inline constexpr size_t kMaxStrictNonceLen = 256;
inline constexpr size_t kMaxStrictFieldLen = 8192;
inline constexpr size_t kSquareFreeGmr98Rounds = 24;
inline constexpr size_t kMaxSquareFreeGmr98Rounds = 128;
inline constexpr size_t kMaxSquareFreeGmr98ChallengeAttempts = 64;
inline constexpr size_t kMaxAuxParamGenerationAttempts = 128;

struct SquareFreeGmr98Payload {
  Bytes nonce;
  uint32_t rounds = 0;
  std::vector<BigInt> roots;
};

struct AuxRsaParamsBigInt {
  BigInt n_tilde;
  BigInt h1;
  BigInt h2;
};

BigInt RandomBelow(const BigInt& upper_exclusive);
BigInt RandomZnStar(const BigInt& modulus_n);
bool IsZnStarResidue(const BigInt& value, const BigInt& modulus);
BigInt NormalizeMod(const BigInt& value, const BigInt& modulus);
BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus);
BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus);
std::optional<BigInt> InvertMod(const BigInt& value, const BigInt& modulus);
bool IsPerfectSquare(const BigInt& value);

AuxRsaParamsBigInt ToBigIntParams(const paillier::AuxRsaParams& params);

BigInt DeriveSquareFreeGmr98Challenge(
    const BigInt& modulus_n, const paillier::StrictProofVerifierContext& context,
    std::span<const uint8_t> nonce, uint32_t round_idx);

Bytes EncodeSquareFreeGmr98Payload(const SquareFreeGmr98Payload& payload);
SquareFreeGmr98Payload DecodeSquareFreeGmr98Payload(
    std::span<const uint8_t> blob);

BigInt PickCoprimeDeterministic(const BigInt& modulus, const BigInt& seed);

}  // namespace tecdsa::core::paillier_internal
