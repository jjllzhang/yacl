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

#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs_internal.h"
#include "yacl/crypto/experimental/threshold_signatures/core/bigint/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::core::paillier {
namespace spi = paillier_internal;

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (modulus <= 2 || value <= 0 || value >= modulus) {
    return false;
  }
  return BigInt::Gcd(value, modulus) == 1;
}

bool ValidateAuxRsaParams(const AuxRsaParams& params) {
  if (params.n_tilde <= 2 || params.h1 == params.h2) {
    return false;
  }
  return IsZnStarElement(params.h1, params.n_tilde) &&
         IsZnStarElement(params.h2, params.n_tilde);
}

bool IsLikelySquareFreeModulus(const BigInt& modulus_n) {
  if (modulus_n <= 2 || modulus_n.IsEven() || spi::IsPerfectSquare(modulus_n)) {
    return false;
  }

  static constexpr std::array<unsigned long, 168> kSmallPrimes = {
      2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
      47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
      109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
      191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
      269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
      353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
      439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
      523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
      617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
      709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
      811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
      907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
  };

  for (unsigned long prime : kSmallPrimes) {
    const unsigned long prime_square = prime * prime;
    if (modulus_n.Mod(BigInt(prime_square)) == 0) {
      return false;
    }
  }

  return true;
}

SquareFreeProof BuildSquareFreeProofGmr98(
    const BigInt& modulus_n, const BigInt& lambda_n,
    const StrictProofVerifierContext& context) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires modulus N > 3");
  }
  if (lambda_n <= 1) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires lambda(N) > 1");
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    TECDSA_THROW_ARGUMENT(
        "square-free GMR98 proof requires likely square-free modulus");
  }

  const auto d_opt =
      spi::InvertMod(spi::NormalizeMod(modulus_n, lambda_n), lambda_n);
  if (!d_opt.has_value()) {
    TECDSA_THROW_ARGUMENT(
        "square-free GMR98 proof requires gcd(N, lambda(N)) = 1");
  }
  const BigInt d = *d_opt;
  const Bytes nonce = Csprng::RandomBytes(spi::kStrictNonceLen);

  spi::SquareFreeGmr98Payload payload;
  payload.nonce = nonce;
  payload.rounds = static_cast<uint32_t>(spi::kSquareFreeGmr98Rounds);
  payload.roots.reserve(payload.rounds);

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt challenge =
        spi::DeriveSquareFreeGmr98Challenge(modulus_n, context, nonce, round);
    const BigInt root = spi::PowMod(challenge, d, modulus_n);
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      TECDSA_THROW("square-free GMR98 proof generated invalid root");
    }
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      TECDSA_THROW(
          "square-free GMR98 proof generated inconsistent root equation");
    }
    payload.roots.push_back(root);
  }

  return SquareFreeProof{.blob = spi::EncodeSquareFreeGmr98Payload(payload)};
}

bool VerifySquareFreeProofGmr98(const BigInt& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context) {
  if (!IsLikelySquareFreeModulus(modulus_n) || proof.blob.empty()) {
    return false;
  }

  spi::SquareFreeGmr98Payload payload;
  try {
    payload = spi::DecodeSquareFreeGmr98Payload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != spi::kStrictNonceLen ||
      payload.rounds != spi::kSquareFreeGmr98Rounds ||
      payload.roots.size() != payload.rounds) {
    return false;
  }

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt& root = payload.roots[round];
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      return false;
    }
    const BigInt challenge =
        spi::DeriveSquareFreeGmr98Challenge(modulus_n, context, payload.nonce,
                                            round);
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      return false;
    }
  }
  return true;
}

}  // namespace tecdsa::core::paillier
