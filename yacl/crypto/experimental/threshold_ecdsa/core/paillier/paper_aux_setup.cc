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

#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_setup.h"

#include <cstddef>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/math/common.h"

namespace tecdsa::core::paillier {
namespace {

constexpr size_t kMaxPaperAuxSetupAttempts = 128;

BigInt RandomNonZeroBelow(const BigInt& upper_exclusive) {
  if (upper_exclusive <= 1) {
    TECDSA_THROW_ARGUMENT(
        "paper auxiliary setup requires an upper bound greater than one");
  }
  BigInt candidate;
  do {
    candidate = BigInt::RandomLtN(upper_exclusive);
  } while (candidate == 0);
  return candidate;
}

BigInt SampleZnStarElement(const BigInt& modulus) {
  if (modulus <= 2) {
    TECDSA_THROW_ARGUMENT(
        "paper auxiliary setup requires modulus greater than two");
  }
  BigInt candidate;
  do {
    candidate = BigInt::RandomLtN(modulus);
  } while (!IsZnStarElement(candidate, modulus));
  return candidate;
}

}  // namespace

bool ValidatePaperAuxSetup(const AuxRsaParams& params,
                           const PaperAuxSetupWitness& witness) {
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }
  if (witness.p_tilde <= 1 || witness.q_tilde <= 1 || witness.P_tilde <= 3 ||
      witness.Q_tilde <= 3 || witness.tau <= 0 || witness.lambda <= 0) {
    return false;
  }
  if (!witness.p_tilde.IsPrime() || !witness.q_tilde.IsPrime() ||
      !witness.P_tilde.IsPrime() || !witness.Q_tilde.IsPrime()) {
    return false;
  }

  if (witness.P_tilde != (witness.p_tilde * 2) + 1 ||
      witness.Q_tilde != (witness.q_tilde * 2) + 1) {
    return false;
  }
  if ((witness.P_tilde % 4) != 3 || (witness.Q_tilde % 4) != 3) {
    return false;
  }

  const BigInt subgroup_order = witness.p_tilde * witness.q_tilde;
  if (subgroup_order <= 1 || witness.lambda >= subgroup_order) {
    return false;
  }
  if (params.n_tilde != witness.P_tilde * witness.Q_tilde) {
    return false;
  }
  if (!IsZnStarElement(witness.tau, params.n_tilde)) {
    return false;
  }

  const BigInt expected_h2 = witness.tau.PowMod(BigInt(2), params.n_tilde);
  const BigInt expected_h1 =
      expected_h2.PowMod(witness.lambda, params.n_tilde);
  if (expected_h2 != params.h2 || expected_h1 != params.h1) {
    return false;
  }
  return params.h1 > 1 && params.h2 > 1 && params.h1 != params.h2;
}

PaperAuxSetupBundle GeneratePaperAuxSetup(uint32_t modulus_bits) {
  if (modulus_bits < 164) {
    TECDSA_THROW_ARGUMENT("paper auxiliary RSA modulus bits must be >= 164");
  }

  const size_t p_bits = static_cast<size_t>(modulus_bits) / 2;
  const size_t q_bits = static_cast<size_t>(modulus_bits) - p_bits;
  if (p_bits <= 81 || q_bits <= 81) {
    TECDSA_THROW_ARGUMENT(
        "paper auxiliary RSA modulus halves must each be greater than 81 bits");
  }

  for (size_t attempt = 0; attempt < kMaxPaperAuxSetupAttempts; ++attempt) {
    BigInt P_tilde;
    BigInt Q_tilde;
    BigInt::RandPrimeOver(p_bits, &P_tilde, yacl::math::PrimeType::FastSafe);
    BigInt::RandPrimeOver(q_bits, &Q_tilde, yacl::math::PrimeType::FastSafe);
    if (P_tilde == Q_tilde) {
      continue;
    }

    const BigInt p_tilde = (P_tilde - 1) / 2;
    const BigInt q_tilde = (Q_tilde - 1) / 2;
    const BigInt n_tilde = P_tilde * Q_tilde;
    const BigInt subgroup_order = p_tilde * q_tilde;

    const BigInt tau = SampleZnStarElement(n_tilde);
    const BigInt h2 = tau.PowMod(BigInt(2), n_tilde);
    if (!IsZnStarElement(h2, n_tilde) || h2 <= 1) {
      continue;
    }

    const BigInt lambda = RandomNonZeroBelow(subgroup_order);
    const BigInt h1 = h2.PowMod(lambda, n_tilde);

    PaperAuxSetupBundle bundle{
        .params =
            AuxRsaParams{
                .n_tilde = n_tilde,
                .h1 = h1,
                .h2 = h2,
            },
        .witness =
            PaperAuxSetupWitness{
                .p_tilde = p_tilde,
                .q_tilde = q_tilde,
                .P_tilde = P_tilde,
                .Q_tilde = Q_tilde,
                .tau = tau,
                .lambda = lambda,
            },
    };
    if (ValidatePaperAuxSetup(bundle.params, bundle.witness)) {
      return bundle;
    }
  }

  TECDSA_THROW("failed to generate paper auxiliary setup");
}

}  // namespace tecdsa::core::paillier
