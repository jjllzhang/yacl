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

#include "yacl/crypto/experimental/threshold_signatures/core/vss/feldman.h"

#include <exception>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/bigint/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::core::vss {

using BigInt = Scalar::BigInt;

Scalar RandomNonZeroScalar(const std::shared_ptr<const GroupContext>& group) {
  while (true) {
    const Scalar candidate = Scalar::FromBigEndianModQ(Csprng::RandomBytes(32), group);
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("polynomial coefficients must not be empty");
  }

  const auto& group = coefficients.front().group();
  const BigInt& q = group->order();
  const BigInt x = BigInt(party_id).Mod(q);

  BigInt acc(0);
  BigInt power(1);
  for (const Scalar& coefficient : coefficients) {
    acc = bigint::NormalizeMod(acc + coefficient.mp_value() * power, q);
    power = bigint::NormalizeMod(power * x, q);
  }
  return Scalar(acc, group);
}

std::vector<ECPoint> BuildCommitments(
    const std::vector<Scalar>& coefficients) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("polynomial coefficients must not be empty");
  }

  std::vector<ECPoint> commitments;
  commitments.reserve(coefficients.size());
  for (const Scalar& coefficient : coefficients) {
    commitments.push_back(ECPoint::GeneratorMultiply(coefficient));
  }
  return commitments;
}

bool VerifyShareForReceiver(PartyIndex receiver_id, size_t threshold,
                            const std::vector<ECPoint>& commitments,
                            const Scalar& share) {
  if (share.value() == 0) {
    return false;
  }
  if (commitments.size() != threshold + 1 || commitments.empty()) {
    return false;
  }

  try {
    ECPoint rhs = commitments.front();
    const auto& group = share.group();
    const BigInt& q = group->order();
    const BigInt receiver = BigInt(receiver_id);
    BigInt power = receiver.Mod(q);
    for (size_t k = 1; k < commitments.size(); ++k) {
      rhs = rhs.Add(commitments[k].Mul(Scalar(power, group)));
      power = bigint::NormalizeMod(power * receiver, q);
    }
    const ECPoint lhs = ECPoint::GeneratorMultiply(share);
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa::core::vss
