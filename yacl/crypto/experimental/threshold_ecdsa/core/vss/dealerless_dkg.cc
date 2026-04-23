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

#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/bigint/bigint_utils.h"

namespace tecdsa::core::vss {
namespace {

using BigInt = Scalar::BigInt;

BigInt NormalizeModQ(const BigInt& value,
                     const std::shared_ptr<const GroupContext>& group) {
  return bigint::NormalizeMod(value, group->order());
}

}  // namespace

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants,
    const std::shared_ptr<const GroupContext>& group) {
  std::unordered_map<PartyIndex, Scalar> out;
  out.reserve(participants.size());

  for (PartyIndex i : participants) {
    BigInt numerator(1);
    BigInt denominator(1);

    for (PartyIndex j : participants) {
      if (j == i) {
        continue;
      }

      const BigInt neg_j = NormalizeModQ(BigInt(0) - BigInt(j), group);
      numerator = NormalizeModQ(numerator * neg_j, group);

      const BigInt diff = NormalizeModQ(BigInt(i) - BigInt(j), group);
      if (diff == 0) {
        TECDSA_THROW_ARGUMENT("duplicate participant id in lagrange set");
      }
      denominator = NormalizeModQ(denominator * diff, group);
    }

    Scalar lambda =
        Scalar(numerator, group) * Scalar(denominator, group).InverseModQ();
    out.emplace(i, lambda);
  }

  return out;
}

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  if (points.empty()) {
    TECDSA_THROW_ARGUMENT("cannot sum an empty point vector");
  }
  ECPoint sum = points.front();
  for (size_t i = 1; i < points.size(); ++i) {
    sum = sum.Add(points[i]);
  }
  return sum;
}

}  // namespace tecdsa::core::vss
