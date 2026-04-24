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

#include <exception>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/common/ids.h"
#include "yacl/crypto/experimental/threshold_signatures/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_signatures/core/bigint/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_signatures/common/types.h"
#include "yacl/crypto/experimental/threshold_signatures/core/random/csprng.h"

namespace tecdsa::sm2::internal {

using BigInt = Scalar::BigInt;

inline const std::shared_ptr<const core::GroupContext>& Sm2Group() {
  static const std::shared_ptr<const core::GroupContext> kGroup =
      core::GroupContext::Create(core::CurveId::kSm2P256V1);
  return kGroup;
}

inline Scalar Sm2Zero() { return Scalar(BigInt(0), Sm2Group()); }

inline Scalar Sm2One() { return Scalar::FromUint64(1, Sm2Group()); }

inline Scalar Sm2Negate(const Scalar& value) { return Sm2Zero() - value; }

inline Scalar RandomSm2Scalar() {
  while (true) {
    try {
      return Scalar::FromCanonicalBytes(Csprng::RandomBytes(32), Sm2Group());
    } catch (const std::exception&) {
      continue;
    }
  }
}

inline Scalar RandomNonZeroSm2Scalar() {
  while (true) {
    const Scalar candidate = RandomSm2Scalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

inline Scalar XCoordinateModN(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != Sm2Group()->compressed_point_size_bytes()) {
    TECDSA_THROW_ARGUMENT("invalid SM2 compressed point length");
  }
  return Scalar::FromBigEndianModQ(
      std::span<const uint8_t>(compressed.data() + 1, compressed.size() - 1),
      Sm2Group());
}

inline ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  return core::vss::SumPointsOrThrow(points);
}

inline Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                                   PartyIndex party_id) {
  return core::vss::EvaluatePolynomialAt(coefficients, party_id);
}

inline std::vector<ECPoint> BuildCommitments(
    const std::vector<Scalar>& coefficients) {
  return core::vss::BuildCommitments(coefficients);
}

inline bool VerifyShareForReceiver(PartyIndex receiver_id, size_t threshold,
                                   const std::vector<ECPoint>& commitments,
                                   const Scalar& share) {
  return core::vss::VerifyShareForReceiver(receiver_id, threshold, commitments,
                                           share);
}

inline std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  return core::vss::ComputeLagrangeAtZero(participants, Sm2Group());
}

inline Bytes SerializeUncompressed(const ECPoint& point) {
  const auto& group = *Sm2Group();
  const auto ec_point = group.ec_group().DeserializePoint(
      point.ToCompressedBytes(), yacl::crypto::PointOctetFormat::X962Compressed);
  const yacl::Buffer encoded = group.ec_group().SerializePoint(
      ec_point, yacl::crypto::PointOctetFormat::X962Uncompressed);
  return Bytes(encoded.data<uint8_t>(), encoded.data<uint8_t>() + encoded.size());
}

}  // namespace tecdsa::sm2::internal
