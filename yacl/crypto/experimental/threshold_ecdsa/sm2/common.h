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
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/group_context.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/transcript/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

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
  if (points.empty()) {
    TECDSA_THROW_ARGUMENT("cannot sum an empty SM2 point vector");
  }
  ECPoint sum = points.front();
  for (size_t i = 1; i < points.size(); ++i) {
    sum = sum.Add(points[i]);
  }
  return sum;
}

inline Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                                   PartyIndex party_id) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("SM2 polynomial coefficients must not be empty");
  }

  BigInt acc(0);
  BigInt power(1);
  const BigInt q = Sm2Group()->order();
  const BigInt x = BigInt(party_id).Mod(q);
  for (const Scalar& coefficient : coefficients) {
    acc = bigint::NormalizeMod(acc + coefficient.value() * power, q);
    power = bigint::NormalizeMod(power * x, q);
  }
  return Scalar(acc, Sm2Group());
}

inline std::vector<ECPoint> BuildCommitments(
    const std::vector<Scalar>& coefficients) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("SM2 polynomial coefficients must not be empty");
  }

  std::vector<ECPoint> commitments;
  commitments.reserve(coefficients.size());
  for (const Scalar& coefficient : coefficients) {
    commitments.push_back(ECPoint::GeneratorMultiply(coefficient));
  }
  return commitments;
}

inline bool VerifyShareForReceiver(PartyIndex receiver_id, size_t threshold,
                                   const std::vector<ECPoint>& commitments,
                                   const Scalar& share) {
  if (share.value() == 0) {
    return false;
  }
  if (commitments.empty() || commitments.size() != threshold + 1) {
    return false;
  }

  try {
    const BigInt q = Sm2Group()->order();
    const BigInt receiver = BigInt(receiver_id);
    BigInt power = receiver.Mod(q);
    ECPoint rhs = commitments.front();
    for (size_t idx = 1; idx < commitments.size(); ++idx) {
      rhs = rhs.Add(commitments[idx].Mul(Scalar(power, Sm2Group())));
      power = bigint::NormalizeMod(power * receiver, q);
    }
    return ECPoint::GeneratorMultiply(share) == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

inline std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  std::unordered_map<PartyIndex, Scalar> out;
  out.reserve(participants.size());
  const BigInt q = Sm2Group()->order();

  for (PartyIndex i : participants) {
    BigInt numerator(1);
    BigInt denominator(1);
    for (PartyIndex j : participants) {
      if (j == i) {
        continue;
      }
      numerator = bigint::NormalizeMod(numerator * (BigInt(0) - BigInt(j)), q);
      const BigInt diff = bigint::NormalizeMod(BigInt(i) - BigInt(j), q);
      if (diff == 0) {
        TECDSA_THROW_ARGUMENT("duplicate participant id in SM2 lagrange set");
      }
      denominator = bigint::NormalizeMod(denominator * diff, q);
    }
    out.emplace(i, Scalar(numerator, Sm2Group()) *
                       Scalar(denominator, Sm2Group()).InverseModQ());
  }
  return out;
}

inline Bytes SerializeUncompressed(const ECPoint& point) {
  const auto& group = *Sm2Group();
  const auto ec_point = group.ec_group().DeserializePoint(
      point.ToCompressedBytes(), yacl::crypto::PointOctetFormat::X962Compressed);
  const yacl::Buffer encoded = group.ec_group().SerializePoint(
      ec_point, yacl::crypto::PointOctetFormat::X962Uncompressed);
  return Bytes(encoded.data<uint8_t>(), encoded.data<uint8_t>() + encoded.size());
}

inline Scalar BuildSchnorrChallenge(const Bytes& session_id,
                                    PartyIndex prover_id,
                                    const ECPoint& statement,
                                    const ECPoint& witness_point) {
  core::transcript::Transcript transcript(HashId::kSm3);
  const Bytes statement_bytes = core::encoding::EncodePoint(statement);
  const Bytes a_bytes = core::encoding::EncodePoint(witness_point);
  transcript.append_proof_id("SM2/Schnorr/v1");
  transcript.append_session_id(session_id);
  transcript.append_u32_be("party_id", prover_id);
  transcript.append_fields({
      core::transcript::TranscriptFieldRef{.label = "X", .data = statement_bytes},
      core::transcript::TranscriptFieldRef{.label = "A", .data = a_bytes},
  });
  return Scalar::FromBigEndianModQ(tecdsa::Hash(HashId::kSm3, transcript.bytes()),
                                   Sm2Group());
}

inline proto::SchnorrProof BuildSchnorrProof(const Bytes& session_id,
                                             PartyIndex prover_id,
                                             const ECPoint& statement,
                                             const Scalar& witness) {
  while (true) {
    const Scalar r = RandomNonZeroSm2Scalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = BuildSchnorrChallenge(session_id, prover_id, statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() != 0) {
      return proto::SchnorrProof{.a = a, .z = z};
    }
  }
}

inline bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const proto::SchnorrProof& proof) {
  if (proof.z.value() == 0) {
    return false;
  }
  try {
    const Scalar e =
        BuildSchnorrChallenge(session_id, prover_id, statement, proof.a);
    ECPoint rhs = proof.a;
    if (e.value() != 0) {
      rhs = rhs.Add(statement.Mul(e));
    }
    return ECPoint::GeneratorMultiply(proof.z) == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa::sm2::internal
