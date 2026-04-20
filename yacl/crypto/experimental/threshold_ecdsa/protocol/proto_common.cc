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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_common.h"

#include <cstddef>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"

namespace tecdsa::proto {

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name) {
  core::participant::ValidateParticipantsOrThrow(participants, self_id,
                                                 context_name);
}

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id) {
  return core::participant::BuildPeers(participants, self_id);
}

Scalar RandomNonZeroScalar() { return core::vss::RandomNonZeroScalar(); }

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id) {
  return core::vss::EvaluatePolynomialAt(coefficients, party_id);
}

StrictProofVerifierContext BuildProofContext(const Bytes& session_id,
                                             PartyIndex prover_id) {
  StrictProofVerifierContext context;
  context.session_id = session_id;
  context.prover_id = prover_id;
  return context;
}

SchnorrProof BuildSchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness) {
  return core::proof::BuildSchnorrProof(session_id, prover_id, statement,
                                        witness);
}

bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const SchnorrProof& proof) {
  return core::proof::VerifySchnorrProof(session_id, prover_id, statement,
                                         proof);
}

const BigInt& MinPaillierModulusQ8() {
  static const BigInt q_pow_8 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 8; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_pow_8;
}

void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub) {
  if (pub.n <= MinPaillierModulusQ8()) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
  }
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  return core::vss::ComputeLagrangeAtZero(participants);
}

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  return core::vss::SumPointsOrThrow(points);
}

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != 33) {
    TECDSA_THROW_ARGUMENT("invalid compressed point length");
  }

  const std::span<const uint8_t> x_bytes(compressed.data() + 1, 32);
  return Scalar::FromBigEndianModQ(x_bytes);
}

bool IsHighScalar(const Scalar& scalar) {
  static const BigInt kHalfOrder = Scalar::ModulusQMpInt() >> 1;
  return scalar.value() > kHalfOrder;
}

}  // namespace tecdsa::proto
