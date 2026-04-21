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

tecdsa::StrictProofVerifierContext BuildProofContext(const Bytes& session_id,
                                                     PartyIndex prover_id) {
  return core::paillier::BuildProofContext(session_id, prover_id);
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

const tecdsa::BigInt& MinPaillierModulusQ8() {
  return core::paillier::MinPaillierModulusQ8();
}

void ValidatePaillierPublicKeyOrThrow(const tecdsa::PaillierPublicKey& pub) {
  core::paillier::ValidatePaillierPublicKeyOrThrow(pub);
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  return core::vss::ComputeLagrangeAtZero(participants);
}

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  return core::vss::SumPointsOrThrow(points);
}

Scalar XCoordinateModQ(const ECPoint& point) {
  return ecdsa::verify::XCoordinateModQ(point);
}

bool IsHighScalar(const Scalar& scalar) {
  return ecdsa::verify::IsHighScalar(scalar);
}

}  // namespace tecdsa::proto
