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

#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/adapters.h"

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

Scalar RandomNonZeroScalar() {
  return core::vss::RandomNonZeroScalar(core::DefaultGroupContext());
}

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id) {
  return core::vss::EvaluatePolynomialAt(coefficients, party_id);
}

core::paillier::StrictProofVerifierContext BuildProofContext(
    const Bytes& session_id, PartyIndex prover_id,
    std::optional<PartyIndex> verifier_id) {
  return core::paillier::BuildProofContext(session_id, prover_id,
                                           core::DefaultEcdsaSuite(),
                                           core::DefaultGroupContext(),
                                           verifier_id);
}

SchnorrProof BuildSchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness) {
  return ecdsa::proofs::FromCoreSchnorrProof(core::proof::BuildSchnorrProof(
      core::DefaultEcdsaSuite(), session_id, prover_id, statement, witness));
}

bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const SchnorrProof& proof) {
  return core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(), session_id,
                                         prover_id, statement,
                                         ecdsa::proofs::ToCoreSchnorrProof(
                                             proof));
}

const core::paillier::BigInt& MinPaillierModulusQ8() {
  static const core::paillier::BigInt kMin =
      core::paillier::MinPaillierModulusQ8(core::DefaultGroupContext());
  return kMin;
}

void ValidatePaillierPublicKeyOrThrow(const tecdsa::PaillierPublicKey& pub) {
  core::paillier::ValidatePaillierPublicKeyOrThrow(pub,
                                                   core::DefaultGroupContext());
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  return core::vss::ComputeLagrangeAtZero(participants,
                                          core::DefaultGroupContext());
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
