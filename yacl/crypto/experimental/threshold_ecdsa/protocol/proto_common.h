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

#include <optional>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/verify/verify.h"

namespace tecdsa::proto {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

using SchnorrProof = tecdsa::core::proof::SchnorrProof;

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name);

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id);

template <typename T>
void RequireExactlyPeers(const PeerMap<T>& messages,
                         const std::vector<PartyIndex>& participants,
                         PartyIndex self_id, const char* field_name) {
  core::participant::RequireExactlyPeers(messages, participants, self_id,
                                         field_name);
}

Scalar RandomNonZeroScalar();
Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id);

core::paillier::StrictProofVerifierContext BuildProofContext(
    const Bytes& session_id, PartyIndex prover_id,
    std::optional<PartyIndex> verifier_id = std::nullopt);

SchnorrProof BuildSchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness);
bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const SchnorrProof& proof);

const core::paillier::BigInt& MinPaillierModulusQ8();
void ValidatePaillierPublicKeyOrThrow(const tecdsa::PaillierPublicKey& pub);

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants);

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points);
Scalar XCoordinateModQ(const ECPoint& point);
bool IsHighScalar(const Scalar& scalar);

}  // namespace tecdsa::proto
