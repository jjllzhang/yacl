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

#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/algebra/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/suite/suite.h"

namespace tecdsa::core::keygen {

using EvaluatePolynomialFn =
    std::function<Scalar(const std::vector<Scalar>&, PartyIndex)>;
using BuildCommitmentsFn =
    std::function<std::vector<ECPoint>(const std::vector<Scalar>&)>;
using VerifyShareFn =
    std::function<bool(const std::vector<ECPoint>&, const Scalar&)>;

struct LocalRound1Bundle {
  std::vector<Scalar> coefficients;
  std::unordered_map<PartyIndex, Scalar> shares;
  std::vector<ECPoint> commitments;
  ECPoint public_point;
  Bytes commitment;
  Bytes randomness;
};

LocalRound1Bundle PrepareLocalRound1Bundle(
    const std::vector<PartyIndex>& participants, uint32_t threshold,
    const ThresholdSuite& suite, std::string_view commitment_domain,
    const std::function<Scalar()>& sample_non_zero_scalar,
    const EvaluatePolynomialFn& evaluate_polynomial_at,
    const BuildCommitmentsFn& build_commitments);

struct LocalPaillierAuxBundle {
  std::shared_ptr<paillier::PaillierProvider> paillier;
  paillier::PaillierPublicKey paillier_public;
  paillier::AuxRsaParams aux_rsa_params;
  paillier::PaperAuxSetupWitness aux_rsa_witness;
  paillier::AuxCorrectFormProof aux_param_proof;
};

LocalPaillierAuxBundle PrepareLocalPaillierAuxBundle(
    uint32_t paillier_modulus_bits, uint32_t aux_rsa_modulus_bits,
    size_t max_paillier_keygen_attempts, const Bytes& session_id,
    PartyIndex self_id, const ThresholdSuite& suite,
    const std::shared_ptr<const GroupContext>& challenge_group);

void ValidatePeerRound1Common(
    const Bytes& session_id, PartyIndex peer_id, const ThresholdSuite& suite,
    const std::shared_ptr<const GroupContext>& challenge_group,
    const paillier::PaillierPublicKey& paillier_public,
    const paillier::AuxRsaParams& aux_rsa_params,
    const paillier::AuxCorrectFormProof& aux_param_proof);

void ValidatePeerRound2ShareCommon(
    uint32_t threshold, const ThresholdSuite& suite,
    std::string_view commitment_domain, std::string_view public_point_name,
    const Bytes& phase1_commitment, const ECPoint& public_point,
    const Bytes& randomness, const std::vector<ECPoint>& commitments,
    const Scalar& share, const VerifyShareFn& verify_share_for_self);

}  // namespace tecdsa::core::keygen
