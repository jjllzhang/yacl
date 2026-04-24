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

#include "yacl/crypto/experimental/threshold_signatures/core/keygen/round12_helpers.h"

#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_signatures/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_setup.h"

namespace tecdsa::core::keygen {

LocalRound1Bundle PrepareLocalRound1Bundle(
    const std::vector<PartyIndex>& participants, uint32_t threshold,
    const ThresholdSuite& suite, std::string_view commitment_domain,
    const std::function<Scalar()>& sample_non_zero_scalar,
    const EvaluatePolynomialFn& evaluate_polynomial_at,
    const BuildCommitmentsFn& build_commitments) {
  const std::string domain(commitment_domain);
  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(threshold + 1);
    for (uint32_t i = 0; i <= threshold; ++i) {
      candidate_coefficients.push_back(sample_non_zero_scalar());
    }

    std::unordered_map<PartyIndex, Scalar> candidate_shares;
    candidate_shares.reserve(participants.size());
    bool has_zero_share = false;
    for (PartyIndex party : participants) {
      const Scalar share = evaluate_polynomial_at(candidate_coefficients, party);
      if (share.value() == 0) {
        has_zero_share = true;
        break;
      }
      candidate_shares.emplace(party, share);
    }
    if (has_zero_share) {
      continue;
    }

    std::vector<ECPoint> commitments = build_commitments(candidate_coefficients);
    const ECPoint public_point = commitments.front();
    const auto commit =
        commitment::CommitMessage(suite, domain, encoding::EncodePoint(public_point));
    return LocalRound1Bundle{
        .coefficients = std::move(candidate_coefficients),
        .shares = std::move(candidate_shares),
        .commitments = std::move(commitments),
        .public_point = public_point,
        .commitment = commit.commitment,
        .randomness = commit.randomness,
    };
  }
}

LocalPaillierAuxBundle PrepareLocalPaillierAuxBundle(
    uint32_t paillier_modulus_bits, uint32_t aux_rsa_modulus_bits,
    size_t max_paillier_keygen_attempts, const Bytes& session_id,
    PartyIndex self_id, const ThresholdSuite& suite,
    const std::shared_ptr<const GroupContext>& challenge_group) {
  LocalPaillierAuxBundle out;
  for (size_t attempt = 0; attempt < max_paillier_keygen_attempts; ++attempt) {
    auto candidate = std::make_shared<paillier::PaillierProvider>(
        paillier_modulus_bits);
    const auto candidate_n = candidate->modulus_n_bigint();
    if (candidate_n > paillier::MinPaillierModulusQ8(challenge_group)) {
      out.paillier = std::move(candidate);
      out.paillier_public = paillier::PaillierPublicKey{.n = candidate_n};
      break;
    }
  }

  if (out.paillier == nullptr) {
    TECDSA_THROW("failed to generate Paillier modulus N > q^8");
  }

  const auto proof_context = paillier::BuildProofContext(
      session_id, self_id, suite, challenge_group);
  const auto aux_setup = paillier::GeneratePaperAuxSetup(aux_rsa_modulus_bits);
  out.aux_rsa_params = aux_setup.params;
  out.aux_rsa_witness = aux_setup.witness;
  if (!paillier::ValidatePaperAuxSetup(out.aux_rsa_params,
                                       out.aux_rsa_witness)) {
    TECDSA_THROW("failed to validate local paper auxiliary setup");
  }
  out.aux_param_proof = paillier::BuildAuxCorrectFormProof(
      out.aux_rsa_params, out.aux_rsa_witness, proof_context);
  return out;
}

void ValidatePeerRound1Common(
    const Bytes& session_id, PartyIndex peer_id, const ThresholdSuite& suite,
    const std::shared_ptr<const GroupContext>& challenge_group,
    const paillier::PaillierPublicKey& paillier_public,
    const paillier::AuxRsaParams& aux_rsa_params,
    const paillier::AuxCorrectFormProof& aux_param_proof) {
  paillier::ValidatePaillierPublicKeyOrThrow(paillier_public, challenge_group);
  if (!paillier::ValidateAuxRsaParams(aux_rsa_params)) {
    TECDSA_THROW_ARGUMENT("peer aux RSA parameters are invalid");
  }

  const auto proof_context = paillier::BuildProofContext(
      session_id, peer_id, suite, challenge_group);
  if (!paillier::VerifyAuxCorrectFormProof(aux_rsa_params, aux_param_proof,
                                           proof_context)) {
    TECDSA_THROW_ARGUMENT("peer aux parameter proof verification failed");
  }
}

void ValidatePeerRound2ShareCommon(
    uint32_t threshold, const ThresholdSuite& suite,
    std::string_view commitment_domain, std::string_view public_point_name,
    const Bytes& phase1_commitment, const ECPoint& public_point,
    const Bytes& randomness, const std::vector<ECPoint>& commitments,
    const Scalar& share, const VerifyShareFn& verify_share_for_self) {
  const std::string domain(commitment_domain);
  if (commitments.size() != threshold + 1) {
    TECDSA_THROW_ARGUMENT("peer commitment count does not match threshold");
  }
  if (commitments.front() != public_point) {
    TECDSA_THROW_ARGUMENT("peer Feldman commitments do not open to " +
                          std::string(public_point_name));
  }
  if (!commitment::VerifyCommitment(suite, domain,
                                    encoding::EncodePoint(public_point),
                                    randomness, phase1_commitment)) {
    TECDSA_THROW_ARGUMENT("peer phase1 commitment verification failed");
  }
  if (!verify_share_for_self(commitments, share)) {
    TECDSA_THROW_ARGUMENT("peer Feldman share verification failed");
  }
}

}  // namespace tecdsa::core::keygen
