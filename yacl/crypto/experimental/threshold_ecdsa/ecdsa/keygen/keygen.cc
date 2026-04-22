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

#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/keygen/keygen.h"

#include <cstddef>
#include <exception>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/encoding/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_setup.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"

namespace tecdsa::ecdsa::keygen {
namespace {

namespace paillier = tecdsa::core::paillier;

constexpr uint32_t kMinPaillierKeygenBits = 2048;
constexpr uint32_t kMinAuxRsaKeygenBits = 164;
constexpr size_t kMaxPaillierKeygenAttempts = 32;
constexpr char kKeygenPhase1CommitDomain[] = "GG2019/keygen/phase1";

}  // namespace

KeygenParty::KeygenParty(KeygenConfig cfg) : cfg_(std::move(cfg)) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "ecdsa::keygen::KeygenParty");
  peers_ = participant_set.peers;
  if (cfg_.threshold >= cfg_.participants.size()) {
    TECDSA_THROW_ARGUMENT("threshold must be less than participant count");
  }
  if (cfg_.paillier_modulus_bits < kMinPaillierKeygenBits) {
    TECDSA_THROW_ARGUMENT("paillier_modulus_bits must be >= 2048");
  }
  if (cfg_.aux_rsa_modulus_bits < kMinAuxRsaKeygenBits) {
    TECDSA_THROW_ARGUMENT("aux_rsa_modulus_bits must be >= 164");
  }
}

const KeygenConfig& KeygenParty::config() const { return cfg_; }

void KeygenParty::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  const auto ecdsa_group = core::DefaultGroupContext();
  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(cfg_.threshold + 1);
    candidate_coefficients.push_back(core::vss::RandomNonZeroScalar(ecdsa_group));
    for (uint32_t i = 0; i < cfg_.threshold; ++i) {
      candidate_coefficients.push_back(core::vss::RandomNonZeroScalar(ecdsa_group));
    }

    PeerMap<Scalar> candidate_shares;
    candidate_shares.reserve(cfg_.participants.size());
    bool has_zero_share = false;
    for (PartyIndex party : cfg_.participants) {
      const Scalar share =
          core::vss::EvaluatePolynomialAt(candidate_coefficients, party);
      if (share.value() == 0) {
        has_zero_share = true;
        break;
      }
      candidate_shares.emplace(party, share);
    }
    if (has_zero_share) {
      continue;
    }

    local_poly_coefficients_ = std::move(candidate_coefficients);
    local_shares_ = std::move(candidate_shares);
    break;
  }

  local_vss_commitments_ = core::vss::BuildCommitments(local_poly_coefficients_);
  local_y_i_ = local_vss_commitments_.front();

  const Bytes y_i_bytes = core::encoding::EncodePoint(local_y_i_);
  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(core::DefaultEcdsaSuite(),
                                      kKeygenPhase1CommitDomain, y_i_bytes);
  local_commitment_ = commit.commitment;
  local_open_randomness_ = commit.randomness;
}

void KeygenParty::EnsureLocalPaillierPrepared() {
  if (local_paillier_ != nullptr) {
    return;
  }

  for (size_t attempt = 0; attempt < kMaxPaillierKeygenAttempts; ++attempt) {
    auto candidate =
        std::make_shared<PaillierProvider>(cfg_.paillier_modulus_bits);
    const BigInt candidate_n = candidate->modulus_n_bigint();
    if (candidate_n > paillier::MinPaillierModulusQ8(local_y_i_.group())) {
      local_paillier_ = std::move(candidate);
      local_paillier_public_ = PaillierPublicKey{.n = candidate_n};
      return;
    }
  }

  TECDSA_THROW("failed to generate Paillier modulus N > q^8");
}

void KeygenParty::EnsureLocalProofsPrepared() {
  if (local_aux_rsa_params_.n_tilde > 0) {
    return;
  }

  EnsureLocalPaillierPrepared();
  const auto context = paillier::BuildProofContext(
      cfg_.session_id, cfg_.self_id, core::DefaultEcdsaSuite(), local_y_i_.group());
  const auto aux_setup = paillier::GeneratePaperAuxSetup(cfg_.aux_rsa_modulus_bits);
  local_aux_rsa_params_ = aux_setup.params;
  local_aux_rsa_witness_ = aux_setup.witness;
  if (!paillier::ValidatePaperAuxSetup(local_aux_rsa_params_,
                                       local_aux_rsa_witness_)) {
    TECDSA_THROW("failed to validate local paper auxiliary setup");
  }
  local_square_free_proof_ = BuildSquareFreeProofGmr98(
      local_paillier_public_.n, local_paillier_->private_lambda_bigint(),
      context);
  local_aux_param_proof_ = paillier::BuildAuxCorrectFormProof(
      local_aux_rsa_params_, local_aux_rsa_witness_, context);

  if (!VerifySquareFreeProofGmr98(local_paillier_public_.n,
                                  local_square_free_proof_, context)) {
    TECDSA_THROW("failed to self-verify local square-free proof");
  }
  if (!paillier::VerifyAuxCorrectFormProof(local_aux_rsa_params_,
                                           local_aux_param_proof_, context)) {
    TECDSA_THROW("failed to self-verify local aux parameter proof");
  }
}

KeygenRound1Msg KeygenParty::MakeRound1() {
  if (round1_.has_value()) {
    return *round1_;
  }

  EnsureLocalPolynomialPrepared();
  EnsureLocalPaillierPrepared();
  EnsureLocalProofsPrepared();

  all_phase1_commitments_[cfg_.self_id] = local_commitment_;
  all_paillier_public_[cfg_.self_id] = local_paillier_public_;
  all_aux_rsa_params_[cfg_.self_id] = local_aux_rsa_params_;
  all_aux_param_proofs_[cfg_.self_id] = local_aux_param_proof_;

  round1_ = KeygenRound1Msg{
      .commitment = local_commitment_,
      .paillier_public = local_paillier_public_,
      .aux_rsa_params = local_aux_rsa_params_,
      .aux_param_proof = local_aux_param_proof_,
  };
  return *round1_;
}

KeygenRound2Out KeygenParty::MakeRound2(
    const PeerMap<KeygenRound1Msg>& peer_round1) {
  if (round2_.has_value()) {
    return *round2_;
  }

  (void)MakeRound1();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");

  for (PartyIndex peer : peers_) {
    const auto it = peer_round1.find(peer);
    const KeygenRound1Msg& msg = it->second;
    paillier::ValidatePaillierPublicKeyOrThrow(msg.paillier_public,
                                               local_y_i_.group());
    if (!ValidateAuxRsaParams(msg.aux_rsa_params)) {
      TECDSA_THROW_ARGUMENT("peer aux RSA parameters are invalid");
    }
    const auto context = paillier::BuildProofContext(
        cfg_.session_id, peer, core::DefaultEcdsaSuite(), local_y_i_.group());
    if (!paillier::VerifyAuxCorrectFormProof(msg.aux_rsa_params,
                                             msg.aux_param_proof, context)) {
      TECDSA_THROW_ARGUMENT("peer aux parameter proof verification failed");
    }

    all_phase1_commitments_[peer] = msg.commitment;
    all_paillier_public_[peer] = msg.paillier_public;
    all_aux_rsa_params_[peer] = msg.aux_rsa_params;
    all_aux_param_proofs_[peer] = msg.aux_param_proof;
  }

  KeygenRound2Out out;
  out.broadcast = KeygenRound2Broadcast{
      .y_i = local_y_i_,
      .randomness = local_open_randomness_,
      .commitments = local_vss_commitments_,
  };
  for (PartyIndex peer : peers_) {
    out.shares_for_peers.emplace(peer, local_shares_.at(peer));
  }
  round2_ = out;
  return *round2_;
}

bool KeygenParty::VerifyDealerShareForSelf(PartyIndex dealer,
                                           const KeygenRound2Broadcast& round2,
                                           const Scalar& share) const {
  (void)dealer;
  return core::vss::VerifyShareForReceiver(cfg_.self_id, cfg_.threshold,
                                           round2.commitments, share);
}

KeygenRound3Msg KeygenParty::MakeRound3(
    const PeerMap<KeygenRound2Broadcast>& peer_round2,
    const PeerMap<Scalar>& shares_for_self) {
  if (round3_.has_value()) {
    return *round3_;
  }

  if (!round2_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound2 must be completed before MakeRound3");
  }
  core::participant::RequireExactlyPeers(peer_round2, cfg_.participants,
                                         cfg_.self_id, "peer_round2");
  core::participant::RequireExactlyPeers(shares_for_self, cfg_.participants,
                                         cfg_.self_id, "shares_for_self");

  Scalar x_sum = local_shares_.at(cfg_.self_id);
  std::vector<ECPoint> y_points;
  y_points.reserve(cfg_.participants.size());
  y_points.push_back(local_y_i_);

  for (PartyIndex peer : peers_) {
    const KeygenRound2Broadcast& msg = peer_round2.at(peer);
    const auto commitment_it = all_phase1_commitments_.find(peer);
    if (commitment_it == all_phase1_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }

    if (msg.commitments.size() != cfg_.threshold + 1) {
      TECDSA_THROW_ARGUMENT("peer commitment count does not match threshold");
    }
    if (msg.commitments.front() != msg.y_i) {
      TECDSA_THROW_ARGUMENT("peer Feldman commitments do not open to y_i");
    }

    const Bytes y_i_bytes = core::encoding::EncodePoint(msg.y_i);
    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), kKeygenPhase1CommitDomain, y_i_bytes,
            msg.randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("peer phase1 commitment verification failed");
    }

    const Scalar share = shares_for_self.at(peer);
    if (!VerifyDealerShareForSelf(peer, msg, share)) {
      TECDSA_THROW_ARGUMENT("peer Feldman share verification failed");
    }

    x_sum = x_sum + share;
    y_points.push_back(msg.y_i);
  }

  if (x_sum.value() == 0) {
    TECDSA_THROW("aggregated local share is zero");
  }

  local_x_i_ = x_sum;
  try {
    aggregated_y_ = core::vss::SumPointsOrThrow(y_points);
  } catch (const std::exception& ex) {
    TECDSA_THROW(std::string("failed to aggregate public key points: ") +
                 ex.what());
  }

  const ECPoint X_i = ECPoint::GeneratorMultiply(local_x_i_);
  round3_ = KeygenRound3Msg{
      .X_i = X_i,
      .proof = core::proof::BuildSchnorrProof(core::DefaultEcdsaSuite(),
                                              cfg_.session_id, cfg_.self_id,
                                              X_i, local_x_i_),
      .square_free_proof = local_square_free_proof_,
  };
  return *round3_;
}

KeygenOutput KeygenParty::Finalize(const PeerMap<KeygenRound3Msg>& peer_round3) {
  if (output_.has_value()) {
    return *output_;
  }
  if (!round3_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound3 must be completed before Finalize");
  }

  core::participant::RequireExactlyPeers(peer_round3, cfg_.participants,
                                         cfg_.self_id, "peer_round3");

  PublicKeygenData public_data;
  public_data.y = aggregated_y_;
  public_data.threshold = cfg_.threshold;
  public_data.all_paillier_public = all_paillier_public_;
  public_data.all_aux_rsa_params = all_aux_rsa_params_;
  public_data.all_aux_param_proofs = all_aux_param_proofs_;
  public_data.all_square_free_proofs[cfg_.self_id] = local_square_free_proof_;
  public_data.all_X_i[cfg_.self_id] = round3_->X_i;

  for (PartyIndex peer : peers_) {
    const KeygenRound3Msg& msg = peer_round3.at(peer);
    if (!core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, peer, msg.X_i,
                                         msg.proof)) {
      TECDSA_THROW_ARGUMENT("peer Schnorr proof verification failed");
    }
    const auto pk_it = all_paillier_public_.find(peer);
    if (pk_it == all_paillier_public_.end()) {
      TECDSA_THROW_LOGIC("missing stored Paillier public key for peer");
    }
    const auto context = paillier::BuildProofContext(
        cfg_.session_id, peer, core::DefaultEcdsaSuite(), local_y_i_.group());
    if (!VerifySquareFreeProofGmr98(pk_it->second.n, msg.square_free_proof,
                                    context)) {
      TECDSA_THROW_ARGUMENT("peer square-free proof verification failed");
    }

    public_data.all_X_i[peer] = msg.X_i;
    public_data.all_square_free_proofs[peer] = msg.square_free_proof;
  }

  output_ = KeygenOutput{
      .local_key_share =
          LocalKeyShare{
              .x_i = local_x_i_,
              .X_i = round3_->X_i,
              .paillier = local_paillier_,
          },
      .public_keygen_data = std::move(public_data),
  };
  return *output_;
}

}  // namespace tecdsa::ecdsa::keygen
