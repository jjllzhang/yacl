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
#include "yacl/crypto/experimental/threshold_ecdsa/core/keygen/round12_helpers.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/adapters.h"

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
  auto prepared = core::keygen::PrepareLocalRound1Bundle(
      cfg_.participants, cfg_.threshold, core::DefaultEcdsaSuite(),
      kKeygenPhase1CommitDomain,
      [ecdsa_group]() { return core::vss::RandomNonZeroScalar(ecdsa_group); },
      [](const std::vector<Scalar>& coefficients, PartyIndex party) {
        return core::vss::EvaluatePolynomialAt(coefficients, party);
      },
      [](const std::vector<Scalar>& coefficients) {
        return core::vss::BuildCommitments(coefficients);
      });
  local_poly_coefficients_ = std::move(prepared.coefficients);
  local_shares_ = std::move(prepared.shares);
  local_vss_commitments_ = std::move(prepared.commitments);
  local_y_i_ = prepared.public_point;
  local_commitment_ = std::move(prepared.commitment);
  local_open_randomness_ = std::move(prepared.randomness);
}

void KeygenParty::EnsureLocalPaillierAndAuxPrepared() {
  if (local_aux_rsa_params_.n_tilde > 0) {
    return;
  }

  auto prepared = core::keygen::PrepareLocalPaillierAuxBundle(
      cfg_.paillier_modulus_bits, cfg_.aux_rsa_modulus_bits,
      kMaxPaillierKeygenAttempts, cfg_.session_id, cfg_.self_id,
      core::DefaultEcdsaSuite(), local_y_i_.group());
  local_paillier_ = std::move(prepared.paillier);
  local_paillier_public_ = prepared.paillier_public;
  local_aux_rsa_params_ = prepared.aux_rsa_params;
  local_aux_rsa_witness_ = prepared.aux_rsa_witness;
  local_aux_param_proof_ = prepared.aux_param_proof;
}

void KeygenParty::EnsureLocalProofsPrepared() {
  if (!local_square_free_proof_.blob.empty()) {
    return;
  }

  EnsureLocalPaillierAndAuxPrepared();
  const auto context =
      paillier::BuildProofContext(cfg_.session_id, cfg_.self_id,
                                  core::DefaultEcdsaSuite(), local_y_i_.group());
  local_square_free_proof_ = BuildSquareFreeProofGmr98(
      local_paillier_public_.n, local_paillier_->private_lambda_bigint(),
      context);
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
    core::keygen::ValidatePeerRound1Common(
        cfg_.session_id, peer, core::DefaultEcdsaSuite(), local_y_i_.group(),
        msg.paillier_public, msg.aux_rsa_params, msg.aux_param_proof);

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

    const Scalar share = shares_for_self.at(peer);
    core::keygen::ValidatePeerRound2ShareCommon(
        cfg_.threshold, core::DefaultEcdsaSuite(), kKeygenPhase1CommitDomain,
        "y_i", commitment_it->second, msg.y_i, msg.randomness, msg.commitments,
        share, [this](const std::vector<ECPoint>& commitments,
                      const Scalar& candidate_share) {
          return core::vss::VerifyShareForReceiver(
              cfg_.self_id, cfg_.threshold, commitments, candidate_share);
        });

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
      .proof = tecdsa::ecdsa::proofs::FromCoreSchnorrProof(
          core::proof::BuildSchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, cfg_.self_id, X_i,
                                         local_x_i_)),
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
                                         tecdsa::ecdsa::proofs::ToCoreSchnorrProof(
                                             msg.proof))) {
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
