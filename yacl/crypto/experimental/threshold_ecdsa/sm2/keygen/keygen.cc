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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/keygen/keygen.h"

#include <algorithm>
#include <exception>
#include <string>
#include <unordered_set>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_setup.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"

namespace tecdsa::sm2::keygen {
namespace {

namespace mta = tecdsa::core::mta;
namespace paillier = tecdsa::core::paillier;

constexpr uint32_t kMinPaillierKeygenBits = 2048;
constexpr uint32_t kMinAuxRsaKeygenBits = 164;
constexpr size_t kMaxPaillierKeygenAttempts = 32;
constexpr char kKeygenPhase1CommitDomain[] = "SM2/keygen/phase1";
constexpr char kDefaultSignerId[] = "1234567812345678";

void RequireExactlyOneRequestPerPeer(
    const std::vector<KeygenRound3Request>& requests,
    const std::vector<PartyIndex>& peers, PartyIndex self_id) {
  if (requests.size() != peers.size()) {
    TECDSA_THROW_ARGUMENT(
        "SM2 keygen requests_for_self must contain exactly one request per peer");
  }

  std::unordered_set<PartyIndex> senders;
  senders.reserve(requests.size());
  for (const auto& request : requests) {
    if (request.to != self_id) {
      TECDSA_THROW_ARGUMENT("SM2 keygen request must target self");
    }
    if (request.type != mta::MtaType::kMta) {
      TECDSA_THROW_ARGUMENT("SM2 keygen only uses the plain MtA path");
    }
    if (!senders.insert(request.from).second) {
      TECDSA_THROW_ARGUMENT("duplicate SM2 keygen request sender");
    }
  }
}

void RequireExactlyOneResponsePerPeer(
    const std::vector<KeygenRound3Response>& responses,
    const std::vector<PartyIndex>& peers, PartyIndex self_id) {
  if (responses.size() != peers.size()) {
    TECDSA_THROW_ARGUMENT(
        "SM2 keygen responses_for_self must contain exactly one response per peer");
  }

  std::unordered_set<PartyIndex> responders;
  responders.reserve(responses.size());
  for (const auto& response : responses) {
    if (response.to != self_id) {
      TECDSA_THROW_ARGUMENT("SM2 keygen response must target self");
    }
    if (response.type != mta::MtaType::kMta) {
      TECDSA_THROW_ARGUMENT("SM2 keygen only uses the plain MtA path");
    }
    if (!responders.insert(response.from).second) {
      TECDSA_THROW_ARGUMENT("duplicate SM2 keygen response sender");
    }
  }
}

}  // namespace

KeygenParty::KeygenParty(KeygenConfig cfg)
    : cfg_(std::move(cfg)),
      sigma_session_({.session_id = cfg_.session_id,
                      .self_id = cfg_.self_id,
                      .suite = core::DefaultSm2Suite(),
                      .group = internal::Sm2Group(),
                      .proof_backend = nullptr}) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "sm2::keygen::KeygenParty");
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
  if (cfg_.signer_id.empty()) {
    cfg_.signer_id.assign(kDefaultSignerId,
                          kDefaultSignerId + sizeof(kDefaultSignerId) - 1);
  }
  local_z_i_ = internal::Sm2Zero();
  local_gamma_i_ = internal::Sm2Zero();
  sigma_initiator_sum_ = internal::Sm2Zero();
  sigma_responder_sum_ = internal::Sm2Zero();
  local_sigma_i_ = internal::Sm2Zero();
}

const KeygenConfig& KeygenParty::config() const { return cfg_; }

void KeygenParty::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(cfg_.threshold + 1);
    candidate_coefficients.push_back(internal::RandomNonZeroSm2Scalar());
    for (uint32_t i = 0; i < cfg_.threshold; ++i) {
      candidate_coefficients.push_back(internal::RandomNonZeroSm2Scalar());
    }

    PeerMap<Scalar> candidate_shares;
    candidate_shares.reserve(cfg_.participants.size());
    bool has_zero_share = false;
    for (PartyIndex party : cfg_.participants) {
      const Scalar share =
          internal::EvaluatePolynomialAt(candidate_coefficients, party);
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

  local_vss_commitments_ = internal::BuildCommitments(local_poly_coefficients_);
  local_Z_i_ = local_vss_commitments_.front();

  const auto commit = core::commitment::CommitMessage(
      core::DefaultSm2Suite(), kKeygenPhase1CommitDomain,
      local_Z_i_.ToCompressedBytes());
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
    if (candidate->modulus_n_bigint() >
        paillier::MinPaillierModulusQ8(internal::Sm2Group())) {
      local_paillier_ = std::move(candidate);
      local_paillier_public_ = PaillierPublicKey{
          .n = local_paillier_->modulus_n_bigint(),
      };
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
  const auto context =
      paillier::BuildProofContext(cfg_.session_id, cfg_.self_id,
                                  core::DefaultSm2Suite(), internal::Sm2Group());
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
    const auto& msg = peer_round1.at(peer);
    paillier::ValidatePaillierPublicKeyOrThrow(msg.paillier_public,
                                               internal::Sm2Group());
    if (!ValidateAuxRsaParams(msg.aux_rsa_params)) {
      TECDSA_THROW_ARGUMENT("peer aux RSA parameters are invalid");
    }
    const auto context =
        paillier::BuildProofContext(cfg_.session_id, peer,
                                    core::DefaultSm2Suite(),
                                    internal::Sm2Group());
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
      .Z_i = local_Z_i_,
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
  return internal::VerifyShareForReceiver(cfg_.self_id, cfg_.threshold,
                                          round2.commitments, share);
}

std::vector<KeygenRound3Request> KeygenParty::MakeRound3Requests(
    const PeerMap<KeygenRound2Broadcast>& peer_round2,
    const PeerMap<Scalar>& shares_for_self) {
  if (!round3_requests_.empty()) {
    return round3_requests_;
  }
  if (!round2_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound2 must be completed before MakeRound3Requests");
  }

  core::participant::RequireExactlyPeers(peer_round2, cfg_.participants,
                                         cfg_.self_id, "peer_round2");
  core::participant::RequireExactlyPeers(shares_for_self, cfg_.participants,
                                         cfg_.self_id, "shares_for_self");

  Scalar z_sum = local_shares_.at(cfg_.self_id);
  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round2.at(peer);
    const auto commitment_it = all_phase1_commitments_.find(peer);
    if (commitment_it == all_phase1_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }
    if (msg.commitments.size() != cfg_.threshold + 1) {
      TECDSA_THROW_ARGUMENT("peer commitment count does not match threshold");
    }
    if (msg.commitments.front() != msg.Z_i) {
      TECDSA_THROW_ARGUMENT("peer Feldman commitments do not open to Z_i");
    }
    if (!core::commitment::VerifyCommitment(
            core::DefaultSm2Suite(), kKeygenPhase1CommitDomain,
            msg.Z_i.ToCompressedBytes(), msg.randomness,
            commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("peer phase1 commitment verification failed");
    }
    const Scalar share = shares_for_self.at(peer);
    if (!VerifyDealerShareForSelf(peer, msg, share)) {
      TECDSA_THROW_ARGUMENT("peer Feldman share verification failed");
    }
    z_sum = z_sum + share;
  }

  if (z_sum.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated local z share is zero");
  }

  local_z_i_ = z_sum;
  local_gamma_i_ = internal::RandomNonZeroSm2Scalar();
  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);

  for (PartyIndex peer : peers_) {
    round3_requests_.push_back(sigma_session_.CreateRequest({
        .responder_id = peer,
        .type = mta::MtaType::kMta,
        .initiator_paillier = local_paillier_.get(),
        .responder_aux = &all_aux_rsa_params_.at(peer),
        .initiator_secret = local_gamma_i_,
    }));
  }
  return round3_requests_;
}

std::vector<KeygenRound3Response> KeygenParty::MakeRound3Responses(
    const std::vector<KeygenRound3Request>& requests_for_self) {
  if (round3_responses_.has_value()) {
    return *round3_responses_;
  }
  if (round3_requests_.empty()) {
    TECDSA_THROW_LOGIC(
        "MakeRound3Requests must be completed before MakeRound3Responses");
  }

  RequireExactlyOneRequestPerPeer(requests_for_self, peers_, cfg_.self_id);

  std::vector<KeygenRound3Response> out;
  out.reserve(requests_for_self.size());
  for (const auto& request : requests_for_self) {
    const auto consume = sigma_session_.ConsumeRequest(
        request,
        {.initiator_modulus_n = all_paillier_public_.at(request.from).n,
         .responder_aux = &all_aux_rsa_params_.at(cfg_.self_id),
         .initiator_aux = &all_aux_rsa_params_.at(request.from),
         .responder_secret = local_z_i_,
         .public_witness_point = std::nullopt});
    sigma_responder_sum_ = sigma_responder_sum_ + consume.responder_share;
    out.push_back(consume.response);
  }

  round3_responses_ = out;
  return *round3_responses_;
}

KeygenRound4Msg KeygenParty::MakeRound4(
    const std::vector<KeygenRound3Response>& responses_for_self) {
  if (round4_.has_value()) {
    return *round4_;
  }
  if (!round3_responses_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound3Responses must be completed before MakeRound4");
  }

  RequireExactlyOneResponsePerPeer(responses_for_self, peers_, cfg_.self_id);

  for (const auto& response : responses_for_self) {
    const auto consume = sigma_session_.ConsumeResponse(
        response,
        {.initiator_paillier = local_paillier_.get(),
         .initiator_aux = &all_aux_rsa_params_.at(cfg_.self_id),
         .public_witness_point = std::nullopt});
    sigma_initiator_sum_ = sigma_initiator_sum_ + consume.initiator_share;
  }

  local_sigma_i_ =
      (local_gamma_i_ * local_z_i_) + sigma_initiator_sum_ + sigma_responder_sum_;
  round4_ = KeygenRound4Msg{
      .sigma_i = local_sigma_i_,
      .Gamma_i = local_Gamma_i_,
      .gamma_proof =
          internal::BuildSchnorrProof(cfg_.session_id, cfg_.self_id,
                                      local_Gamma_i_, local_gamma_i_),
      .square_free_proof = local_square_free_proof_,
  };
  return *round4_;
}

KeygenOutput KeygenParty::Finalize(const PeerMap<KeygenRound4Msg>& peer_round4) {
  if (output_.has_value()) {
    return *output_;
  }
  if (!round4_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound4 must be completed before Finalize");
  }

  core::participant::RequireExactlyPeers(peer_round4, cfg_.participants,
                                         cfg_.self_id, "peer_round4");

  Scalar sigma = local_sigma_i_;
  std::vector<ECPoint> gamma_points;
  gamma_points.reserve(cfg_.participants.size());
  gamma_points.push_back(local_Gamma_i_);

  PublicKeygenData public_data;
  public_data.all_paillier_public = all_paillier_public_;
  public_data.all_aux_rsa_params = all_aux_rsa_params_;
  public_data.all_aux_param_proofs = all_aux_param_proofs_;
  public_data.all_square_free_proofs[cfg_.self_id] = local_square_free_proof_;

  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round4.at(peer);
    if (!internal::VerifySchnorrProof(cfg_.session_id, peer, msg.Gamma_i,
                                      msg.gamma_proof)) {
      TECDSA_THROW_ARGUMENT("peer gamma Schnorr proof verification failed");
    }
    const auto context =
        paillier::BuildProofContext(cfg_.session_id, peer,
                                    core::DefaultSm2Suite(),
                                    internal::Sm2Group());
    if (!VerifySquareFreeProofGmr98(all_paillier_public_.at(peer).n,
                                    msg.square_free_proof, context)) {
      TECDSA_THROW_ARGUMENT("peer square-free proof verification failed");
    }

    sigma = sigma + msg.sigma_i;
    gamma_points.push_back(msg.Gamma_i);
    public_data.all_square_free_proofs[peer] = msg.square_free_proof;
  }

  if (sigma.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated sigma is zero");
  }
  const Scalar sigma_inverse = sigma.InverseModQ();
  public_data.sigma_inverse = sigma_inverse;

  ECPoint plus_one_public;
  try {
    for (PartyIndex party : cfg_.participants) {
      const ECPoint gamma_point =
          (party == cfg_.self_id) ? local_Gamma_i_ : peer_round4.at(party).Gamma_i;
      public_data.all_plus_one_public_shares[party] = gamma_point.Mul(sigma_inverse);
    }
    std::vector<ECPoint> plus_one_points;
    plus_one_points.reserve(cfg_.participants.size());
    for (PartyIndex party : cfg_.participants) {
      plus_one_points.push_back(public_data.all_plus_one_public_shares.at(party));
    }
    plus_one_public = internal::SumPointsOrThrow(plus_one_points);
    public_data.public_key =
        plus_one_public.Add(ECPoint::GeneratorMultiply(internal::Sm2Negate(
            internal::Sm2One())));
  } catch (const std::exception& ex) {
    TECDSA_THROW(std::string("failed to derive SM2 public key: ") + ex.what());
  }

  if (public_data.public_key == plus_one_public) {
    TECDSA_THROW_ARGUMENT("invalid SM2 public key derivation");
  }

  zid::IdentityBinding binding =
      zid::BindIdentity(cfg_.signer_id, public_data.public_key);

  output_ = KeygenOutput{
      .local_key_share =
          LocalKeyShare{
              .z_i = local_z_i_,
              .paillier = local_paillier_,
              .binding = std::move(binding),
          },
      .public_keygen_data = std::move(public_data),
  };
  return *output_;
}

}  // namespace tecdsa::sm2::keygen
