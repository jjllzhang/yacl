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

#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/sign.h"

#include <algorithm>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/relation_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/scalar_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/verify/verify.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace mta = tecdsa::core::mta;
namespace paillier = tecdsa::core::paillier;
namespace relation = tecdsa::ecdsa::sign;
namespace verify = tecdsa::ecdsa::verify;

inline constexpr size_t kCommitmentLen = 32;
inline constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
inline constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
inline constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";

mta::MtaType ToCoreMtaType(MtaType type) {
  switch (type) {
    case MtaType::kTimesGamma:
      return mta::MtaType::kMta;
    case MtaType::kTimesW:
      return mta::MtaType::kMtAwc;
  }
  TECDSA_THROW_ARGUMENT("unknown protocol MtaType");
}

MtaType FromCoreMtaType(mta::MtaType type) {
  switch (type) {
    case mta::MtaType::kMta:
      return MtaType::kTimesGamma;
    case mta::MtaType::kMtAwc:
      return MtaType::kTimesW;
  }
  TECDSA_THROW_ARGUMENT("unknown core MtaType");
}

SignRound2Request ToProtocolRequest(const mta::PairwiseProductRequest& request) {
  return SignRound2Request{
      .from = request.from,
      .to = request.to,
      .type = FromCoreMtaType(request.type),
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = request.a1_proof,
  };
}

mta::PairwiseProductRequest ToCoreRequest(const SignRound2Request& request) {
  return mta::PairwiseProductRequest{
      .from = request.from,
      .to = request.to,
      .type = ToCoreMtaType(request.type),
      .instance_id = request.instance_id,
      .c1 = request.c1,
      .a1_proof = request.a1_proof,
  };
}

SignRound2Response ToProtocolResponse(
    const mta::PairwiseProductResponse& response) {
  return SignRound2Response{
      .from = response.from,
      .to = response.to,
      .type = FromCoreMtaType(response.type),
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof,
      .a3_proof = response.a3_proof,
  };
}

mta::PairwiseProductResponse ToCoreResponse(const SignRound2Response& response) {
  return mta::PairwiseProductResponse{
      .from = response.from,
      .to = response.to,
      .type = ToCoreMtaType(response.type),
      .instance_id = response.instance_id,
      .c2 = response.c2,
      .a2_proof = response.a2_proof,
      .a3_proof = response.a3_proof,
  };
}

bool IsPeer(const std::vector<PartyIndex>& peers, PartyIndex party) {
  return std::find(peers.begin(), peers.end(), party) != peers.end();
}

void ValidateCommitmentOrThrow(const Bytes& commitment,
                               const char* field_name) {
  if (commitment.size() != kCommitmentLen) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must be exactly 32 bytes");
  }
}

}  // namespace

SignParty::SignParty(SignConfig cfg)
    : cfg_(std::move(cfg)),
      message_scalar_(Scalar::FromBigEndianModQ(cfg_.msg32)),
      phase2_session_(
          {.session_id = cfg_.session_id,
           .self_id = cfg_.self_id,
           .suite = core::DefaultEcdsaSuite(),
           .group = nullptr}) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "ecdsa::sign::SignParty");
  peers_ = participant_set.peers;
  if (cfg_.msg32.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignParty");
  }
  if (cfg_.local_key_share.x_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  if (ECPoint::GeneratorMultiply(cfg_.local_key_share.x_i) !=
      cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("local key share X_i does not match x_i");
  }

  for (PartyIndex party : cfg_.participants) {
    if (!cfg_.public_keygen_data.all_X_i.contains(party) ||
        !cfg_.public_keygen_data.all_paillier_public.contains(party) ||
        !cfg_.public_keygen_data.all_aux_rsa_params.contains(party) ||
        !cfg_.public_keygen_data.all_square_free_proofs.contains(party) ||
        !cfg_.public_keygen_data.all_aux_param_proofs.contains(party)) {
      TECDSA_THROW_ARGUMENT("public keygen data is missing participant data");
    }

    const auto& paillier_public =
        cfg_.public_keygen_data.all_paillier_public.at(party);
    const auto& aux_params =
        cfg_.public_keygen_data.all_aux_rsa_params.at(party);
    const auto& square_free_proof =
        cfg_.public_keygen_data.all_square_free_proofs.at(party);
    const auto& aux_param_proof =
        cfg_.public_keygen_data.all_aux_param_proofs.at(party);

    paillier::ValidatePaillierPublicKeyOrThrow(
        paillier_public, cfg_.local_key_share.x_i.group());
    if (!paillier::ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("public aux RSA parameters are invalid");
    }

    const paillier::StrictProofVerifierContext proof_context =
        paillier::BuildProofContext(cfg_.keygen_session_id, party,
                                    core::DefaultEcdsaSuite(),
                                    cfg_.local_key_share.x_i.group());
    if (!paillier::VerifySquareFreeProofGmr98(paillier_public.n,
                                              square_free_proof,
                                              proof_context)) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }
    if (!paillier::VerifyAuxCorrectFormProof(aux_params, aux_param_proof,
                                             proof_context)) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }
  }

  const auto self_pk_it =
      cfg_.public_keygen_data.all_paillier_public.find(cfg_.self_id);
  if (self_pk_it == cfg_.public_keygen_data.all_paillier_public.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != cfg_.local_key_share.paillier->modulus_n_bigint()) {
    TECDSA_THROW_ARGUMENT(
        "self Paillier public key does not match local provider");
  }

  const auto self_x_it = cfg_.public_keygen_data.all_X_i.find(cfg_.self_id);
  if (self_x_it == cfg_.public_keygen_data.all_X_i.end()) {
    TECDSA_THROW_ARGUMENT("missing self X_i in public keygen data");
  }
  if (self_x_it->second != cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("self X_i does not match local key share");
  }

  PrepareResharedSigningShares();
}

const SignConfig& SignParty::config() const { return cfg_; }

void SignParty::PrepareResharedSigningShares() {
  lagrange_coefficients_ = core::vss::ComputeLagrangeAtZero(
      cfg_.participants, cfg_.local_key_share.x_i.group());

  const auto lambda_self_it = lagrange_coefficients_.find(cfg_.self_id);
  if (lambda_self_it == lagrange_coefficients_.end()) {
    TECDSA_THROW_ARGUMENT("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * cfg_.local_key_share.x_i;

  std::vector<ECPoint> w_points;
  w_points.reserve(cfg_.participants.size());
  for (PartyIndex party : cfg_.participants) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    const auto x_it = cfg_.public_keygen_data.all_X_i.find(party);
    if (lambda_it == lagrange_coefficients_.end() ||
        x_it == cfg_.public_keygen_data.all_X_i.end()) {
      TECDSA_THROW_ARGUMENT(
          "missing lagrange coefficient or X_i for participant");
    }

    try {
      w_points_[party] = x_it->second.Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      TECDSA_THROW_ARGUMENT(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(w_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = core::vss::SumPointsOrThrow(w_points);
    if (reconstructed_y != cfg_.public_keygen_data.y) {
      TECDSA_THROW_ARGUMENT("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate W_i aggregation: ") +
                          ex.what());
  }
}

void SignParty::EnsurePhase1Prepared() {
  if (round1_.has_value()) {
    return;
  }

  const auto& group = cfg_.local_key_share.x_i.group();
  local_k_i_ = core::vss::RandomNonZeroScalar(group);
  local_gamma_i_ = core::vss::RandomNonZeroScalar(group);
  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(core::DefaultEcdsaSuite(),
                                      kPhase1CommitDomain,
                                      local_Gamma_i_.ToCompressedBytes());
  local_round1_randomness_ = commit.randomness;
  round1_ = SignRound1Msg{.commitment = commit.commitment};
  phase1_commitments_[cfg_.self_id] = round1_->commitment;
}

void SignParty::EnsureRound5ASharePrepared() {
  if (round5a_.has_value()) {
    return;
  }

  local_s_i_ = (message_scalar_ * local_k_i_) + (r_ * local_sigma_i_);
  const auto& group = cfg_.local_key_share.x_i.group();
  local_l_i_ = core::vss::RandomNonZeroScalar(group);
  local_rho_i_ = core::vss::RandomNonZeroScalar(group);

  local_V_i_ = ECPoint::GeneratorMultiply(local_l_i_);
  if (local_s_i_.value() != 0) {
    local_V_i_ = local_V_i_.Add(R_.Mul(local_s_i_));
  }
  local_A_i_ = ECPoint::GeneratorMultiply(local_rho_i_);

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(
          core::DefaultEcdsaSuite(),
          kPhase5ACommitDomain,
          relation::SerializePointPair(local_V_i_, local_A_i_));
  local_round5a_randomness_ = commit.randomness;
  round5a_ = SignRound5AMsg{.commitment = commit.commitment};
  phase5a_commitments_[cfg_.self_id] = round5a_->commitment;
}

SignRound1Msg SignParty::MakeRound1() {
  EnsurePhase1Prepared();
  return *round1_;
}

std::vector<SignRound2Request> SignParty::MakeRound2Requests(
    const PeerMap<SignRound1Msg>& peer_round1) {
  if (!round2_requests_.empty()) {
    return round2_requests_;
  }

  EnsurePhase1Prepared();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");

  for (PartyIndex peer : peers_) {
    const SignRound1Msg& msg = peer_round1.at(peer);
    ValidateCommitmentOrThrow(msg.commitment, "sign round1 commitment");
    phase1_commitments_[peer] = msg.commitment;
  }

  for (PartyIndex peer : peers_) {
    const auto aux_it = cfg_.public_keygen_data.all_aux_rsa_params.find(peer);
    if (aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing peer auxiliary parameters for sign round2");
    }

    for (MtaType type : {MtaType::kTimesGamma, MtaType::kTimesW}) {
      const auto request = phase2_session_.CreateRequest({
          .responder_id = peer,
          .type = ToCoreMtaType(type),
          .initiator_paillier = cfg_.local_key_share.paillier.get(),
          .responder_aux = &aux_it->second,
          .initiator_secret = local_k_i_,
      });
      round2_requests_.push_back(ToProtocolRequest(request));
    }
  }

  return round2_requests_;
}

std::vector<SignRound2Response> SignParty::MakeRound2Responses(
    const std::vector<SignRound2Request>& requests_for_self) {
  if (round2_responses_.has_value()) {
    return *round2_responses_;
  }
  if (round2_requests_.empty()) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Requests must be completed before MakeRound2Responses");
  }
  if (requests_for_self.size() !=
      mta::ExpectedPairwiseProductMessageCount(peers_.size())) {
    TECDSA_THROW_ARGUMENT(
        "requests_for_self must contain exactly one request per peer/type");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(requests_for_self.size());
  seen_instance_keys.reserve(requests_for_self.size());

  std::vector<SignRound2Response> out;
  out.reserve(requests_for_self.size());
  for (const SignRound2Request& request : requests_for_self) {
    if (!IsPeer(peers_, request.from)) {
      TECDSA_THROW_ARGUMENT("round2 request sender is not a peer");
    }
    if (request.to != cfg_.self_id) {
      TECDSA_THROW_ARGUMENT("round2 request must target self");
    }
    if (request.instance_id.size() != mta::kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("round2 request instance id has invalid length");
    }

    const std::string request_key =
        mta::MakeResponderRequestKey(request.from, ToCoreMtaType(request.type));
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 request for sender/type");
    }

    const std::string instance_key = mta::BytesToKey(request.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 request instance id");
    }

    const auto self_aux_it =
        cfg_.public_keygen_data.all_aux_rsa_params.find(cfg_.self_id);
    if (self_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing responder auxiliary parameters");
    }

    const Scalar witness =
        (request.type == MtaType::kTimesGamma) ? local_gamma_i_ : local_w_i_;
    const auto initiator_aux_it =
        cfg_.public_keygen_data.all_aux_rsa_params.find(request.from);
    if (initiator_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
      TECDSA_THROW_LOGIC("missing initiator auxiliary parameters");
    }
    const auto consume_result = phase2_session_.ConsumeRequest(
        ToCoreRequest(request),
        {.initiator_modulus_n =
             cfg_.public_keygen_data.all_paillier_public.at(request.from).n,
         .responder_aux = &self_aux_it->second,
         .initiator_aux = &initiator_aux_it->second,
         .responder_secret = witness,
         .public_witness_point =
             (request.type == MtaType::kTimesW)
                 ? std::optional<ECPoint>(w_points_.at(cfg_.self_id))
                 : std::nullopt});

    const Scalar responder_share = consume_result.responder_share;
    if (request.type == MtaType::kTimesGamma) {
      phase2_mta_responder_sum_ = phase2_mta_responder_sum_ + responder_share;
    } else {
      phase2_mtawc_responder_sum_ =
          phase2_mtawc_responder_sum_ + responder_share;
    }
    out.push_back(ToProtocolResponse(consume_result.response));
  }

  round2_responses_ = out;
  return *round2_responses_;
}

SignRound3Msg SignParty::MakeRound3(
    const std::vector<SignRound2Response>& responses_for_self) {
  if (round3_.has_value()) {
    return *round3_;
  }
  if (!round2_responses_.has_value()) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Responses must be completed before MakeRound3");
  }
  if (responses_for_self.size() != phase2_session_.initiator_instance_count()) {
    TECDSA_THROW_ARGUMENT(
        "responses_for_self must contain exactly one response per request");
  }

  std::unordered_set<std::string> seen_request_keys;
  std::unordered_set<std::string> seen_instance_keys;
  seen_request_keys.reserve(responses_for_self.size());
  seen_instance_keys.reserve(responses_for_self.size());

  const auto self_aux_it =
      cfg_.public_keygen_data.all_aux_rsa_params.find(cfg_.self_id);
  if (self_aux_it == cfg_.public_keygen_data.all_aux_rsa_params.end()) {
    TECDSA_THROW_LOGIC("missing initiator auxiliary parameters");
  }

  for (const SignRound2Response& response : responses_for_self) {
    if (!IsPeer(peers_, response.from)) {
      TECDSA_THROW_ARGUMENT("round2 response sender is not a peer");
    }
    if (response.to != cfg_.self_id) {
      TECDSA_THROW_ARGUMENT("round2 response must target self");
    }
    if (response.instance_id.size() != mta::kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("round2 response instance id has invalid length");
    }

    const std::string instance_key = mta::BytesToKey(response.instance_id);
    if (!seen_instance_keys.insert(instance_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 response instance id");
    }

    const auto& instance =
        phase2_session_.GetInitiatorInstance(response.instance_id);
    if (instance.responder != response.from) {
      TECDSA_THROW_ARGUMENT("round2 response sender mismatch");
    }
    if (instance.type != ToCoreMtaType(response.type)) {
      TECDSA_THROW_ARGUMENT("round2 response type mismatch");
    }

    const std::string request_key =
        mta::MakeResponderRequestKey(response.from,
                                     ToCoreMtaType(response.type));
    if (!seen_request_keys.insert(request_key).second) {
      TECDSA_THROW_ARGUMENT("duplicate round2 response for sender/type");
    }
    const auto consume_result = phase2_session_.ConsumeResponse(
        ToCoreResponse(response),
        {.initiator_paillier = cfg_.local_key_share.paillier.get(),
         .initiator_aux = &self_aux_it->second,
         .public_witness_point =
             (response.type == MtaType::kTimesW)
                 ? std::optional<ECPoint>(w_points_.at(response.from))
                 : std::nullopt});
    const Scalar initiator_share = consume_result.initiator_share;
    if (response.type == MtaType::kTimesGamma) {
      phase2_mta_initiator_sum_ = phase2_mta_initiator_sum_ + initiator_share;
    } else {
      phase2_mtawc_initiator_sum_ =
          phase2_mtawc_initiator_sum_ + initiator_share;
    }
  }

  local_delta_i_ = (local_k_i_ * local_gamma_i_) + phase2_mta_initiator_sum_ +
                   phase2_mta_responder_sum_;
  local_sigma_i_ = (local_k_i_ * local_w_i_) + phase2_mtawc_initiator_sum_ +
                   phase2_mtawc_responder_sum_;
  round3_ = SignRound3Msg{.delta_i = local_delta_i_};
  return *round3_;
}

SignRound4Msg SignParty::MakeRound4(const PeerMap<SignRound3Msg>& peer_round3) {
  if (round4_.has_value()) {
    return *round4_;
  }
  if (!round3_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound3 must be completed before MakeRound4");
  }

  core::participant::RequireExactlyPeers(peer_round3, cfg_.participants,
                                         cfg_.self_id, "peer_round3");
  Scalar delta = local_delta_i_;
  for (PartyIndex peer : peers_) {
    delta = delta + peer_round3.at(peer).delta_i;
  }
  if (delta.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated delta is zero");
  }

  const std::optional<Scalar> delta_inv = InvertScalar(delta);
  if (!delta_inv.has_value()) {
    TECDSA_THROW_ARGUMENT("failed to invert aggregated delta");
  }
  delta_inv_ = *delta_inv;

  round4_ = SignRound4Msg{
      .gamma_i = local_Gamma_i_,
      .randomness = local_round1_randomness_,
      .gamma_proof = core::proof::BuildSchnorrProof(
          core::DefaultEcdsaSuite(), cfg_.session_id, cfg_.self_id,
          local_Gamma_i_, local_gamma_i_),
  };
  return *round4_;
}

SignRound5AMsg SignParty::MakeRound5A(
    const PeerMap<SignRound4Msg>& peer_round4) {
  if (round5a_.has_value()) {
    return *round5a_;
  }
  if (!round4_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound4 must be completed before MakeRound5A");
  }

  core::participant::RequireExactlyPeers(peer_round4, cfg_.participants,
                                         cfg_.self_id, "peer_round4");
  std::vector<ECPoint> gamma_points;
  gamma_points.reserve(cfg_.participants.size());
  gamma_points.push_back(local_Gamma_i_);

  for (PartyIndex peer : peers_) {
    const SignRound4Msg& msg = peer_round4.at(peer);
    const auto commitment_it = phase1_commitments_.find(peer);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round1 commitment for peer");
    }
    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), kPhase1CommitDomain,
            msg.gamma_i.ToCompressedBytes(), msg.randomness,
            commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round4 gamma opening does not match round1 commitment");
    }
    if (!core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, peer, msg.gamma_i,
                                         msg.gamma_proof)) {
      TECDSA_THROW_ARGUMENT("round4 gamma Schnorr proof verification failed");
    }
    gamma_points.push_back(msg.gamma_i);
  }

  try {
    gamma_ = core::vss::SumPointsOrThrow(gamma_points);
    R_ = gamma_.Mul(delta_inv_);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute R in round5A: ") +
                          ex.what());
  }
  r_ = verify::XCoordinateModQ(R_);
  if (r_.value() == 0) {
    TECDSA_THROW_ARGUMENT("computed r is zero");
  }

  EnsureRound5ASharePrepared();
  return *round5a_;
}

SignRound5BMsg SignParty::MakeRound5B(
    const PeerMap<SignRound5AMsg>& peer_round5a) {
  if (round5b_.has_value()) {
    return *round5b_;
  }
  if (!round5a_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5A must be completed before MakeRound5B");
  }

  core::participant::RequireExactlyPeers(peer_round5a, cfg_.participants,
                                         cfg_.self_id, "peer_round5a");
  for (PartyIndex peer : peers_) {
    ValidateCommitmentOrThrow(peer_round5a.at(peer).commitment,
                              "sign round5A commitment");
    phase5a_commitments_[peer] = peer_round5a.at(peer).commitment;
  }

  round5b_ = SignRound5BMsg{
      .V_i = local_V_i_,
      .A_i = local_A_i_,
      .randomness = local_round5a_randomness_,
      .a_schnorr_proof = core::proof::BuildSchnorrProof(
          core::DefaultEcdsaSuite(), cfg_.session_id, cfg_.self_id, local_A_i_,
          local_rho_i_),
      .v_relation_proof =
          relation::BuildVRelationProof(cfg_.session_id, cfg_.self_id, R_,
                                        local_V_i_, local_s_i_, local_l_i_),
  };
  return *round5b_;
}

SignRound5CMsg SignParty::MakeRound5C(
    const PeerMap<SignRound5BMsg>& peer_round5b) {
  if (round5c_.has_value()) {
    return *round5c_;
  }
  if (!round5b_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5B must be completed before MakeRound5C");
  }

  core::participant::RequireExactlyPeers(peer_round5b, cfg_.participants,
                                         cfg_.self_id, "peer_round5b");

  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(cfg_.participants.size());
  a_points.reserve(cfg_.participants.size());
  v_points.push_back(local_V_i_);
  a_points.push_back(local_A_i_);

  for (PartyIndex peer : peers_) {
    const SignRound5BMsg& msg = peer_round5b.at(peer);
    const auto commitment_it = phase5a_commitments_.find(peer);
    if (commitment_it == phase5a_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round5A commitment for peer");
    }

    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), kPhase5ACommitDomain,
            relation::SerializePointPair(msg.V_i, msg.A_i),
            msg.randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5B opening does not match round5A commitment");
    }
    if (!core::proof::VerifySchnorrProof(core::DefaultEcdsaSuite(),
                                         cfg_.session_id, peer, msg.A_i,
                                         msg.a_schnorr_proof)) {
      TECDSA_THROW_ARGUMENT("round5B A_i Schnorr proof verification failed");
    }
    if (!relation::VerifyVRelationProof(cfg_.session_id, peer, R_, msg.V_i,
                                        msg.v_relation_proof)) {
      TECDSA_THROW_ARGUMENT("round5B V relation proof verification failed");
    }

    v_points.push_back(msg.V_i);
    a_points.push_back(msg.A_i);
  }

  try {
    V_ = core::vss::SumPointsOrThrow(v_points);
    A_ = core::vss::SumPointsOrThrow(a_points);
    if (message_scalar_.value() != 0) {
      V_ = V_.Add(ECPoint::GeneratorMultiply(Scalar() - message_scalar_));
    }
    V_ = V_.Add(cfg_.public_keygen_data.y.Mul(Scalar() - r_));
    local_U_i_ = V_.Mul(local_rho_i_);
    local_T_i_ = A_.Mul(local_l_i_);
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to compute round5C values: ") +
                          ex.what());
  }

  const core::commitment::CommitmentResult commit =
      core::commitment::CommitMessage(
          core::DefaultEcdsaSuite(),
          kPhase5CCommitDomain,
          relation::SerializePointPair(local_U_i_, local_T_i_));
  local_round5c_randomness_ = commit.randomness;
  round5c_ = SignRound5CMsg{.commitment = commit.commitment};
  phase5c_commitments_[cfg_.self_id] = round5c_->commitment;
  return *round5c_;
}

SignRound5DMsg SignParty::MakeRound5D(
    const PeerMap<SignRound5CMsg>& peer_round5c) {
  if (round5d_.has_value()) {
    return *round5d_;
  }
  if (!round5c_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5C must be completed before MakeRound5D");
  }

  core::participant::RequireExactlyPeers(peer_round5c, cfg_.participants,
                                         cfg_.self_id, "peer_round5c");
  for (PartyIndex peer : peers_) {
    ValidateCommitmentOrThrow(peer_round5c.at(peer).commitment,
                              "sign round5C commitment");
    phase5c_commitments_[peer] = peer_round5c.at(peer).commitment;
  }

  round5d_ = SignRound5DMsg{
      .U_i = local_U_i_,
      .T_i = local_T_i_,
      .randomness = local_round5c_randomness_,
  };
  return *round5d_;
}

Scalar SignParty::RevealRound5E(const PeerMap<SignRound5DMsg>& peer_round5d) {
  if (round5e_.has_value()) {
    return *round5e_;
  }
  if (!round5d_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound5D must be completed before RevealRound5E");
  }

  core::participant::RequireExactlyPeers(peer_round5d, cfg_.participants,
                                         cfg_.self_id, "peer_round5d");
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(cfg_.participants.size());
  t_points.reserve(cfg_.participants.size());
  u_points.push_back(local_U_i_);
  t_points.push_back(local_T_i_);

  for (PartyIndex peer : peers_) {
    const SignRound5DMsg& msg = peer_round5d.at(peer);
    const auto commitment_it = phase5c_commitments_.find(peer);
    if (commitment_it == phase5c_commitments_.end()) {
      TECDSA_THROW_LOGIC("missing stored round5C commitment for peer");
    }
    if (!core::commitment::VerifyCommitment(
            core::DefaultEcdsaSuite(), kPhase5CCommitDomain,
            relation::SerializePointPair(msg.U_i, msg.T_i),
            msg.randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT(
          "round5D opening does not match round5C commitment");
    }
    u_points.push_back(msg.U_i);
    t_points.push_back(msg.T_i);
  }

  try {
    const ECPoint sum_u = core::vss::SumPointsOrThrow(u_points);
    const ECPoint sum_t = core::vss::SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      TECDSA_THROW_ARGUMENT("round5D consistency check failed");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate round5D: ") +
                          ex.what());
  }

  round5e_ = local_s_i_;
  return *round5e_;
}

Signature SignParty::Finalize(const PeerMap<Scalar>& peer_round5e) {
  if (signature_.has_value()) {
    return *signature_;
  }
  if (!round5e_.has_value()) {
    TECDSA_THROW_LOGIC("RevealRound5E must be completed before Finalize");
  }

  core::participant::RequireExactlyPeers(peer_round5e, cfg_.participants,
                                         cfg_.self_id, "peer_round5e");
  Scalar s = *round5e_;
  for (PartyIndex peer : peers_) {
    s = s + peer_round5e.at(peer);
  }
  if (s.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated signature scalar s is zero");
  }

  Scalar canonical_s = s;
  if (verify::IsHighScalar(canonical_s)) {
    canonical_s = Scalar() - canonical_s;
  }
  if (!verify::VerifyEcdsaSignatureMath(cfg_.public_keygen_data.y, cfg_.msg32,
                                        r_, canonical_s)) {
    TECDSA_THROW_ARGUMENT("final ECDSA signature verification failed");
  }

  signature_ = Signature{
      .r = r_,
      .s = canonical_s,
      .R = R_,
  };
  return *signature_;
}

}  // namespace tecdsa::ecdsa::sign
