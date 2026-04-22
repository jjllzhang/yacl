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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/presign/offline.h"

#include <exception>
#include <unordered_set>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/detection/evidence.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_group.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_linear.h"

namespace tecdsa::sm2::presign {
namespace {

namespace mta = tecdsa::core::mta;

constexpr char kPhase1CommitDomain[] = "SM2/offline/phase1";

void RequireExactlyOneRequestPerPeer(const std::vector<Round2Request>& requests,
                                     const std::vector<PartyIndex>& peers,
                                     PartyIndex self_id) {
  if (requests.size() != peers.size()) {
    TECDSA_THROW_ARGUMENT(
        "SM2 offline requests_for_self must contain exactly one request per peer");
  }
  std::unordered_set<PartyIndex> senders;
  senders.reserve(requests.size());
  for (const auto& request : requests) {
    if (request.to != self_id || request.type != mta::MtaType::kMta) {
      TECDSA_THROW_ARGUMENT("invalid SM2 offline request envelope");
    }
    if (!senders.insert(request.from).second) {
      TECDSA_THROW_ARGUMENT("duplicate SM2 offline request sender");
    }
  }
}

void RequireExactlyOneResponsePerPeer(
    const std::vector<Round2Response>& responses,
    const std::vector<PartyIndex>& peers, PartyIndex self_id) {
  if (responses.size() != peers.size()) {
    TECDSA_THROW_ARGUMENT(
        "SM2 offline responses_for_self must contain exactly one response per peer");
  }
  std::unordered_set<PartyIndex> responders;
  responders.reserve(responses.size());
  for (const auto& response : responses) {
    if (response.to != self_id || response.type != mta::MtaType::kMta) {
      TECDSA_THROW_ARGUMENT("invalid SM2 offline response envelope");
    }
    if (!responders.insert(response.from).second) {
      TECDSA_THROW_ARGUMENT("duplicate SM2 offline response sender");
    }
  }
}

}  // namespace

OfflineParty::OfflineParty(OfflineConfig cfg)
    : cfg_(std::move(cfg)),
      delta_session_({.session_id = cfg_.session_id,
                      .self_id = cfg_.self_id,
                      .suite = core::DefaultSm2Suite(),
                      .group = internal::Sm2Group(),
                      .proof_backend = proofs::BuildSm2ProofBackend()}) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "sm2::presign::OfflineParty");
  peers_ = participant_set.peers;
  if (cfg_.local_key_share.z_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local z share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  local_k_i_ = internal::Sm2Zero();
  delta_initiator_sum_ = internal::Sm2Zero();
  delta_responder_sum_ = internal::Sm2Zero();
  local_delta_i_ = internal::Sm2Zero();
}

const OfflineConfig& OfflineParty::config() const { return cfg_; }

void OfflineParty::EnsureRound1Prepared() {
  if (round1_.has_value()) {
    return;
  }

  local_k_i_ = internal::RandomNonZeroSm2Scalar();
  local_K_i_ = ECPoint::GeneratorMultiply(local_k_i_);
  const auto commit = core::commitment::CommitMessage(
      core::DefaultSm2Suite(), kPhase1CommitDomain,
      local_K_i_.ToCompressedBytes());
  local_randomness_ = commit.randomness;
  round1_ = Round1Msg{.commitment = commit.commitment};
  phase1_commitments_[cfg_.self_id] = commit.commitment;
}

Round1Msg OfflineParty::MakeRound1() {
  EnsureRound1Prepared();
  return *round1_;
}

std::vector<Round2Request> OfflineParty::MakeRound2Requests(
    const PeerMap<Round1Msg>& peer_round1) {
  if (!round2_requests_.empty()) {
    return round2_requests_;
  }

  EnsureRound1Prepared();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");
  for (PartyIndex peer : peers_) {
    phase1_commitments_[peer] = peer_round1.at(peer).commitment;
    round2_requests_.push_back(delta_session_.CreateRequest({
        .responder_id = peer,
        .type = mta::MtaType::kMta,
        .initiator_paillier = cfg_.local_key_share.paillier.get(),
        .responder_aux = &cfg_.public_keygen_data.all_aux_rsa_params.at(peer),
        .initiator_secret = local_k_i_,
    }));
  }
  return round2_requests_;
}

std::vector<Round2Response> OfflineParty::MakeRound2Responses(
    const std::vector<Round2Request>& requests_for_self) {
  const auto result = TryMakeRound2Responses(requests_for_self);
  if (!result.ok()) {
    TECDSA_THROW_ARGUMENT(result.abort->reason);
  }
  return *result.value;
}

detection::DetectionResult<std::vector<Round2Response>>
OfflineParty::TryMakeRound2Responses(
    const std::vector<Round2Request>& requests_for_self) {
  if (round2_responses_.has_value()) {
    return {.value = *round2_responses_, .abort = std::nullopt};
  }
  if (round2_requests_.empty()) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Requests must be completed before MakeRound2Responses");
  }

  try {
    RequireExactlyOneRequestPerPeer(requests_for_self, peers_, cfg_.self_id);
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kMtaProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }

  std::vector<Round2Response> out;
  out.reserve(requests_for_self.size());
  Scalar responder_sum = delta_responder_sum_;
  for (const auto& request : requests_for_self) {
    try {
      const auto consume = delta_session_.ConsumeRequest(
          request,
          {.initiator_modulus_n =
               cfg_.public_keygen_data.all_paillier_public.at(request.from).n,
           .responder_aux =
               &cfg_.public_keygen_data.all_aux_rsa_params.at(cfg_.self_id),
           .initiator_aux =
               &cfg_.public_keygen_data.all_aux_rsa_params.at(request.from),
           .responder_secret = cfg_.local_key_share.z_i,
           .public_witness_point = std::nullopt});
      responder_sum = responder_sum + consume.responder_share;
      out.push_back(consume.response);
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeIdentifiableAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kMtaProof, cfg_.session_id,
                  cfg_.self_id, request.from, ex.what(), request.instance_id)};
    }
  }
  delta_responder_sum_ = responder_sum;
  round2_responses_ = out;
  return {.value = *round2_responses_, .abort = std::nullopt};
}

Round3Msg OfflineParty::MakeRound3(
    const std::vector<Round2Response>& responses_for_self) {
  if (round3_.has_value()) {
    return *round3_;
  }
  if (!round2_responses_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound2Responses must be completed before MakeRound3");
  }

  RequireExactlyOneResponsePerPeer(responses_for_self, peers_, cfg_.self_id);
  for (const auto& response : responses_for_self) {
    const auto consume = delta_session_.ConsumeResponse(
        response,
        {.initiator_paillier = cfg_.local_key_share.paillier.get(),
         .initiator_aux = &cfg_.public_keygen_data.all_aux_rsa_params.at(cfg_.self_id),
         .public_witness_point = std::nullopt});
    delta_initiator_sum_ = delta_initiator_sum_ + consume.initiator_share;
  }

  local_delta_i_ = (local_k_i_ * cfg_.local_key_share.z_i) + delta_initiator_sum_ +
                   delta_responder_sum_;
  round3_ = Round3Msg{
      .K_i = local_K_i_,
      .randomness = local_randomness_,
      .k_proof =
          proofs::BuildPiGroupProof(cfg_.session_id, cfg_.self_id, local_K_i_,
                                    local_k_i_),
      .delta_i = local_delta_i_,
  };
  return *round3_;
}

OfflineState OfflineParty::Finalize(const PeerMap<Round3Msg>& peer_round3) {
  const auto result = TryFinalize(peer_round3);
  if (!result.ok()) {
    TECDSA_THROW_ARGUMENT(result.abort->reason);
  }
  return *result.value;
}

detection::DetectionResult<OfflineState> OfflineParty::TryFinalize(
    const PeerMap<Round3Msg>& peer_round3) {
  if (offline_.has_value()) {
    return {.value = *offline_, .abort = std::nullopt};
  }
  if (!round3_.has_value()) {
    TECDSA_THROW_LOGIC("MakeRound3 must be completed before Finalize");
  }

  try {
    core::participant::RequireExactlyPeers(peer_round3, cfg_.participants,
                                           cfg_.self_id, "peer_round3");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kNonceProof, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }
  std::vector<ECPoint> k_points;
  k_points.reserve(cfg_.participants.size());
  k_points.push_back(local_K_i_);
  for (PartyIndex peer : peers_) {
    const auto& msg = peer_round3.at(peer);
    const auto commitment_it = phase1_commitments_.find(peer);
    if (commitment_it == phase1_commitments_.end()) {
      return {.value = std::nullopt,
              .abort = detection::MakeUnattributedAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kCommitment, cfg_.session_id,
                  cfg_.self_id, "missing phase1 commitment for peer")};
    }
    try {
      if (!core::commitment::VerifyCommitment(
              core::DefaultSm2Suite(), kPhase1CommitDomain,
              msg.K_i.ToCompressedBytes(), msg.randomness,
              commitment_it->second)) {
        return {.value = std::nullopt,
                .abort = detection::MakeIdentifiableAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kCommitment, cfg_.session_id,
                    cfg_.self_id, peer,
                    "SM2 offline nonce opening verification failed")};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeIdentifiableAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kCommitment, cfg_.session_id,
                  cfg_.self_id, peer, ex.what())};
    }
    try {
      if (!proofs::VerifyPiGroupProof(cfg_.session_id, peer, msg.K_i,
                                      msg.k_proof)) {
        return {.value = std::nullopt,
                .abort = detection::MakeIdentifiableAbort(
                    detection::AbortStage::kOffline,
                    detection::EvidenceKind::kNonceProof, cfg_.session_id,
                    cfg_.self_id, peer,
                    "SM2 offline nonce pi_group verification failed")};
      }
    } catch (const std::exception& ex) {
      return {.value = std::nullopt,
              .abort = detection::MakeIdentifiableAbort(
                  detection::AbortStage::kOffline,
                  detection::EvidenceKind::kNonceProof, cfg_.session_id,
                  cfg_.self_id, peer, ex.what())};
    }
    k_points.push_back(msg.K_i);
  }

  try {
    offline_ = OfflineState{
        .delta_i = local_delta_i_,
        .R = internal::SumPointsOrThrow(k_points),
    };
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOffline,
                detection::EvidenceKind::kNonceProof, cfg_.session_id,
                cfg_.self_id,
                std::string("failed to finalize SM2 offline presign: ") +
                    ex.what())};
  }
  return {.value = *offline_, .abort = std::nullopt};
}

}  // namespace tecdsa::sm2::presign
