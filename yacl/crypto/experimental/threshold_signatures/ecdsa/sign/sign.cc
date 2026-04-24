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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/sign.h"

#include <array>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/commitment/commitment.h"
#include "yacl/crypto/experimental/threshold_signatures/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_signatures/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_signatures/core/proof/schnorr.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/dealerless_dkg.h"
#include "yacl/crypto/experimental/threshold_signatures/core/vss/feldman.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/relation_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/verify/verify.h"

namespace tecdsa::ecdsa::sign {
namespace {

namespace mta = tecdsa::core::mta;
namespace paillier = tecdsa::core::paillier;
namespace keygen = tecdsa::ecdsa::keygen;
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

void ValidateCommitmentOrThrow(const Bytes& commitment,
                               const char* field_name) {
  if (commitment.size() != kCommitmentLen) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) +
                          " must be exactly 32 bytes");
  }
}

std::optional<Scalar> InvertScalar(const Scalar& scalar) {
  if (scalar.value() == 0) {
    return std::nullopt;
  }
  try {
    return scalar.InverseModQ();
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

const keygen::AuxRsaParams& AuxFor(const PublicKeygenData& public_data,
                                   PartyIndex party, const char* context) {
  const auto it = public_data.all_aux_rsa_params.find(party);
  if (it == public_data.all_aux_rsa_params.end()) {
    TECDSA_THROW_LOGIC(std::string("missing ") + context +
                       " auxiliary parameters");
  }
  return it->second;
}

std::optional<ECPoint> PublicWitnessFor(MtaType type,
                                        const PeerMap<ECPoint>& witnesses,
                                        PartyIndex party) {
  if (type == MtaType::kTimesW) {
    return witnesses.at(party);
  }
  return std::nullopt;
}

template <typename Msg>
void StoreCommitments(const PeerMap<Msg>& messages,
                      std::span<const PartyIndex> peers,
                      PeerMap<Bytes>* commitments, const char* field_name) {
  for (PartyIndex peer : peers) {
    const Bytes& commitment = messages.at(peer).commitment;
    ValidateCommitmentOrThrow(commitment, field_name);
    (*commitments)[peer] = commitment;
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
  if (cfg_.participants.size() !=
      static_cast<size_t>(cfg_.public_keygen_data.threshold) + 1) {
    TECDSA_THROW_ARGUMENT("signer set size must equal threshold + 1");
  }
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
  if (round1_done_) {
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
  phase1_commitments_[cfg_.self_id] = commit.commitment;
  round1_done_ = true;
}

void SignParty::EnsureRound5ASharePrepared() {
  if (round5a_done_) {
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
  phase5a_commitments_[cfg_.self_id] = commit.commitment;
  round5a_done_ = true;
}

SignRound1Msg SignParty::MakeRound1() {
  if (round1_done_) {
    TECDSA_THROW_LOGIC("MakeRound1 must not be called twice");
  }
  EnsurePhase1Prepared();
  return SignRound1Msg{.commitment = phase1_commitments_.at(cfg_.self_id)};
}

std::vector<SignRound2Request> SignParty::MakeRound2Requests(
    const PeerMap<SignRound1Msg>& peer_round1) {
  if (round2_requests_done_) {
    TECDSA_THROW_LOGIC("MakeRound2Requests must not be called twice");
  }

  EnsurePhase1Prepared();
  core::participant::RequireExactlyPeers(peer_round1, cfg_.participants,
                                         cfg_.self_id, "peer_round1");
  StoreCommitments(peer_round1, peers_, &phase1_commitments_,
                   "sign round1 commitment");

  std::vector<SignRound2Request> out;
  out.reserve(peers_.size() * 2);
  for (PartyIndex peer : peers_) {
    const auto& peer_aux = AuxFor(cfg_.public_keygen_data, peer, "peer");

    for (MtaType type : {MtaType::kTimesGamma, MtaType::kTimesW}) {
      const auto request = phase2_session_.CreateRequest({
          .responder_id = peer,
          .type = ToCoreMtaType(type),
          .initiator_paillier = cfg_.local_key_share.paillier.get(),
          .responder_aux = &peer_aux,
          .initiator_secret = local_k_i_,
      });
      out.push_back(ToProtocolRequest(request));
    }
  }

  round2_requests_done_ = true;
  return out;
}

std::vector<SignRound2Response> SignParty::MakeRound2Responses(
    const std::vector<SignRound2Request>& requests_for_self) {
  if (round2_responses_done_) {
    TECDSA_THROW_LOGIC("MakeRound2Responses must not be called twice");
  }
  if (!round2_requests_done_) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Requests must be completed before MakeRound2Responses");
  }
  const std::array<mta::MtaType, 2> expected_types = {
      mta::MtaType::kMta, mta::MtaType::kMtAwc};
  mta::RequireExactlyOneRequestPerPeerAndType(
      requests_for_self, peers_, cfg_.self_id, expected_types, ToCoreRequest,
      "round2 request");

  std::vector<SignRound2Response> out;
  out.reserve(requests_for_self.size());
  const auto& self_aux = AuxFor(cfg_.public_keygen_data, cfg_.self_id,
                                "responder");
  for (const SignRound2Request& request : requests_for_self) {
    const Scalar witness =
        (request.type == MtaType::kTimesGamma) ? local_gamma_i_ : local_w_i_;
    const auto& initiator_aux =
        AuxFor(cfg_.public_keygen_data, request.from, "initiator");
    const auto consume_result = phase2_session_.ConsumeRequest(
        ToCoreRequest(request),
        {.initiator_modulus_n =
             cfg_.public_keygen_data.all_paillier_public.at(request.from).n,
         .responder_aux = &self_aux,
         .initiator_aux = &initiator_aux,
         .responder_secret = witness,
         .public_witness_point =
             PublicWitnessFor(request.type, w_points_, cfg_.self_id)});

    const Scalar responder_share = consume_result.responder_share;
    if (request.type == MtaType::kTimesGamma) {
      phase2_mta_responder_sum_ = phase2_mta_responder_sum_ + responder_share;
    } else {
      phase2_mtawc_responder_sum_ =
          phase2_mtawc_responder_sum_ + responder_share;
    }
    out.push_back(ToProtocolResponse(consume_result.response));
  }

  round2_responses_done_ = true;
  return out;
}

SignRound3Msg SignParty::MakeRound3(
    const std::vector<SignRound2Response>& responses_for_self) {
  if (round3_done_) {
    TECDSA_THROW_LOGIC("MakeRound3 must not be called twice");
  }
  if (!round2_responses_done_) {
    TECDSA_THROW_LOGIC(
        "MakeRound2Responses must be completed before MakeRound3");
  }
  mta::RequireExactlyOneResponsePerInitiatorInstance(
      responses_for_self, peers_, peers_.size() * 2, cfg_.self_id,
      phase2_session_, ToCoreResponse, "round2 response");

  const auto& self_aux = AuxFor(cfg_.public_keygen_data, cfg_.self_id,
                                "initiator");

  for (const SignRound2Response& response : responses_for_self) {
    const auto consume_result = phase2_session_.ConsumeResponse(
        ToCoreResponse(response),
        {.initiator_paillier = cfg_.local_key_share.paillier.get(),
         .initiator_aux = &self_aux,
         .public_witness_point =
             PublicWitnessFor(response.type, w_points_, response.from)});
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
  round3_done_ = true;
  return SignRound3Msg{.delta_i = local_delta_i_};
}

SignRound4Msg SignParty::MakeRound4(const PeerMap<SignRound3Msg>& peer_round3) {
  if (round4_done_) {
    TECDSA_THROW_LOGIC("MakeRound4 must not be called twice");
  }
  if (!round3_done_) {
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

  round4_done_ = true;
  return SignRound4Msg{
      .gamma_i = local_Gamma_i_,
      .randomness = local_round1_randomness_,
      .gamma_proof = core::proof::BuildSchnorrProof(
          core::DefaultEcdsaSuite(), cfg_.session_id, cfg_.self_id,
          local_Gamma_i_, local_gamma_i_),
  };
}

SignRound5AMsg SignParty::MakeRound5A(
    const PeerMap<SignRound4Msg>& peer_round4) {
  if (round5a_done_) {
    TECDSA_THROW_LOGIC("MakeRound5A must not be called twice");
  }
  if (!round4_done_) {
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
  return SignRound5AMsg{.commitment = phase5a_commitments_.at(cfg_.self_id)};
}

SignRound5BMsg SignParty::MakeRound5B(
    const PeerMap<SignRound5AMsg>& peer_round5a) {
  if (round5b_done_) {
    TECDSA_THROW_LOGIC("MakeRound5B must not be called twice");
  }
  if (!round5a_done_) {
    TECDSA_THROW_LOGIC("MakeRound5A must be completed before MakeRound5B");
  }

  core::participant::RequireExactlyPeers(peer_round5a, cfg_.participants,
                                         cfg_.self_id, "peer_round5a");
  StoreCommitments(peer_round5a, peers_, &phase5a_commitments_,
                   "sign round5A commitment");

  round5b_done_ = true;
  return SignRound5BMsg{
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
}

SignRound5CMsg SignParty::MakeRound5C(
    const PeerMap<SignRound5BMsg>& peer_round5b) {
  if (round5c_done_) {
    TECDSA_THROW_LOGIC("MakeRound5C must not be called twice");
  }
  if (!round5b_done_) {
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
  phase5c_commitments_[cfg_.self_id] = commit.commitment;
  round5c_done_ = true;
  return SignRound5CMsg{.commitment = phase5c_commitments_.at(cfg_.self_id)};
}

SignRound5DMsg SignParty::MakeRound5D(
    const PeerMap<SignRound5CMsg>& peer_round5c) {
  if (round5d_done_) {
    TECDSA_THROW_LOGIC("MakeRound5D must not be called twice");
  }
  if (!round5c_done_) {
    TECDSA_THROW_LOGIC("MakeRound5C must be completed before MakeRound5D");
  }

  core::participant::RequireExactlyPeers(peer_round5c, cfg_.participants,
                                         cfg_.self_id, "peer_round5c");
  StoreCommitments(peer_round5c, peers_, &phase5c_commitments_,
                   "sign round5C commitment");

  round5d_done_ = true;
  return SignRound5DMsg{
      .U_i = local_U_i_,
      .T_i = local_T_i_,
      .randomness = local_round5c_randomness_,
  };
}

Scalar SignParty::RevealRound5E(const PeerMap<SignRound5DMsg>& peer_round5d) {
  if (round5e_done_) {
    TECDSA_THROW_LOGIC("RevealRound5E must not be called twice");
  }
  if (!round5d_done_) {
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

  round5e_done_ = true;
  return local_s_i_;
}

Signature SignParty::Finalize(const PeerMap<Scalar>& peer_round5e) {
  if (!round5e_done_) {
    TECDSA_THROW_LOGIC("RevealRound5E must be completed before Finalize");
  }

  core::participant::RequireExactlyPeers(peer_round5e, cfg_.participants,
                                         cfg_.self_id, "peer_round5e");
  Scalar s = local_s_i_;
  for (PartyIndex peer : peers_) {
    s = s + peer_round5e.at(peer);
  }
  if (s.value() == 0) {
    TECDSA_THROW_ARGUMENT("aggregated signature scalar s is zero");
  }

  if (!verify::VerifyEcdsaSignatureMath(cfg_.public_keygen_data.y, cfg_.msg32,
                                        r_, s)) {
    TECDSA_THROW_ARGUMENT("final ECDSA signature verification failed");
  }

  return Signature{
      .r = r_,
      .s = s,
      .R = R_,
  };
}

}  // namespace tecdsa::ecdsa::sign
