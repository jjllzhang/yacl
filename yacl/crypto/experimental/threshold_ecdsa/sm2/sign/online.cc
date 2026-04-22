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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/sign/online.h"

#include <exception>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/participant/participant_set.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/detection/evidence.h"

namespace tecdsa::sm2::sign {

OnlineParty::OnlineParty(OnlineConfig cfg) : cfg_(std::move(cfg)) {
  const auto participant_set = core::participant::BuildParticipantSet(
      cfg_.participants, cfg_.self_id, "sm2::sign::OnlineParty");
  peers_ = participant_set.peers;
  if (cfg_.participants.size() !=
      static_cast<size_t>(cfg_.public_keygen_data.threshold) + 1) {
    TECDSA_THROW_ARGUMENT("online signer set size must equal threshold + 1");
  }
  if (cfg_.local_key_share.z_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local z share must be non-zero");
  }
  const auto lagrange = internal::ComputeLagrangeAtZero(cfg_.participants);
  const auto lambda_it = lagrange.find(cfg_.self_id);
  if (lambda_it == lagrange.end()) {
    TECDSA_THROW_ARGUMENT("missing Lagrange coefficient for signer");
  }
  local_w_i_ = lambda_it->second * cfg_.local_key_share.z_i;
  if (local_w_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("weighted SM2 signing share must be non-zero");
  }
  for (PartyIndex party : cfg_.participants) {
    if (!cfg_.offline.all_W_i.contains(party) || !cfg_.offline.all_T_i.contains(party)) {
      TECDSA_THROW_ARGUMENT("offline state is missing W_i/T_i data for signers");
    }
  }
  if (ECPoint::GeneratorMultiply(local_w_i_) != cfg_.offline.all_W_i.at(cfg_.self_id)) {
    TECDSA_THROW_ARGUMENT("offline W_i does not match local SM2 signing share");
  }

  const Bytes digest = zid::PreprocessMessageDigest(cfg_.local_key_share.binding,
                                                    cfg_.message);
  message_hash_ = Scalar::FromBigEndianModQ(digest, internal::Sm2Group());
  r_ = message_hash_ + internal::XCoordinateModN(cfg_.offline.R);
  if (r_.value() == 0) {
    TECDSA_THROW_ARGUMENT("computed SM2 signature r is zero");
  }
}

const OnlineConfig& OnlineParty::config() const { return cfg_; }

Scalar OnlineParty::MakePartialSignature() {
  if (partial_s_prime_.has_value()) {
    return *partial_s_prime_;
  }

  partial_s_prime_ = (r_ * local_w_i_) + cfg_.offline.delta_i;
  return *partial_s_prime_;
}

verify::Signature OnlineParty::Finalize(const PeerMap<Scalar>& peer_partials) {
  const auto result = TryFinalize(peer_partials);
  if (!result.ok()) {
    TECDSA_THROW_ARGUMENT(result.abort->reason);
  }
  return *result.value;
}

detection::DetectionResult<verify::Signature> OnlineParty::TryFinalize(
    const PeerMap<Scalar>& peer_partials) {
  if (signature_.has_value()) {
    return {.value = *signature_, .abort = std::nullopt};
  }

  try {
    core::participant::RequireExactlyPeers(peer_partials, cfg_.participants,
                                           cfg_.self_id, "peer_partials");
  } catch (const std::exception& ex) {
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOnline,
                detection::EvidenceKind::kPartialSignature, cfg_.session_id,
                cfg_.self_id, ex.what())};
  }

  Scalar s_prime = MakePartialSignature();
  for (PartyIndex peer : peers_) {
    s_prime = s_prime + peer_partials.at(peer);
  }
  const Scalar s = s_prime - r_;
  if (s.value() == 0) {
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOnline,
                detection::EvidenceKind::kPartialSignature, cfg_.session_id,
                cfg_.self_id, "aggregated SM2 signature scalar s is zero")};
  }

  verify::Signature signature{
      .r = r_,
      .s = s,
      .R = cfg_.offline.R,
  };
  if (!verify::VerifySm2SignatureMath(cfg_.public_keygen_data.public_key,
                                      cfg_.local_key_share.binding,
                                      cfg_.message, signature)) {
    std::optional<PartyIndex> culprit;
    size_t mismatch_count = 0;
    auto record_mismatch = [&](PartyIndex party, const Scalar& partial) {
      const ECPoint lhs = ECPoint::GeneratorMultiply(partial);
      const ECPoint rhs =
          cfg_.offline.all_T_i.at(party).Add(cfg_.offline.all_W_i.at(party).Mul(r_));
      if (lhs != rhs) {
        culprit = party;
        ++mismatch_count;
      }
    };
    try {
      record_mismatch(cfg_.self_id, *partial_s_prime_);
      for (PartyIndex peer : peers_) {
        record_mismatch(peer, peer_partials.at(peer));
      }
    } catch (const std::exception&) {
      mismatch_count = 0;
      culprit = std::nullopt;
    }
    if (mismatch_count == 1 && culprit.has_value()) {
      return {.value = std::nullopt,
              .abort = detection::MakeIdentifiableAbort(
                  detection::AbortStage::kOnline,
                  detection::EvidenceKind::kPartialSignature, cfg_.session_id,
                  cfg_.self_id, *culprit,
                  "SM2 partial signature relation check failed")};
    }
    return {.value = std::nullopt,
            .abort = detection::MakeUnattributedAbort(
                detection::AbortStage::kOnline,
                detection::EvidenceKind::kPartialSignature, cfg_.session_id,
                cfg_.self_id, "final SM2 signature verification failed")};
  }

  signature_ = signature;
  return {.value = *signature_, .abort = std::nullopt};
}

}  // namespace tecdsa::sm2::sign
