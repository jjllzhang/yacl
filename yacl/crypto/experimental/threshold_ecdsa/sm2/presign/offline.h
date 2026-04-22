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

#include "yacl/crypto/experimental/threshold_ecdsa/common/ids.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/pi_group.h"

namespace tecdsa::sm2::presign {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

struct OfflineConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  keygen::LocalKeyShare local_key_share;
  keygen::PublicKeygenData public_keygen_data;
};

struct Round1Msg {
  Bytes commitment;
};

using Round2Request = tecdsa::core::mta::PairwiseProductRequest;
using Round2Response = tecdsa::core::mta::PairwiseProductResponse;

struct Round3Msg {
  ECPoint K_i;
  Bytes randomness;
  proofs::PiGroupProof k_proof;
  Scalar delta_i;
};

struct OfflineState {
  Scalar delta_i;
  ECPoint R;
};

class OfflineParty {
 public:
  explicit OfflineParty(OfflineConfig cfg);

  const OfflineConfig& config() const;

  Round1Msg MakeRound1();
  std::vector<Round2Request> MakeRound2Requests(
      const PeerMap<Round1Msg>& peer_round1);
  std::vector<Round2Response> MakeRound2Responses(
      const std::vector<Round2Request>& requests_for_self);
  Round3Msg MakeRound3(const std::vector<Round2Response>& responses_for_self);
  OfflineState Finalize(const PeerMap<Round3Msg>& peer_round3);

 private:
  void EnsureRound1Prepared();

  OfflineConfig cfg_;
  std::vector<PartyIndex> peers_;
  Scalar local_k_i_;
  ECPoint local_K_i_;
  Bytes local_randomness_;
  PeerMap<Bytes> phase1_commitments_;
  tecdsa::core::mta::PairwiseProductSession delta_session_;
  std::vector<Round2Request> round2_requests_;
  std::optional<std::vector<Round2Response>> round2_responses_;
  Scalar delta_initiator_sum_;
  Scalar delta_responder_sum_;
  Scalar local_delta_i_;
  std::optional<Round1Msg> round1_;
  std::optional<Round3Msg> round3_;
  std::optional<OfflineState> offline_;
};

}  // namespace tecdsa::sm2::presign
