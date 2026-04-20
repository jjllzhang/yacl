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

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/presign/offline.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/sign/online.h"

namespace tecdsa::sm2::test {

using keygen::KeygenOutput;
using keygen::KeygenParty;
using keygen::KeygenRound1Msg;
using keygen::KeygenRound2Broadcast;
using keygen::KeygenRound3Request;
using keygen::KeygenRound3Response;
using keygen::KeygenRound4Msg;
using keygen::PeerMap;
using presign::OfflineParty;
using presign::OfflineState;
using presign::Round1Msg;
using presign::Round2Request;
using presign::Round2Response;
using presign::Round3Msg;
using sign::OnlineParty;
using verify::Signature;

using KeygenOutputs = std::unordered_map<PartyIndex, KeygenOutput>;
using KeygenPartyMap = std::unordered_map<PartyIndex, KeygenParty>;
using OfflinePartyMap = std::unordered_map<PartyIndex, OfflineParty>;
using OfflineStates = std::unordered_map<PartyIndex, OfflineState>;
using OnlinePartyMap = std::unordered_map<PartyIndex, OnlineParty>;
using KeygenRound2Shares = std::unordered_map<PartyIndex, PeerMap<Scalar>>;

void Expect(bool condition, const std::string& message);
void ExpectThrow(const std::function<void()>& fn, const std::string& message);

std::vector<PartyIndex> BuildParticipants(uint32_t n);

KeygenPartyMap BuildKeygenParties(uint32_t n, uint32_t t, const Bytes& session_id,
                                  const Bytes& signer_id);
KeygenOutputs RunKeygen(uint32_t n, uint32_t t, const Bytes& session_id,
                        const Bytes& signer_id);

OfflinePartyMap BuildOfflineParties(const std::vector<PartyIndex>& signers,
                                    const KeygenOutputs& keygen_outputs,
                                    const Bytes& session_id);
OfflineStates RunOffline(const std::vector<PartyIndex>& signers,
                         const KeygenOutputs& keygen_outputs,
                         const Bytes& session_id);

OnlinePartyMap BuildOnlineParties(const std::vector<PartyIndex>& signers,
                                  const KeygenOutputs& keygen_outputs,
                                  const OfflineStates& offline_states,
                                  const Bytes& session_id, const Bytes& message);
std::unordered_map<PartyIndex, Signature> RunOnline(
    const std::vector<PartyIndex>& signers, const KeygenOutputs& keygen_outputs,
    const OfflineStates& offline_states, const Bytes& session_id,
    const Bytes& message);

template <typename T>
PeerMap<T> BuildPeerMapFor(const std::vector<PartyIndex>& parties,
                           PartyIndex self_id,
                           const std::unordered_map<PartyIndex, T>& all_msgs) {
  PeerMap<T> out;
  for (PartyIndex peer : parties) {
    if (peer != self_id) {
      out.emplace(peer, all_msgs.at(peer));
    }
  }
  return out;
}

}  // namespace tecdsa::sm2::test
