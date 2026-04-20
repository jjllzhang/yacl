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

#include "yacl/crypto/experimental/threshold_ecdsa/tests/sm2/test_support.h"

#include <stdexcept>

namespace tecdsa::sm2::test {
namespace {

std::unordered_map<PartyIndex, std::vector<KeygenRound3Request>>
GroupKeygenRequestsByRecipient(const std::vector<KeygenRound3Request>& requests) {
  std::unordered_map<PartyIndex, std::vector<KeygenRound3Request>> grouped;
  for (const auto& request : requests) {
    grouped[request.to].push_back(request);
  }
  return grouped;
}

std::unordered_map<PartyIndex, std::vector<KeygenRound3Response>>
GroupKeygenResponsesByRecipient(
    const std::vector<KeygenRound3Response>& responses) {
  std::unordered_map<PartyIndex, std::vector<KeygenRound3Response>> grouped;
  for (const auto& response : responses) {
    grouped[response.to].push_back(response);
  }
  return grouped;
}

std::unordered_map<PartyIndex, std::vector<Round2Request>>
GroupOfflineRequestsByRecipient(const std::vector<Round2Request>& requests) {
  std::unordered_map<PartyIndex, std::vector<Round2Request>> grouped;
  for (const auto& request : requests) {
    grouped[request.to].push_back(request);
  }
  return grouped;
}

std::unordered_map<PartyIndex, std::vector<Round2Response>>
GroupOfflineResponsesByRecipient(const std::vector<Round2Response>& responses) {
  std::unordered_map<PartyIndex, std::vector<Round2Response>> grouped;
  for (const auto& response : responses) {
    grouped[response.to].push_back(response);
  }
  return grouped;
}

}  // namespace

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void ExpectThrow(const std::function<void()>& fn, const std::string& message) {
  bool threw = false;
  try {
    fn();
  } catch (const std::exception&) {
    threw = true;
  }
  if (!threw) {
    throw std::runtime_error("Test failed: " + message);
  }
}

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex party = 1; party <= n; ++party) {
    out.push_back(party);
  }
  return out;
}

KeygenPartyMap BuildKeygenParties(uint32_t n, uint32_t t, const Bytes& session_id,
                                  const Bytes& signer_id) {
  const auto participants = BuildParticipants(n);
  KeygenPartyMap parties;
  for (PartyIndex party : participants) {
    keygen::KeygenConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = party;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.signer_id = signer_id;
    parties.emplace(party, KeygenParty(std::move(cfg)));
  }
  return parties;
}

KeygenOutputs RunKeygen(uint32_t n, uint32_t t, const Bytes& session_id,
                        const Bytes& signer_id) {
  auto parties = BuildKeygenParties(n, t, session_id, signer_id);
  const auto participants = BuildParticipants(n);

  PeerMap<KeygenRound1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  PeerMap<KeygenRound2Broadcast> round2_broadcasts;
  KeygenRound2Shares round2_shares;
  for (PartyIndex party : participants) {
    const auto peer_round1 = BuildPeerMapFor(participants, party, round1);
    const auto round2 = parties.at(party).MakeRound2(peer_round1);
    round2_broadcasts.emplace(party, round2.broadcast);
    round2_shares.emplace(party, round2.shares_for_peers);
  }

  std::vector<KeygenRound3Request> all_requests;
  for (PartyIndex party : participants) {
    PeerMap<Scalar> shares_for_self;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        shares_for_self.emplace(peer, round2_shares.at(peer).at(party));
      }
    }
    const auto peer_round2 =
        BuildPeerMapFor(participants, party, round2_broadcasts);
    const auto requests =
        parties.at(party).MakeRound3Requests(peer_round2, shares_for_self);
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  const auto grouped_requests = GroupKeygenRequestsByRecipient(all_requests);
  std::vector<KeygenRound3Response> all_responses;
  for (PartyIndex party : participants) {
    const auto responses =
        parties.at(party).MakeRound3Responses(grouped_requests.at(party));
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }

  const auto grouped_responses = GroupKeygenResponsesByRecipient(all_responses);
  PeerMap<KeygenRound4Msg> round4;
  for (PartyIndex party : participants) {
    round4.emplace(party, parties.at(party).MakeRound4(grouped_responses.at(party)));
  }

  KeygenOutputs outputs;
  for (PartyIndex party : participants) {
    outputs.emplace(
        party,
        parties.at(party).Finalize(BuildPeerMapFor(participants, party, round4)));
  }
  return outputs;
}

OfflinePartyMap BuildOfflineParties(const std::vector<PartyIndex>& signers,
                                    const KeygenOutputs& keygen_outputs,
                                    const Bytes& session_id) {
  OfflinePartyMap parties;
  for (PartyIndex signer : signers) {
    presign::OfflineConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = signer;
    cfg.participants = signers;
    cfg.local_key_share = keygen_outputs.at(signer).local_key_share;
    cfg.public_keygen_data = keygen_outputs.at(signer).public_keygen_data;
    parties.emplace(signer, OfflineParty(std::move(cfg)));
  }
  return parties;
}

OfflineStates RunOffline(const std::vector<PartyIndex>& signers,
                         const KeygenOutputs& keygen_outputs,
                         const Bytes& session_id) {
  auto parties = BuildOfflineParties(signers, keygen_outputs, session_id);
  PeerMap<Round1Msg> round1;
  for (PartyIndex signer : signers) {
    round1.emplace(signer, parties.at(signer).MakeRound1());
  }

  std::vector<Round2Request> all_requests;
  for (PartyIndex signer : signers) {
    const auto requests = parties.at(signer).MakeRound2Requests(
        BuildPeerMapFor(signers, signer, round1));
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  const auto grouped_requests = GroupOfflineRequestsByRecipient(all_requests);
  std::vector<Round2Response> all_responses;
  for (PartyIndex signer : signers) {
    const auto responses =
        parties.at(signer).MakeRound2Responses(grouped_requests.at(signer));
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }

  const auto grouped_responses = GroupOfflineResponsesByRecipient(all_responses);
  PeerMap<Round3Msg> round3;
  for (PartyIndex signer : signers) {
    round3.emplace(signer, parties.at(signer).MakeRound3(grouped_responses.at(signer)));
  }

  OfflineStates states;
  for (PartyIndex signer : signers) {
    states.emplace(signer, parties.at(signer).Finalize(
                               BuildPeerMapFor(signers, signer, round3)));
  }
  return states;
}

OnlinePartyMap BuildOnlineParties(const std::vector<PartyIndex>& signers,
                                  const KeygenOutputs& keygen_outputs,
                                  const OfflineStates& offline_states,
                                  const Bytes& session_id, const Bytes& message) {
  OnlinePartyMap parties;
  for (PartyIndex signer : signers) {
    sign::OnlineConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = signer;
    cfg.participants = signers;
    cfg.local_key_share = keygen_outputs.at(signer).local_key_share;
    cfg.public_keygen_data = keygen_outputs.at(signer).public_keygen_data;
    cfg.offline = offline_states.at(signer);
    cfg.message = message;
    parties.emplace(signer, OnlineParty(std::move(cfg)));
  }
  return parties;
}

std::unordered_map<PartyIndex, Signature> RunOnline(
    const std::vector<PartyIndex>& signers, const KeygenOutputs& keygen_outputs,
    const OfflineStates& offline_states, const Bytes& session_id,
    const Bytes& message) {
  auto parties =
      BuildOnlineParties(signers, keygen_outputs, offline_states, session_id, message);

  PeerMap<Scalar> partials;
  for (PartyIndex signer : signers) {
    partials.emplace(signer, parties.at(signer).MakePartialSignature());
  }

  std::unordered_map<PartyIndex, Signature> signatures;
  for (PartyIndex signer : signers) {
    signatures.emplace(signer, parties.at(signer).Finalize(
                                   BuildPeerMapFor(signers, signer, partials)));
  }
  return signatures;
}

}  // namespace tecdsa::sm2::test
