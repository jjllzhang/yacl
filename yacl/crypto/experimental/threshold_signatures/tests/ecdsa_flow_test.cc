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

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/sign/sign.h"
#include "yacl/crypto/experimental/threshold_signatures/ecdsa/verify/verify.h"
#include "yacl/crypto/experimental/threshold_signatures/tests/test_helpers.h"

namespace tecdsa::ecdsa_flow_test {
namespace {

using ::tecdsa::Bytes;
using ::tecdsa::PartyIndex;
using ::tecdsa::Scalar;
using ::tecdsa::ecdsa::keygen::KeygenOutput;
using ::tecdsa::ecdsa::keygen::KeygenParty;
using ::tecdsa::ecdsa::keygen::KeygenRound1Msg;
using ::tecdsa::ecdsa::keygen::KeygenRound2Broadcast;
using ::tecdsa::ecdsa::keygen::KeygenRound3Msg;
using ::tecdsa::ecdsa::sign::Signature;
using ::tecdsa::ecdsa::sign::SignConfig;
using ::tecdsa::ecdsa::sign::SignParty;
using ::tecdsa::ecdsa::sign::SignRound1Msg;
using ::tecdsa::ecdsa::sign::SignRound2Request;
using ::tecdsa::ecdsa::sign::SignRound2Response;
using ::tecdsa::ecdsa::sign::SignRound3Msg;
using ::tecdsa::ecdsa::sign::SignRound4Msg;
using ::tecdsa::ecdsa::sign::SignRound5AMsg;
using ::tecdsa::ecdsa::sign::SignRound5BMsg;
using ::tecdsa::ecdsa::sign::SignRound5CMsg;
using ::tecdsa::ecdsa::sign::SignRound5DMsg;
using ::tecdsa::test_helpers::BuildPeerMapFor;
using ::tecdsa::test_helpers::Expect;
using ::tecdsa::test_helpers::ExpectThrow;

constexpr uint32_t kTestAuxRsaBits = 192;

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

using KeygenOutputs = std::unordered_map<PartyIndex, KeygenOutput>;
using KeygenPartyMap = std::unordered_map<PartyIndex, KeygenParty>;
using KeygenRound2Shares = std::unordered_map<PartyIndex, PeerMap<Scalar>>;
using SignPartyMap = std::unordered_map<PartyIndex, SignParty>;

struct SignFixture {
  std::vector<PartyIndex> signers;
  Bytes msg32;
};

struct SignRoundState {
  PeerMap<SignRound1Msg> round1;
  std::vector<SignRound2Request> round2_requests;
  std::vector<SignRound2Response> round2_responses;
  PeerMap<SignRound3Msg> round3;
  PeerMap<SignRound4Msg> round4;
  PeerMap<SignRound5AMsg> round5a;
  PeerMap<SignRound5BMsg> round5b;
  PeerMap<SignRound5CMsg> round5c;
  PeerMap<SignRound5DMsg> round5d;
  PeerMap<Scalar> round5e;
};

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex id = 1; id <= n; ++id) {
    out.push_back(id);
  }
  return out;
}

std::unordered_map<PartyIndex, std::vector<SignRound2Request>>
GroupRound2RequestsByRecipient(const std::vector<SignRound2Request>& requests) {
  std::unordered_map<PartyIndex, std::vector<SignRound2Request>> grouped;
  for (const SignRound2Request& request : requests) {
    grouped[request.to].push_back(request);
  }
  return grouped;
}

std::unordered_map<PartyIndex, std::vector<SignRound2Response>>
GroupRound2ResponsesByRecipient(
    const std::vector<SignRound2Response>& responses) {
  std::unordered_map<PartyIndex, std::vector<SignRound2Response>> grouped;
  for (const SignRound2Response& response : responses) {
    grouped[response.to].push_back(response);
  }
  return grouped;
}

KeygenOutputs RunKeygenAndCollectResults(uint32_t n, uint32_t t,
                                         const Bytes& session_id) {
  const std::vector<PartyIndex> participants = BuildParticipants(n);
  KeygenPartyMap parties;
  for (PartyIndex party : participants) {
    ecdsa::keygen::KeygenConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = party;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.aux_rsa_modulus_bits = kTestAuxRsaBits;
    parties.emplace(party, KeygenParty(std::move(cfg)));
  }

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

  PeerMap<KeygenRound3Msg> round3;
  for (PartyIndex party : participants) {
    const auto peer_round2 =
        BuildPeerMapFor(participants, party, round2_broadcasts);
    PeerMap<Scalar> shares_for_self;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        shares_for_self.emplace(peer, round2_shares.at(peer).at(party));
      }
    }
    round3.emplace(party,
                   parties.at(party).MakeRound3(peer_round2, shares_for_self));
  }

  KeygenOutputs outputs;
  for (PartyIndex party : participants) {
    outputs.emplace(
        party,
        parties.at(party).Finalize(BuildPeerMapFor(participants, party, round3)));
  }
  return outputs;
}

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers) {
  return SignFixture{.signers = signers,
                     .msg32 = Bytes(32, static_cast<uint8_t>(0x5A))};
}

SignPartyMap BuildSignParties(const SignFixture& fixture,
                              const KeygenOutputs& keygen_results,
                              const Bytes& sign_session_id,
                              const Bytes& keygen_session_id) {
  SignPartyMap parties;
  for (PartyIndex signer : fixture.signers) {
    const auto result_it = keygen_results.find(signer);
    if (result_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer");
    }
    SignConfig cfg;
    cfg.session_id = sign_session_id;
    cfg.keygen_session_id = keygen_session_id;
    cfg.self_id = signer;
    cfg.participants = fixture.signers;
    cfg.local_key_share = result_it->second.local_key_share;
    cfg.public_keygen_data = result_it->second.public_keygen_data;
    cfg.msg32 = fixture.msg32;
    parties.emplace(signer, SignParty(std::move(cfg)));
  }
  return parties;
}

PeerMap<SignRound1Msg> CollectRound1Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers) {
  PeerMap<SignRound1Msg> round1;
  for (PartyIndex signer : signers) {
    round1.emplace(signer, parties->at(signer).MakeRound1());
  }
  return round1;
}

std::vector<SignRound2Request> CollectRound2Requests(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound1Msg>& round1) {
  std::vector<SignRound2Request> out;
  for (PartyIndex signer : signers) {
    const auto requests = parties->at(signer).MakeRound2Requests(
        BuildPeerMapFor(signers, signer, round1));
    out.insert(out.end(), requests.begin(), requests.end());
  }
  return out;
}

std::vector<SignRound2Response> CollectRound2Responses(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Request>& round2_requests) {
  const auto grouped = GroupRound2RequestsByRecipient(round2_requests);
  std::vector<SignRound2Response> out;
  for (PartyIndex signer : signers) {
    const auto it = grouped.find(signer);
    if (it == grouped.end()) {
      throw std::runtime_error("missing round2 requests for signer");
    }
    const auto responses = parties->at(signer).MakeRound2Responses(it->second);
    out.insert(out.end(), responses.begin(), responses.end());
  }
  return out;
}

PeerMap<SignRound3Msg> CollectRound3Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const std::vector<SignRound2Response>& round2_responses) {
  const auto grouped = GroupRound2ResponsesByRecipient(round2_responses);
  PeerMap<SignRound3Msg> round3;
  for (PartyIndex signer : signers) {
    const auto it = grouped.find(signer);
    if (it == grouped.end()) {
      throw std::runtime_error("missing round2 responses for signer");
    }
    round3.emplace(signer, parties->at(signer).MakeRound3(it->second));
  }
  return round3;
}

PeerMap<SignRound4Msg> CollectRound4Messages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound3Msg>& round3) {
  PeerMap<SignRound4Msg> round4;
  for (PartyIndex signer : signers) {
    round4.emplace(signer, parties->at(signer).MakeRound4(
                               BuildPeerMapFor(signers, signer, round3)));
  }
  return round4;
}

PeerMap<SignRound5AMsg> CollectRound5AMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound4Msg>& round4) {
  PeerMap<SignRound5AMsg> round5a;
  for (PartyIndex signer : signers) {
    round5a.emplace(signer, parties->at(signer).MakeRound5A(
                                BuildPeerMapFor(signers, signer, round4)));
  }
  return round5a;
}

PeerMap<SignRound5BMsg> CollectRound5BMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5AMsg>& round5a) {
  PeerMap<SignRound5BMsg> round5b;
  for (PartyIndex signer : signers) {
    round5b.emplace(signer, parties->at(signer).MakeRound5B(
                                BuildPeerMapFor(signers, signer, round5a)));
  }
  return round5b;
}

PeerMap<SignRound5CMsg> CollectRound5CMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5BMsg>& round5b) {
  PeerMap<SignRound5CMsg> round5c;
  for (PartyIndex signer : signers) {
    round5c.emplace(signer, parties->at(signer).MakeRound5C(
                                BuildPeerMapFor(signers, signer, round5b)));
  }
  return round5c;
}

PeerMap<SignRound5DMsg> CollectRound5DMessages(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5CMsg>& round5c) {
  PeerMap<SignRound5DMsg> round5d;
  for (PartyIndex signer : signers) {
    round5d.emplace(signer, parties->at(signer).MakeRound5D(
                                BuildPeerMapFor(signers, signer, round5c)));
  }
  return round5d;
}

PeerMap<Scalar> CollectRound5EReveals(
    SignPartyMap* parties, const std::vector<PartyIndex>& signers,
    const PeerMap<SignRound5DMsg>& round5d) {
  PeerMap<Scalar> round5e;
  for (PartyIndex signer : signers) {
    round5e.emplace(signer, parties->at(signer).RevealRound5E(
                                BuildPeerMapFor(signers, signer, round5d)));
  }
  return round5e;
}

PeerMap<Signature> FinalizeSignatures(SignPartyMap* parties,
                                      const std::vector<PartyIndex>& signers,
                                      const PeerMap<Scalar>& round5e) {
  PeerMap<Signature> signatures;
  for (PartyIndex signer : signers) {
    signatures.emplace(signer, parties->at(signer).Finalize(
                                   BuildPeerMapFor(signers, signer, round5e)));
  }
  return signatures;
}

SignPartyMap BuildDefaultSignParties(const KeygenOutputs& keygen_results,
                                     const Bytes& keygen_session_id,
                                     const Bytes& sign_session_id) {
  const std::vector<PartyIndex> signers = {1, 2};
  return BuildSignParties(BuildSignFixture(signers), keygen_results,
                          sign_session_id, keygen_session_id);
}

void RunToRound5B(SignPartyMap* parties, const std::vector<PartyIndex>& signers,
                  SignRoundState* state) {
  state->round1 = CollectRound1Messages(parties, signers);
  state->round2_requests =
      CollectRound2Requests(parties, signers, state->round1);
  state->round2_responses =
      CollectRound2Responses(parties, signers, state->round2_requests);
  state->round3 =
      CollectRound3Messages(parties, signers, state->round2_responses);
  state->round4 = CollectRound4Messages(parties, signers, state->round3);
  state->round5a = CollectRound5AMessages(parties, signers, state->round4);
  state->round5b = CollectRound5BMessages(parties, signers, state->round5a);
}

void TestSignEndToEndProducesVerifiableSignature() {
  const Bytes keygen_session = {0xD1, 0x03, 0x01};
  const Bytes sign_session = {0xE1, 0x02, 0x01};
  const auto keygen_results =
      RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, keygen_session);
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto parties =
      BuildSignParties(fixture, keygen_results, sign_session, keygen_session);

  SignRoundState state;
  RunToRound5B(&parties, signers, &state);
  state.round5c = CollectRound5CMessages(&parties, signers, state.round5b);
  state.round5d = CollectRound5DMessages(&parties, signers, state.round5c);
  state.round5e = CollectRound5EReveals(&parties, signers, state.round5d);
  const auto signatures = FinalizeSignatures(&parties, signers, state.round5e);

  const Signature& baseline = signatures.at(signers.front());
  Expect(baseline.r.value() != 0, "final signature r must be non-zero");
  Expect(baseline.s.value() != 0, "final signature s must be non-zero");
  Expect(ecdsa::verify::VerifyEcdsaSignatureMath(
             keygen_results.at(1).public_keygen_data.y, fixture.msg32,
             baseline.r, baseline.s),
         "final signature must verify");

  for (PartyIndex signer : signers) {
    const Signature& signature = signatures.at(signer);
    Expect(signature.r == baseline.r, "all signers must derive same r");
    Expect(signature.s == baseline.s, "all signers must derive same s");
    Expect(signature.R == baseline.R, "all signers must derive same R");
  }
}

void TestTamperedMtaProofAbortsResponder() {
  const Bytes session = {0xD7, 0x03, 0x01};
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1,
                                                        session);
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties =
      BuildDefaultSignParties(keygen_results, session, Bytes{0xE7, 0x02, 0x01});

  const auto round1 = CollectRound1Messages(&parties, signers);
  std::vector<SignRound2Request> round2_requests =
      CollectRound2Requests(&parties, signers, round1);
  for (SignRound2Request& request : round2_requests) {
    if (request.from == 1 && request.to == 2) {
      request.a1_proof.s2 += BigInt(1);
      ExpectThrow(
          [&]() {
            (void)CollectRound2Responses(&parties, signers, round2_requests);
          },
          "responder must reject tampered A1 proof");
      return;
    }
  }
  throw std::runtime_error("Test failed: missing round2 request to tamper");
}

void TestTamperedCommitmentAbortsReceiver() {
  const Bytes session = {0xDB, 0x03, 0x01};
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1,
                                                        session);
  const std::vector<PartyIndex> signers = {1, 2};
  auto parties =
      BuildDefaultSignParties(keygen_results, session, Bytes{0xEB, 0x02, 0x01});

  SignRoundState state;
  state.round1 = CollectRound1Messages(&parties, signers);
  state.round2_requests =
      CollectRound2Requests(&parties, signers, state.round1);
  state.round2_responses =
      CollectRound2Responses(&parties, signers, state.round2_requests);
  state.round3 =
      CollectRound3Messages(&parties, signers, state.round2_responses);
  state.round4 = CollectRound4Messages(&parties, signers, state.round3);
  state.round5a = CollectRound5AMessages(&parties, signers, state.round4);
  state.round5a.at(1).commitment[0] ^= 0x01;
  state.round5b = CollectRound5BMessages(&parties, signers, state.round5a);

  ExpectThrow(
      [&]() { (void)CollectRound5CMessages(&parties, signers, state.round5b); },
      "receiver must reject tampered round5A commitment");
}

}  // namespace
}  // namespace tecdsa::ecdsa_flow_test

int main() {
  using namespace tecdsa::ecdsa_flow_test;

  try {
    TestSignEndToEndProducesVerifiableSignature();
    TestTamperedMtaProofAbortsResponder();
    TestTamperedCommitmentAbortsReceiver();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "sign_flow_tests passed" << '\n';
  return 0;
}
