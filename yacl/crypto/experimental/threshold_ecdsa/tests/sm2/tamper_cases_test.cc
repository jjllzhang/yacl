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

#include "test_support.h"

namespace tecdsa::sm2::testcases {
namespace {

using tecdsa::Bytes;
using tecdsa::PartyIndex;
using tecdsa::sm2::keygen::KeygenRound4Msg;
using tecdsa::sm2::presign::Round3Msg;
using tecdsa::sm2::test::BuildKeygenParties;
using tecdsa::sm2::test::BuildOfflineParties;
using tecdsa::sm2::test::BuildOnlineParties;
using tecdsa::sm2::test::BuildParticipants;
using tecdsa::sm2::test::BuildPeerMapFor;
using tecdsa::sm2::test::ExpectThrow;
using tecdsa::sm2::test::RunKeygen;
using tecdsa::sm2::test::RunOffline;

void TestTamperedKeygenGammaProofAbortsFinalize() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const auto participants = BuildParticipants(3);
  auto parties =
      BuildKeygenParties(/*n=*/3, /*t=*/1, Bytes{0x84, 0x01}, signer_id);

  tecdsa::sm2::test::PeerMap<tecdsa::sm2::keygen::KeygenRound1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  tecdsa::sm2::test::PeerMap<tecdsa::sm2::keygen::KeygenRound2Broadcast>
      round2_broadcasts;
  tecdsa::sm2::test::KeygenRound2Shares round2_shares;
  for (PartyIndex party : participants) {
    const auto round2 =
        parties.at(party).MakeRound2(BuildPeerMapFor(participants, party, round1));
    round2_broadcasts.emplace(party, round2.broadcast);
    round2_shares.emplace(party, round2.shares_for_peers);
  }

  std::vector<tecdsa::sm2::keygen::KeygenRound3Request> all_requests;
  for (PartyIndex party : participants) {
    tecdsa::sm2::keygen::PeerMap<tecdsa::Scalar> shares_for_self;
    for (PartyIndex peer : participants) {
      if (peer != party) {
        shares_for_self.emplace(peer, round2_shares.at(peer).at(party));
      }
    }
    const auto requests = parties.at(party).MakeRound3Requests(
        BuildPeerMapFor(participants, party, round2_broadcasts), shares_for_self);
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  std::unordered_map<PartyIndex, std::vector<tecdsa::sm2::keygen::KeygenRound3Request>>
      grouped_requests;
  for (const auto& request : all_requests) {
    grouped_requests[request.to].push_back(request);
  }
  std::vector<tecdsa::sm2::keygen::KeygenRound3Response> all_responses;
  for (PartyIndex party : participants) {
    const auto responses =
        parties.at(party).MakeRound3Responses(grouped_requests.at(party));
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }
  std::unordered_map<
      PartyIndex, std::vector<tecdsa::sm2::keygen::KeygenRound3Response>>
      grouped_responses;
  for (const auto& response : all_responses) {
    grouped_responses[response.to].push_back(response);
  }

  tecdsa::sm2::keygen::PeerMap<KeygenRound4Msg> round4;
  for (PartyIndex party : participants) {
    round4.emplace(party, parties.at(party).MakeRound4(grouped_responses.at(party)));
  }
  round4.at(1).gamma_proof.z =
      round4.at(1).gamma_proof.z +
      tecdsa::Scalar::FromUint64(1, round4.at(1).gamma_proof.z.group());

  ExpectThrow(
      [&]() {
        (void)parties.at(2).Finalize(BuildPeerMapFor(participants, 2, round4));
      },
      "SM2 keygen finalize must reject tampered gamma proof");
}

void TestTamperedOfflineNonceProofAbortsFinalize() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const auto participants = BuildParticipants(3);
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x84, 0x02}, signer_id);
  auto parties =
      BuildOfflineParties(participants, keygen_outputs, Bytes{0x84, 0x03});

  tecdsa::sm2::presign::PeerMap<tecdsa::sm2::presign::Round1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  std::vector<tecdsa::sm2::presign::Round2Request> all_requests;
  for (PartyIndex party : participants) {
    const auto requests = parties.at(party).MakeRound2Requests(
        BuildPeerMapFor(participants, party, round1));
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  std::unordered_map<PartyIndex, std::vector<tecdsa::sm2::presign::Round2Request>>
      grouped_requests;
  for (const auto& request : all_requests) {
    grouped_requests[request.to].push_back(request);
  }
  std::vector<tecdsa::sm2::presign::Round2Response> all_responses;
  for (PartyIndex party : participants) {
    const auto responses =
        parties.at(party).MakeRound2Responses(grouped_requests.at(party));
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }
  std::unordered_map<
      PartyIndex, std::vector<tecdsa::sm2::presign::Round2Response>>
      grouped_responses;
  for (const auto& response : all_responses) {
    grouped_responses[response.to].push_back(response);
  }

  tecdsa::sm2::presign::PeerMap<Round3Msg> round3;
  for (PartyIndex party : participants) {
    round3.emplace(party, parties.at(party).MakeRound3(grouped_responses.at(party)));
  }
  round3.at(1).k_proof.z =
      round3.at(1).k_proof.z +
      tecdsa::Scalar::FromUint64(1, round3.at(1).k_proof.z.group());

  ExpectThrow(
      [&]() {
        (void)parties.at(2).Finalize(BuildPeerMapFor(participants, 2, round3));
      },
      "SM2 offline finalize must reject tampered nonce proof");
}

void TestTamperedOnlinePartialAbortsFinalize() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const Bytes message = {'t', 'a', 'm', 'p', 'e', 'r'};
  const auto participants = BuildParticipants(3);
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x84, 0x04}, signer_id);
  const auto offline_states =
      RunOffline(participants, keygen_outputs, Bytes{0x84, 0x05});
  auto parties = BuildOnlineParties(participants, keygen_outputs, offline_states,
                                    Bytes{0x84, 0x06}, message);

  tecdsa::sm2::sign::PeerMap<tecdsa::Scalar> partials;
  for (PartyIndex party : participants) {
    partials.emplace(party, parties.at(party).MakePartialSignature());
  }
  partials.at(1) =
      partials.at(1) + tecdsa::Scalar::FromUint64(1, partials.at(1).group());

  ExpectThrow(
      [&]() {
        (void)parties.at(2).Finalize(BuildPeerMapFor(participants, 2, partials));
      },
      "SM2 online finalize must reject a tampered partial signature");
}

}  // namespace

void RunTamperCaseTests() {
  TestTamperedKeygenGammaProofAbortsFinalize();
  TestTamperedOfflineNonceProofAbortsFinalize();
  TestTamperedOnlinePartialAbortsFinalize();
}

}  // namespace tecdsa::sm2::testcases
