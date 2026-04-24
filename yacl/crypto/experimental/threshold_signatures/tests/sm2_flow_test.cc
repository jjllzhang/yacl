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
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_signatures/sm2/common.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/detection/evidence.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/presign/offline.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/sign/online.h"
#include "yacl/crypto/experimental/threshold_signatures/sm2/verify/verify.h"
#include "yacl/crypto/experimental/threshold_signatures/tests/test_helpers.h"

namespace tecdsa::sm2_flow_test {
namespace {

using ::tecdsa::Bytes;
using ::tecdsa::ECPoint;
using ::tecdsa::PartyIndex;
using ::tecdsa::Scalar;
using ::tecdsa::sm2::detection::AbortStage;
using ::tecdsa::sm2::detection::EvidenceKind;
using ::tecdsa::sm2::keygen::KeygenOutput;
using ::tecdsa::sm2::keygen::KeygenParty;
using ::tecdsa::sm2::keygen::KeygenRound1Msg;
using ::tecdsa::sm2::keygen::KeygenRound2Broadcast;
using ::tecdsa::sm2::keygen::KeygenRound3Request;
using ::tecdsa::sm2::keygen::KeygenRound3Response;
using ::tecdsa::sm2::keygen::KeygenRound4Msg;
using ::tecdsa::sm2::keygen::PeerMap;
using ::tecdsa::sm2::presign::OfflineParty;
using ::tecdsa::sm2::presign::OfflineState;
using ::tecdsa::sm2::presign::Round1Msg;
using ::tecdsa::sm2::presign::Round2Request;
using ::tecdsa::sm2::presign::Round2Response;
using ::tecdsa::sm2::presign::Round3Msg;
using ::tecdsa::sm2::sign::OnlineParty;
using ::tecdsa::sm2::verify::Signature;
using ::tecdsa::test_helpers::BuildPeerMapFor;
using ::tecdsa::test_helpers::Expect;
using ::tecdsa::test_helpers::ExpectThrow;

constexpr uint32_t kTestAuxRsaBits = 192;

using KeygenOutputs = std::unordered_map<PartyIndex, KeygenOutput>;
using KeygenPartyMap = std::unordered_map<PartyIndex, KeygenParty>;
using OfflinePartyMap = std::unordered_map<PartyIndex, OfflineParty>;
using OfflineStates = std::unordered_map<PartyIndex, OfflineState>;
using OnlinePartyMap = std::unordered_map<PartyIndex, OnlineParty>;
using KeygenRound2Shares = std::unordered_map<PartyIndex, PeerMap<Scalar>>;

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex party = 1; party <= n; ++party) {
    out.push_back(party);
  }
  return out;
}

template <typename Msg>
std::unordered_map<PartyIndex, std::vector<Msg>> GroupByRecipient(
    const std::vector<Msg>& messages) {
  std::unordered_map<PartyIndex, std::vector<Msg>> grouped;
  for (const auto& message : messages) {
    grouped[message.to].push_back(message);
  }
  return grouped;
}

template <typename T>
T RequireDetectionValue(const sm2::detection::DetectionResult<T>& result,
                        const std::string& message) {
  if (!result.ok()) {
    throw std::runtime_error("Test failed: " + message + ": " +
                             result.abort->reason);
  }
  return *result.value;
}

KeygenOutputs RunKeygen(uint32_t n, uint32_t t, const Bytes& session_id,
                        const Bytes& signer_id) {
  const auto participants = BuildParticipants(n);
  KeygenPartyMap parties;
  for (PartyIndex party : participants) {
    sm2::keygen::KeygenConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = party;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.aux_rsa_modulus_bits = kTestAuxRsaBits;
    cfg.signer_id = signer_id;
    parties.emplace(party, KeygenParty(std::move(cfg)));
  }

  PeerMap<KeygenRound1Msg> round1;
  for (PartyIndex party : participants) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  PeerMap<KeygenRound2Broadcast> round2_broadcasts;
  KeygenRound2Shares round2_shares;
  for (PartyIndex party : participants) {
    const auto round2 = parties.at(party).MakeRound2(
        BuildPeerMapFor(participants, party, round1));
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
    const auto requests = parties.at(party).MakeRound3Requests(
        BuildPeerMapFor(participants, party, round2_broadcasts),
        shares_for_self);
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  const auto grouped_requests = GroupByRecipient(all_requests);
  std::vector<KeygenRound3Response> all_responses;
  for (PartyIndex party : participants) {
    const auto responses = RequireDetectionValue(
        parties.at(party).TryMakeRound3Responses(grouped_requests.at(party)),
        "SM2 keygen round3 responses");
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }

  const auto grouped_responses = GroupByRecipient(all_responses);
  PeerMap<KeygenRound4Msg> round4;
  for (PartyIndex party : participants) {
    round4.emplace(party,
                   parties.at(party).MakeRound4(grouped_responses.at(party)));
  }

  KeygenOutputs outputs;
  for (PartyIndex party : participants) {
    outputs.emplace(
        party, RequireDetectionValue(
                   parties.at(party).TryFinalize(
                       BuildPeerMapFor(participants, party, round4)),
                   "SM2 keygen finalize"));
  }
  return outputs;
}

OfflinePartyMap BuildOfflineParties(const std::vector<PartyIndex>& signers,
                                    const KeygenOutputs& keygen_outputs,
                                    const Bytes& session_id) {
  OfflinePartyMap parties;
  for (PartyIndex signer : signers) {
    sm2::presign::OfflineConfig cfg;
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

  const auto grouped_requests = GroupByRecipient(all_requests);
  std::vector<Round2Response> all_responses;
  for (PartyIndex signer : signers) {
    const auto responses = RequireDetectionValue(
        parties.at(signer).TryMakeRound2Responses(grouped_requests.at(signer)),
        "SM2 offline round2 responses");
    all_responses.insert(all_responses.end(), responses.begin(), responses.end());
  }

  const auto grouped_responses = GroupByRecipient(all_responses);
  PeerMap<Round3Msg> round3;
  for (PartyIndex signer : signers) {
    round3.emplace(signer,
                   parties.at(signer).MakeRound3(grouped_responses.at(signer)));
  }

  OfflineStates states;
  for (PartyIndex signer : signers) {
    states.emplace(
        signer, RequireDetectionValue(
                    parties.at(signer).TryFinalize(
                        BuildPeerMapFor(signers, signer, round3)),
                    "SM2 offline finalize"));
  }
  return states;
}

OnlinePartyMap BuildOnlineParties(const std::vector<PartyIndex>& signers,
                                  const KeygenOutputs& keygen_outputs,
                                  const OfflineStates& offline_states,
                                  const Bytes& session_id,
                                  const Bytes& message) {
  OnlinePartyMap parties;
  for (PartyIndex signer : signers) {
    sm2::sign::OnlineConfig cfg;
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

void ExpectAbort(const std::optional<sm2::detection::AbortEvidence>& abort,
                 AbortStage stage, EvidenceKind evidence_kind,
                 PartyIndex culprit, const std::optional<Bytes>& instance_id,
                 const std::string& message) {
  Expect(abort.has_value(), message + ": missing abort report");
  Expect(abort->stage == stage, message + ": wrong stage");
  Expect(abort->evidence_kind == evidence_kind,
         message + ": wrong evidence kind");
  Expect(abort->culprit == culprit, message + ": wrong culprit");
  Expect(abort->instance_id == instance_id, message + ": wrong instance id");
  Expect(!abort->reason.empty(), message + ": missing reason");
}

void TestOfflinePresignFlow() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const auto participants = BuildParticipants(3);
  const std::vector<PartyIndex> signers = {1, 2};
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x82, 0x01}, signer_id);
  ExpectThrow(
      [&]() {
        (void)BuildOfflineParties(participants, keygen_outputs,
                                  Bytes{0x82, 0x02});
      },
      "SM2 offline must reject signer sets larger than threshold + 1");
  ExpectThrow(
      [&]() {
        (void)BuildOfflineParties(std::vector<PartyIndex>{1}, keygen_outputs,
                                  Bytes{0x82, 0x03});
      },
      "SM2 offline must reject signer sets smaller than threshold + 1");

  const auto offline_states =
      RunOffline(signers, keygen_outputs, Bytes{0x82, 0x04});
  const auto& baseline = offline_states.at(signers.front());

  for (PartyIndex party : signers) {
    const auto& state = offline_states.at(party);
    Expect(state.R == baseline.R, "all SM2 parties must derive same offline R");
    Expect(state.W == baseline.W, "all SM2 parties must derive same offline W");
    Expect(state.delta_i.value() != 0,
           "SM2 offline delta share should be non-zero in honest flow");
    Expect(state.all_W_i.size() == signers.size(),
           "SM2 offline state must include all W_i");
    Expect(state.all_T_i.size() == signers.size(),
           "SM2 offline state must include all T_i");
    Expect(state.all_WK_i.size() == signers.size(),
           "SM2 offline state must include all WK_i");
    Expect(ECPoint::GeneratorMultiply(state.delta_i) == state.all_T_i.at(party),
           "SM2 offline T_i must match local delta_i");
  }
  Expect(sm2::internal::SumPointsOrThrow(
             {baseline.all_W_i.at(1), baseline.all_W_i.at(2)}) == baseline.W,
         "SM2 offline W must aggregate signer W_i");
  Expect(sm2::internal::SumPointsOrThrow(
             {baseline.all_T_i.at(1), baseline.all_T_i.at(2)}) ==
             sm2::internal::SumPointsOrThrow(
                 {baseline.all_WK_i.at(1), baseline.all_WK_i.at(2)}),
         "SM2 offline aggregate T_i must match aggregate WK_i");
}

void TestOnlineSignFlow() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const Bytes message = {'h', 'e', 'l', 'l', 'o', ' ', 's', 'm', '2'};
  const auto participants = BuildParticipants(3);
  const std::vector<PartyIndex> signers = {1, 2};
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x83, 0x01}, signer_id);
  const auto offline_states =
      RunOffline(signers, keygen_outputs, Bytes{0x83, 0x02});
  auto oversized_offline_states = offline_states;
  oversized_offline_states.emplace(3, offline_states.at(signers.front()));
  ExpectThrow(
      [&]() {
        (void)BuildOnlineParties(participants, keygen_outputs,
                                 oversized_offline_states, Bytes{0x83, 0x03},
                                 message);
      },
      "SM2 online must reject signer sets larger than threshold + 1");
  ExpectThrow(
      [&]() {
        (void)BuildOnlineParties(std::vector<PartyIndex>{1}, keygen_outputs,
                                 offline_states, Bytes{0x83, 0x04}, message);
      },
      "SM2 online must reject signer sets smaller than threshold + 1");

  const auto lagrange = sm2::internal::ComputeLagrangeAtZero(signers);
  Scalar subset_z = sm2::internal::Sm2Zero();
  Scalar delta = sm2::internal::Sm2Zero();
  for (PartyIndex party : signers) {
    subset_z = subset_z +
               (lagrange.at(party) * keygen_outputs.at(party).local_key_share.z_i);
    delta = delta + offline_states.at(party).delta_i;
  }
  Expect(subset_z.value() != 0, "strict SM2 subset z must be non-zero");
  Expect(ECPoint::GeneratorMultiply(delta) ==
             offline_states.at(signers.front()).R.Mul(subset_z),
         "strict SM2 offline delta must satisfy delta = k * z");

  const Bytes digest = sm2::zid::PreprocessMessageDigest(
      keygen_outputs.at(signers.front()).local_key_share.binding, message);
  const Scalar e = Scalar::FromBigEndianModQ(digest, sm2::internal::Sm2Group());
  const Scalar r =
      e + sm2::internal::XCoordinateModN(offline_states.at(signers.front()).R);
  const Signature manual_signature{
      .r = r,
      .s = delta + (r * subset_z) - r,
      .R = offline_states.at(signers.front()).R,
  };
  Expect(sm2::verify::VerifySm2SignatureMath(
             keygen_outputs.at(signers.front()).public_keygen_data.public_key,
             keygen_outputs.at(signers.front()).local_key_share.binding,
             message, manual_signature),
         "strict SM2 subset signature formula must verify");

  auto online_parties = BuildOnlineParties(signers, keygen_outputs,
                                           offline_states, Bytes{0x83, 0x03},
                                           message);
  sm2::sign::PeerMap<Scalar> partials;
  for (PartyIndex party : signers) {
    partials.emplace(party, online_parties.at(party).MakePartialSignature());
    Expect(ECPoint::GeneratorMultiply(partials.at(party)) ==
               offline_states.at(party).all_T_i.at(party).Add(
                   offline_states.at(party).all_W_i.at(party).Mul(r)),
           "strict SM2 online partial must satisfy g^s_i = T_i * W_i^r");
  }

  std::unordered_map<PartyIndex, Signature> signatures;
  for (PartyIndex party : signers) {
    const auto result = online_parties.at(party).TryFinalize(
        BuildPeerMapFor(signers, party, partials));
    Expect(result.ok(), "strict SM2 online finalize must succeed");
    signatures.emplace(party, *result.value);
  }
  const auto& baseline = signatures.at(signers.front());

  for (PartyIndex party : signers) {
    const auto& signature = signatures.at(party);
    Expect(signature.r == baseline.r && signature.s == baseline.s &&
               signature.R == baseline.R,
           "all SM2 parties must finalize the same signature");
    Expect(sm2::verify::VerifySm2SignatureMath(
               keygen_outputs.at(party).public_keygen_data.public_key,
               keygen_outputs.at(party).local_key_share.binding, message,
               signature),
           "final SM2 signature must verify");
  }
}

void TestTamperedOfflineA1ProofIdentifiesCulprit() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const std::vector<PartyIndex> signers = {1, 2};
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x84, 0x07}, signer_id);
  auto parties = BuildOfflineParties(signers, keygen_outputs, Bytes{0x84, 0x08});

  PeerMap<Round1Msg> round1;
  for (PartyIndex party : signers) {
    round1.emplace(party, parties.at(party).MakeRound1());
  }

  std::vector<Round2Request> all_requests;
  for (PartyIndex party : signers) {
    const auto requests = parties.at(party).MakeRound2Requests(
        BuildPeerMapFor(signers, party, round1));
    all_requests.insert(all_requests.end(), requests.begin(), requests.end());
  }

  std::optional<Bytes> tampered_instance_id;
  for (auto& request : all_requests) {
    if (request.from == 1 && request.to == 2) {
      request.a1_proof.s2 = request.a1_proof.s2 + decltype(request.a1_proof.s2)(1);
      tampered_instance_id = request.instance_id;
      break;
    }
  }
  Expect(tampered_instance_id.has_value(),
         "SM2 offline A1 tamper case must locate request from 1 to 2");

  const auto grouped_requests = GroupByRecipient(all_requests);
  const auto result = parties.at(2).TryMakeRound2Responses(grouped_requests.at(2));
  Expect(!result.ok(), "SM2 offline MtA must reject tampered A1 proof");
  ExpectAbort(result.abort, AbortStage::kOffline, EvidenceKind::kMtaProof,
              /*culprit=*/1, tampered_instance_id, "SM2 offline MtA blame");
}

void TestTamperedOnlinePartialIdentifiesCulprit() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const Bytes message = {'t', 'a', 'm', 'p', 'e', 'r'};
  const std::vector<PartyIndex> signers = {1, 2};
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x84, 0x04}, signer_id);
  const auto offline_states =
      RunOffline(signers, keygen_outputs, Bytes{0x84, 0x05});
  auto parties = BuildOnlineParties(signers, keygen_outputs, offline_states,
                                    Bytes{0x84, 0x06}, message);

  sm2::sign::PeerMap<Scalar> partials;
  for (PartyIndex party : signers) {
    partials.emplace(party, parties.at(party).MakePartialSignature());
  }
  partials.at(1) =
      partials.at(1) + Scalar::FromUint64(1, partials.at(1).group());

  const auto result =
      parties.at(2).TryFinalize(BuildPeerMapFor(signers, 2, partials));
  Expect(!result.ok(),
         "SM2 online finalize must reject a tampered partial signature");
  ExpectAbort(result.abort, AbortStage::kOnline,
              EvidenceKind::kPartialSignature, /*culprit=*/1, std::nullopt,
              "SM2 online partial blame");
}

}  // namespace
}  // namespace tecdsa::sm2_flow_test

int main() {
  using namespace tecdsa::sm2_flow_test;

  try {
    TestOfflinePresignFlow();
    TestOnlineSignFlow();
    TestTamperedOfflineA1ProofIdentifiesCulprit();
    TestTamperedOnlinePartialIdentifiesCulprit();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "sm2_sign_flow_tests passed" << '\n';
  return 0;
}
