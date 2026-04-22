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

#include <iostream>

#include "test_support.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/common.h"
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/verify/verify.h"

namespace tecdsa::sm2::testcases {

using tecdsa::Bytes;
using tecdsa::PartyIndex;
using tecdsa::Scalar;
using tecdsa::sm2::test::BuildPeerMapFor;
using tecdsa::sm2::test::BuildOnlineParties;
using tecdsa::sm2::test::BuildParticipants;
using tecdsa::sm2::test::Expect;
using tecdsa::sm2::test::ExpectThrow;
using tecdsa::sm2::test::RunKeygen;
using tecdsa::sm2::test::RunOffline;
using tecdsa::sm2::verify::VerifySm2SignatureMath;

void RunOnlineSignTests() {
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
                                 oversized_offline_states,
                                 Bytes{0x83, 0x03}, message);
      },
      "SM2 online must reject signer sets larger than threshold + 1");
  ExpectThrow(
      [&]() {
        (void)BuildOnlineParties(std::vector<PartyIndex>{1}, keygen_outputs,
                                 offline_states, Bytes{0x83, 0x04}, message);
      },
      "SM2 online must reject signer sets smaller than threshold + 1");

  const auto lagrange = tecdsa::sm2::internal::ComputeLagrangeAtZero(signers);
  Scalar subset_z = tecdsa::sm2::internal::Sm2Zero();
  Scalar delta = tecdsa::sm2::internal::Sm2Zero();
  for (PartyIndex party : signers) {
    subset_z =
        subset_z + (lagrange.at(party) * keygen_outputs.at(party).local_key_share.z_i);
    delta = delta + offline_states.at(party).delta_i;
  }
  Expect(subset_z.value() != 0, "strict SM2 subset z must be non-zero");
  Expect(ECPoint::GeneratorMultiply(delta) ==
             offline_states.at(signers.front()).R.Mul(subset_z),
         "strict SM2 offline delta must satisfy delta = k * z");

  const Bytes digest = tecdsa::sm2::zid::PreprocessMessageDigest(
      keygen_outputs.at(signers.front()).local_key_share.binding, message);
  const Scalar e = Scalar::FromBigEndianModQ(digest, tecdsa::sm2::internal::Sm2Group());
  const Scalar r = e + tecdsa::sm2::internal::XCoordinateModN(
                           offline_states.at(signers.front()).R);
  const verify::Signature manual_signature{
      .r = r,
      .s = delta + (r * subset_z) - r,
      .R = offline_states.at(signers.front()).R,
  };
  Expect(VerifySm2SignatureMath(
             keygen_outputs.at(signers.front()).public_keygen_data.public_key,
             keygen_outputs.at(signers.front()).local_key_share.binding, message,
             manual_signature),
         "strict SM2 subset signature formula must verify");

  auto online_parties = BuildOnlineParties(signers, keygen_outputs, offline_states,
                                           Bytes{0x83, 0x03}, message);
  tecdsa::sm2::sign::PeerMap<Scalar> partials;
  for (PartyIndex party : signers) {
    partials.emplace(party, online_parties.at(party).MakePartialSignature());
    Expect(ECPoint::GeneratorMultiply(partials.at(party)) ==
               offline_states.at(party).all_T_i.at(party).Add(
                   offline_states.at(party).all_W_i.at(party).Mul(r)),
           "strict SM2 online partial must satisfy g^s_i = T_i * W_i^r");
  }

  std::unordered_map<PartyIndex, verify::Signature> signatures;
  for (PartyIndex party : signers) {
    signatures.emplace(
        party, online_parties.at(party).Finalize(
                   BuildPeerMapFor(signers, party, partials)));
  }
  const auto& baseline = signatures.at(signers.front());

  for (PartyIndex party : signers) {
    const auto& signature = signatures.at(party);
    Expect(signature.r == baseline.r && signature.s == baseline.s &&
               signature.R == baseline.R,
           "all SM2 parties must finalize the same signature");
    Expect(VerifySm2SignatureMath(keygen_outputs.at(party).public_keygen_data.public_key,
                                  keygen_outputs.at(party).local_key_share.binding,
                                  message, signature),
           "final SM2 signature must verify");
  }
}

}  // namespace tecdsa::sm2::testcases
