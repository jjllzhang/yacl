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

namespace tecdsa::sm2::testcases {

using tecdsa::Bytes;
using tecdsa::PartyIndex;
using tecdsa::sm2::test::BuildOfflineParties;
using tecdsa::sm2::test::BuildParticipants;
using tecdsa::sm2::test::Expect;
using tecdsa::sm2::test::ExpectThrow;
using tecdsa::sm2::test::RunKeygen;
using tecdsa::sm2::test::RunOffline;

void RunOfflinePresignTests() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const auto participants = BuildParticipants(3);
  const std::vector<PartyIndex> signers = {1, 2};
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x82, 0x01}, signer_id);
  ExpectThrow(
      [&]() {
        (void)BuildOfflineParties(participants, keygen_outputs, Bytes{0x82, 0x02});
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
    Expect(state.R == baseline.R,
           "all SM2 parties must derive the same offline R");
    Expect(state.delta_i.value() != 0,
           "SM2 offline delta share should be non-zero in honest flow");
  }
}

}  // namespace tecdsa::sm2::testcases
