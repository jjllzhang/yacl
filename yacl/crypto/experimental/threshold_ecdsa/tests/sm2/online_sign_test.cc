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
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/verify/verify.h"

namespace tecdsa::sm2::testcases {

using tecdsa::Bytes;
using tecdsa::PartyIndex;
using tecdsa::sm2::test::BuildParticipants;
using tecdsa::sm2::test::Expect;
using tecdsa::sm2::test::RunKeygen;
using tecdsa::sm2::test::RunOffline;
using tecdsa::sm2::test::RunOnline;
using tecdsa::sm2::verify::VerifySm2SignatureMath;

void RunOnlineSignTests() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const Bytes message = {'h', 'e', 'l', 'l', 'o', ' ', 's', 'm', '2'};
  const auto participants = BuildParticipants(3);
  const auto keygen_outputs =
      RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x83, 0x01}, signer_id);
  const auto offline_states =
      RunOffline(participants, keygen_outputs, Bytes{0x83, 0x02});
  const auto signatures = RunOnline(participants, keygen_outputs, offline_states,
                                    Bytes{0x83, 0x03}, message);
  const auto& baseline = signatures.at(participants.front());

  for (PartyIndex party : participants) {
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
