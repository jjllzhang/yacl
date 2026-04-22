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
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/zid/zid.h"

namespace {

using tecdsa::Bytes;
using tecdsa::ECPoint;
using tecdsa::PartyIndex;
using tecdsa::sm2::test::BuildParticipants;
using tecdsa::sm2::test::Expect;
using tecdsa::sm2::test::RunKeygen;

void TestHonestSm2KeygenFlow() {
  const Bytes signer_id = {'a', 'l', 'i', 'c', 'e'};
  const auto participants = BuildParticipants(3);
  const auto outputs = RunKeygen(/*n=*/3, /*t=*/1, Bytes{0x81, 0x01}, signer_id);
  const auto& baseline = outputs.at(participants.front());

  for (PartyIndex party : participants) {
    const auto& output = outputs.at(party);
    Expect(output.local_key_share.z_i.value() != 0,
           "SM2 local z share must be non-zero");
    Expect(output.local_key_share.paillier != nullptr,
           "SM2 local Paillier provider must be present");
    Expect(output.public_keygen_data.public_key ==
               baseline.public_keygen_data.public_key,
           "all SM2 parties must derive the same public key");
    Expect(output.public_keygen_data.all_Y_i.size() == participants.size(),
           "SM2 keygen must export all public y shares");
    Expect(output.public_keygen_data.all_Y_i ==
               baseline.public_keygen_data.all_Y_i,
           "all SM2 parties must derive the same public y shares");
    Expect(ECPoint::GeneratorMultiply(output.local_key_share.z_i) ==
               output.public_keygen_data.all_Y_i.at(party),
           "SM2 public y share must match the local signing share");
    Expect(output.local_key_share.binding.zid ==
               baseline.local_key_share.binding.zid,
           "all SM2 parties must derive the same zid");
    Expect(output.local_key_share.binding.zid ==
               tecdsa::sm2::zid::ComputeZid(signer_id,
                                            output.public_keygen_data.public_key),
           "stored zid must match the derived public key and signer id");
  }
}

}  // namespace

int main() {
  TestHonestSm2KeygenFlow();
  std::cout << "sm2_keygen_flow_tests passed" << std::endl;
  return 0;
}
