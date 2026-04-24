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
#include <stdexcept>
#include <type_traits>

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/keygen/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/types.h"
#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/sign/sign.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign.h"

namespace {

void Expect(bool condition, const char* message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void TestProtocolCompatibilityAliases() {
  static_assert(std::is_same_v<tecdsa::proto::KeygenConfig,
                               tecdsa::ecdsa::keygen::KeygenConfig>);
  static_assert(std::is_same_v<tecdsa::proto::KeygenParty,
                               tecdsa::ecdsa::keygen::KeygenParty>);
  static_assert(std::is_same_v<tecdsa::proto::SignConfig,
                               tecdsa::ecdsa::sign::SignConfig>);
  static_assert(std::is_same_v<tecdsa::proto::SignParty,
                               tecdsa::ecdsa::sign::SignParty>);
}

void TestProtocolProofCompatibilityAliases() {
  static_assert(
      std::is_convertible_v<tecdsa::proto::A1RangeProof,
                            decltype(tecdsa::proto::SignRound2Request{}.a1_proof)>);
  static_assert(
      std::is_convertible_v<
          tecdsa::proto::A2MtAwcProof,
          typename decltype(
              tecdsa::proto::SignRound2Response{}.a2_proof)::value_type>);
  static_assert(
      std::is_convertible_v<
          tecdsa::proto::A3MtAProof,
          typename decltype(
              tecdsa::proto::SignRound2Response{}.a3_proof)::value_type>);
  static_assert(std::is_same_v<tecdsa::proto::A1RangeProof,
                               tecdsa::core::mta::A1RangeProof>);
  static_assert(std::is_same_v<tecdsa::proto::A2MtAwcProof,
                               tecdsa::core::mta::A2MtAwcProof>);
  static_assert(std::is_same_v<tecdsa::proto::A3MtAProof,
                               tecdsa::core::mta::A3MtAProof>);
  static_assert(std::is_same_v<tecdsa::proto::SchnorrProof,
                               tecdsa::ecdsa::proofs::SchnorrProof>);
  static_assert(!std::is_same_v<tecdsa::proto::SchnorrProof,
                                tecdsa::core::proof::SchnorrProof>);

  tecdsa::proto::A1RangeProof a1{
      .z = tecdsa::BigInt(11),
      .u = tecdsa::BigInt(12),
      .w = tecdsa::BigInt(13),
      .s = tecdsa::BigInt(14),
      .s1 = tecdsa::BigInt(15),
      .s2 = tecdsa::BigInt(16),
  };
  tecdsa::proto::A2MtAwcProof a2{
      .u = tecdsa::ECPoint::GeneratorMultiply(tecdsa::Scalar::FromUint64(3)),
      .z = tecdsa::BigInt(21),
      .z2 = tecdsa::BigInt(22),
      .t = tecdsa::BigInt(23),
      .v = tecdsa::BigInt(24),
      .w = tecdsa::BigInt(25),
      .s = tecdsa::BigInt(26),
      .s1 = tecdsa::BigInt(27),
      .s2 = tecdsa::BigInt(28),
      .t1 = tecdsa::BigInt(29),
      .t2 = tecdsa::BigInt(30),
  };
  tecdsa::proto::A3MtAProof a3{
      .z = tecdsa::BigInt(31),
      .z2 = tecdsa::BigInt(32),
      .t = tecdsa::BigInt(33),
      .v = tecdsa::BigInt(34),
      .w = tecdsa::BigInt(35),
      .s = tecdsa::BigInt(36),
      .s1 = tecdsa::BigInt(37),
      .s2 = tecdsa::BigInt(38),
      .t1 = tecdsa::BigInt(39),
      .t2 = tecdsa::BigInt(40),
  };

  tecdsa::proto::SignRound2Request request{
      .from = 1,
      .to = 2,
      .type = tecdsa::proto::MtaType::kTimesGamma,
      .instance_id = tecdsa::Bytes{0xC3, 0x02, 0x01},
      .c1 = tecdsa::BigInt(17),
      .a1_proof = a1,
  };
  tecdsa::proto::SignRound2Response response{
      .from = 2,
      .to = 1,
      .type = tecdsa::proto::MtaType::kTimesGamma,
      .instance_id = tecdsa::Bytes{0xC3, 0x02, 0x01},
      .c2 = tecdsa::BigInt(18),
      .a2_proof = a2,
      .a3_proof = a3,
  };

  Expect(request.a1_proof.s2 == a1.s2,
         "proto::A1RangeProof must populate SignRound2Request directly");
  Expect(response.a2_proof.has_value() && response.a2_proof->t2 == a2.t2,
         "proto::A2MtAwcProof must populate SignRound2Response directly");
  Expect(response.a3_proof.has_value() && response.a3_proof->t2 == a3.t2,
         "proto::A3MtAProof must populate SignRound2Response directly");
}

}  // namespace

int main() {
  try {
    TestProtocolCompatibilityAliases();
    TestProtocolProofCompatibilityAliases();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "compatibility_tests passed" << '\n';
  return 0;
}
