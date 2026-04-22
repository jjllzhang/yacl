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

#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/adapters.h"

namespace tecdsa::sm2::proofs {

PiRangeProof FromCorePiRangeProof(const core::mta::A1RangeProof& proof) {
  return PiRangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

core::mta::A1RangeProof ToCorePiRangeProof(const PiRangeProof& proof) {
  return core::mta::A1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

PiLinearGroupProof FromCorePiLinearGroupProof(
    const core::mta::A2MtAwcProof& proof) {
  return PiLinearGroupProof{
      .u = proof.u,
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

core::mta::A2MtAwcProof ToCorePiLinearGroupProof(
    const PiLinearGroupProof& proof) {
  return core::mta::A2MtAwcProof{
      .u = proof.u,
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

PiLinearProof FromCorePiLinearProof(const core::mta::A3MtAProof& proof) {
  return PiLinearProof{
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

core::mta::A3MtAProof ToCorePiLinearProof(const PiLinearProof& proof) {
  return core::mta::A3MtAProof{
      .z = proof.z,
      .z2 = proof.z2,
      .t = proof.t,
      .v = proof.v,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
      .t1 = proof.t1,
      .t2 = proof.t2,
  };
}

PiGroupProof FromCorePiGroupProof(const core::proof::SchnorrProof& proof) {
  return PiGroupProof{
      .a = proof.a,
      .z = proof.z,
  };
}

core::proof::SchnorrProof ToCorePiGroupProof(const PiGroupProof& proof) {
  return core::proof::SchnorrProof{
      .a = proof.a,
      .z = proof.z,
  };
}

}  // namespace tecdsa::sm2::proofs
