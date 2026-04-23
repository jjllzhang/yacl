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

#include "yacl/crypto/experimental/threshold_ecdsa/ecdsa/proofs/adapters.h"

namespace tecdsa::ecdsa::proofs {

A1RangeProof FromCoreA1RangeProof(const core::mta::A1RangeProof& proof) {
  return A1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

core::mta::A1RangeProof ToCoreA1RangeProof(const A1RangeProof& proof) {
  return core::mta::A1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

A2MtAwcProof FromCoreA2MtAwcProof(const core::mta::A2MtAwcProof& proof) {
  return A2MtAwcProof{
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

core::mta::A2MtAwcProof ToCoreA2MtAwcProof(const A2MtAwcProof& proof) {
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

A3MtAProof FromCoreA3MtAProof(const core::mta::A3MtAProof& proof) {
  return A3MtAProof{
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

core::mta::A3MtAProof ToCoreA3MtAProof(const A3MtAProof& proof) {
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

SchnorrProof FromCoreSchnorrProof(const core::proof::SchnorrProof& proof) {
  return SchnorrProof{
      .a = proof.a,
      .z = proof.z,
  };
}

core::proof::SchnorrProof ToCoreSchnorrProof(const SchnorrProof& proof) {
  return core::proof::SchnorrProof{
      .a = proof.a,
      .z = proof.z,
  };
}

}  // namespace tecdsa::ecdsa::proofs
