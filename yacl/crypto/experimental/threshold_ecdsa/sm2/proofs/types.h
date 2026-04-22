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

#pragma once

#include "yacl/crypto/experimental/threshold_ecdsa/core/mta/proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/core/proof/types.h"

namespace tecdsa::sm2::proofs {

using BigInt = core::paillier::BigInt;

struct PiRangeProof {
  BigInt z = BigInt(0);
  BigInt u = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
};

struct PiLinearGroupProof {
  ECPoint u;
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct PiLinearProof {
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct PiGroupProof {
  ECPoint a;
  Scalar z;
};

struct PiGroupRelationProof {
  ECPoint a_g;
  ECPoint a_h;
  Scalar z;
};

inline PiRangeProof FromCorePiRangeProof(const core::mta::A1RangeProof& proof) {
  return PiRangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

inline core::mta::A1RangeProof ToCorePiRangeProof(const PiRangeProof& proof) {
  return core::mta::A1RangeProof{
      .z = proof.z,
      .u = proof.u,
      .w = proof.w,
      .s = proof.s,
      .s1 = proof.s1,
      .s2 = proof.s2,
  };
}

inline PiLinearGroupProof FromCorePiLinearGroupProof(
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

inline core::mta::A2MtAwcProof ToCorePiLinearGroupProof(
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

inline PiLinearProof FromCorePiLinearProof(const core::mta::A3MtAProof& proof) {
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

inline core::mta::A3MtAProof ToCorePiLinearProof(const PiLinearProof& proof) {
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

}  // namespace tecdsa::sm2::proofs
