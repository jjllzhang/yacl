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

#include "yacl/crypto/experimental/threshold_ecdsa/core/paillier/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

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

}  // namespace tecdsa::sm2::proofs

// Keep adapter declarations transitively visible for callers that historically
// included only types.h.
#include "yacl/crypto/experimental/threshold_ecdsa/sm2/proofs/adapters.h"
